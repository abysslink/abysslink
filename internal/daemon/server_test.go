// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Abysslink Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package daemon_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/notifyv2"
)

// notifyStubNotifier satisfies daemon.Notifier for the notify body-size tests.
type notifyStubNotifier struct{}

func (notifyStubNotifier) Send(_ context.Context, _, _ string) error { return nil }

func (notifyStubNotifier) SendNote(_ context.Context, _ notifyv2.RenderedNote) error { return nil }

// v2RecordingNotifier captures SendNote deliveries for the POST /notify v2
// branch tests (the daemon seam half of phase success criterion 1).
type v2RecordingNotifier struct {
	mu    sync.Mutex
	notes []notifyv2.RenderedNote
}

func (n *v2RecordingNotifier) Send(_ context.Context, _, _ string) error { return nil }

func (n *v2RecordingNotifier) SendNote(_ context.Context, note notifyv2.RenderedNote) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.notes = append(n.notes, note)
	return nil
}

func (n *v2RecordingNotifier) all() []notifyv2.RenderedNote {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]notifyv2.RenderedNote, len(n.notes))
	copy(out, n.notes)
	return out
}

// startNotifyServer spins up a daemon Server on a temp Unix socket and returns
// an HTTP client wired to that socket plus a cancel function.
// The socket dir comes from shortRuntimeDir (daemon_test.go): macOS limits Unix
// socket paths to ~104 bytes and t.TempDir() under /var/folders exceeds it.
func startNotifyServer(t *testing.T) (*http.Client, context.CancelFunc) {
	t.Helper()
	return startNotifyServerWith(t, notifyStubNotifier{})
}

// startNotifyServerWith is startNotifyServer with a caller-supplied Notifier
// (the v2 tests capture RenderedNotes at the daemon seam).
func startNotifyServerWith(t *testing.T, notifier daemon.Notifier) (*http.Client, context.CancelFunc) {
	t.Helper()
	dir := shortRuntimeDir(t)
	sock := filepath.Join(dir, "abysslinkd-notify.sock")
	t.Setenv("XDG_RUNTIME_DIR", dir)
	_ = os.Remove(sock)

	srv := daemon.NewServer(notifier, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Run(ctx) }()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", daemon.SocketPath())
			},
		},
	}

	// Wait until the socket is ready.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://unix/health", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return client, cancel
}

// TestHandleNotify_BodyTooLarge verifies that a POST /notify with a body
// exceeding maxNotifyBody (256 KiB) is rejected with a non-2xx status code
// (400 or 413). This is the A11 / DOS-01 guard.
// The body is a valid JSON object whose "body" field contains enough padding
// to exceed the limit — this ensures the rejection is from the body-cap guard,
// not from a JSON parse failure on a non-JSON payload.
func TestHandleNotify_BodyTooLarge(t *testing.T) {
	client, cancel := startNotifyServer(t)
	defer cancel()

	// maxNotifyBody is 256 KiB (256*1024 bytes). Build a valid JSON payload
	// that exceeds the limit so the test is unambiguously about the cap, not a
	// JSON parse error.
	const maxNotifyBody = 256 * 1024
	// Padding: enough to push the total body well past maxNotifyBody.
	padding := strings.Repeat("A", maxNotifyBody)
	oversizeBody := `{"title":"t","body":"` + padding + `"}`

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"http://unix/notify",
		bytes.NewBufferString(oversizeBody),
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"oversized /notify body must not return 200")
	assert.NotEqual(t, http.StatusNoContent, resp.StatusCode,
		"oversized /notify body must not return 204")
	// Expect 400 Bad Request or 413 Request Entity Too Large.
	acceptable := resp.StatusCode == http.StatusBadRequest ||
		resp.StatusCode == http.StatusRequestEntityTooLarge
	assert.True(t, acceptable,
		"expected 400 or 413, got %d", resp.StatusCode)
}

// TestHandleNotify_ValidBody verifies that a POST /notify with a normal-sized
// JSON body is accepted (204 No Content).
func TestHandleNotify_ValidBody(t *testing.T) {
	client, cancel := startNotifyServer(t)
	defer cancel()

	body := `{"title":"hello","body":"world"}`
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"http://unix/notify",
		bytes.NewBufferString(body),
	)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// postNotify POSTs body to /notify and returns the status code and response
// body text.
func postNotify(t *testing.T, client *http.Client, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "http://unix/notify", bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(respBody)
}

// validV2Body returns a valid v2 Message JSON with a fresh ULID.
func validV2Body() string {
	return `{"v":2,"msg_id":"` + notifyv2.NewMsgID() + `","kind":"needs_input","host":"rig-1",` +
		`"session":{"session":"$1","window":"@2","pane":"%3","epoch":1},` +
		`"consumer":"claudecode","title":"needs input"}`
}

// TestHandleNotifyV2_HappyPath: a valid v2 payload is accepted and the
// dispatched RenderedNote carries the byte-exact locked title (phase success
// criterion 1 asserted at the daemon seam).
func TestHandleNotifyV2_HappyPath(t *testing.T) {
	notifier := &v2RecordingNotifier{}
	client, cancel := startNotifyServerWith(t, notifier)
	defer cancel()

	status, _ := postNotify(t, client, validV2Body())
	require.Equal(t, http.StatusNoContent, status)

	notes := notifier.all()
	require.Len(t, notes, 1, "the v2 payload must be dispatched via SendNote")
	assert.Equal(t, "rig-1 · claude · %3 needs input", notes[0].Title,
		"the locked compact title must arrive byte-exact at the daemon seam")
}

// TestHandleNotifyV2_UnknownKeyRejected (D-17 decode gate): a v2 payload with
// any unknown key — anything body/content-shaped — is rejected at decode time
// with 400. The Message struct has no body field, so a body key is unknown by
// construction.
func TestHandleNotifyV2_UnknownKeyRejected(t *testing.T) {
	notifier := &v2RecordingNotifier{}
	client, cancel := startNotifyServerWith(t, notifier)
	defer cancel()

	body := `{"v":2,"msg_id":"` + notifyv2.NewMsgID() + `","kind":"needs_input","host":"rig-1",` +
		`"title":"needs input","body":"secret stuff"}`
	status, _ := postNotify(t, client, body)
	assert.Equal(t, http.StatusBadRequest, status,
		"an unknown body/content-shaped key must be rejected at decode time")
	assert.Empty(t, notifier.all(), "a rejected payload must never be dispatched")
}

// TestHandleNotifyV2_ValidateFailure422: a payload failing Validate() (bad
// ULID) gets 422 and the response carries the reason.
func TestHandleNotifyV2_ValidateFailure422(t *testing.T) {
	notifier := &v2RecordingNotifier{}
	client, cancel := startNotifyServerWith(t, notifier)
	defer cancel()

	body := `{"v":2,"msg_id":"not-a-ulid","kind":"needs_input","host":"rig-1","title":"needs input"}`
	status, respBody := postNotify(t, client, body)
	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Contains(t, respBody, "msg_id", "the 422 response must carry the validation reason")
	assert.Empty(t, notifier.all())
}

// TestHandleNotifyV2_Enrichment: empty msg_id and host are enriched
// server-side (fresh ULID, cached short hostname) before validation, so the
// payload is accepted and the dispatched note carries the server hostname.
func TestHandleNotifyV2_Enrichment(t *testing.T) {
	notifier := &v2RecordingNotifier{}
	client, cancel := startNotifyServerWith(t, notifier)
	defer cancel()

	body := `{"v":2,"msg_id":"","kind":"needs_input","host":"",` +
		`"session":{"pane":"%3","epoch":1},"consumer":"claudecode","title":"needs input"}`
	status, _ := postNotify(t, client, body)
	require.Equal(t, http.StatusNoContent, status,
		"an empty msg_id must be enriched to a valid ULID (a 422 means enrichment did not run)")

	notes := notifier.all()
	require.Len(t, notes, 1)
	hostname, err := os.Hostname()
	require.NoError(t, err)
	short, _, _ := strings.Cut(hostname, ".")
	assert.Equal(t, short+" · claude · %3 needs input", notes[0].Title,
		"an empty host must be enriched to the server's short hostname")
}

// TestRun_RefusesToStealLiveSocket: a second daemon instance on the same
// socket path must refuse to start while the first is serving (its pre-listen
// probe gets an answer), and the first daemon's socket must stay untouched —
// no unconditional os.Remove may unlink a live daemon's socket.
func TestRun_RefusesToStealLiveSocket(t *testing.T) {
	client, cancel := startNotifyServer(t)
	defer cancel()

	srv2 := daemon.NewServer(notifyStubNotifier{}, nil, nil)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	err := srv2.Run(ctx2)
	require.Error(t, err, "a second daemon on a live socket must refuse to start")
	assert.Contains(t, err.Error(), "already serving")

	// The first daemon keeps serving: its socket file was not stolen.
	req, rerr := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://unix/health", nil)
	require.NoError(t, rerr)
	resp, derr := client.Do(req)
	require.NoError(t, derr, "the first daemon's socket must still answer")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestRun_RemovesStaleSocket: a leftover socket file from a crashed daemon
// (file exists, nothing listening → ECONNREFUSED on the probe) is cleared and
// the daemon starts normally.
func TestRun_RemovesStaleSocket(t *testing.T) {
	dir := shortRuntimeDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	// Fabricate the crash artifact: bind the socket, keep the file on close.
	ln, err := net.Listen("unix", filepath.Join(dir, "abysslinkd.sock"))
	require.NoError(t, err)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, ln.Close())

	srv := daemon.NewServer(notifyStubNotifier{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	require.Eventually(t, func() bool { return daemon.NewClient().Ping(context.Background()) },
		2*time.Second, 20*time.Millisecond, "the daemon must clear the stale socket and come up")
}

// TestHandleNotifyV2_Oversize413: a v2-shaped body over the existing cap still
// returns 413 (the A11 / DOS-01 guard covers both paths).
func TestHandleNotifyV2_Oversize413(t *testing.T) {
	notifier := &v2RecordingNotifier{}
	client, cancel := startNotifyServerWith(t, notifier)
	defer cancel()

	const maxNotifyBody = 256 * 1024
	padding := strings.Repeat("A", maxNotifyBody)
	body := `{"v":2,"msg_id":"` + notifyv2.NewMsgID() + `","kind":"needs_input","host":"` + padding + `","title":"t"}`
	status, _ := postNotify(t, client, body)
	assert.Equal(t, http.StatusRequestEntityTooLarge, status,
		"the 413 disambiguation must hold on the v2 path")
	assert.Empty(t, notifier.all())
}
