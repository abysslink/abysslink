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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// startNotifyServer spins up a daemon Server on a temp Unix socket and returns
// an HTTP client wired to that socket plus a cancel function.
// The socket dir comes from shortRuntimeDir (daemon_test.go): macOS limits Unix
// socket paths to ~104 bytes and t.TempDir() under /var/folders exceeds it.
func startNotifyServer(t *testing.T) (*http.Client, context.CancelFunc) {
	t.Helper()
	dir := shortRuntimeDir(t)
	sock := filepath.Join(dir, "abysslinkd-notify.sock")
	t.Setenv("XDG_RUNTIME_DIR", dir)
	_ = os.Remove(sock)

	srv := daemon.NewServer(notifyStubNotifier{}, nil, nil)
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
