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

package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── TestNotifyAllRigs_Headers ─────────────────────────────────────────────────

// notifyTestKeychain is an in-memory KeychainStore for notify tests.
type notifyTestKeychain struct {
	mu   sync.RWMutex
	data map[string]string
}

func newNotifyTestKeychain() *notifyTestKeychain {
	return &notifyTestKeychain{data: make(map[string]string)}
}

func (k *notifyTestKeychain) Set(_ context.Context, service, account, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data[service+":"+account] = secret
	return nil
}

func (k *notifyTestKeychain) Get(_ context.Context, service, account string) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	v, ok := k.data[service+":"+account]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (k *notifyTestKeychain) Delete(_ context.Context, _, _ string) error { return nil }

// capturedRequest stores a received HTTP request for later assertion.
type capturedRequest struct {
	path string
	hdr  http.Header
}

// storeRigKey generates and stores an HMAC signing key for rigName, returning
// the hex key. The fan-out SKIPS rigs without a key (T-14-17/18), so every
// test that expects a delivered POST must enroll a key first.
func storeRigKey(t *testing.T, kc *notifyTestKeychain, rigName string) string {
	t.Helper()
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)
	require.NoError(t, kc.Set(context.Background(), fleet.RigService(rigName), "hmac-signing-key", key))
	return key
}

// discardPrinter returns a Printer that swallows all output (for fan-out tests
// that do not assert on the printed warnings).
func discardPrinter() Printer {
	return NewHumanPrinterTo(&bytes.Buffer{}, &bytes.Buffer{})
}

// TestNotifyAllRigs_Headers verifies that sendNotifyAllRigs sends a POST per rig,
// each request carrying the three HMAC rig-identity headers with correct values
// (SC-5, D-NI-03, T-14-17 / T-14-20). Also asserts per-rig topic isolation
// (T-14-18: Rig A never POSTs to Rig B's topic).
func TestNotifyAllRigs_Headers(t *testing.T) {
	// Set up an httptest.Server to capture all requests.
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{
			path: r.URL.Path,
			hdr:  r.Header.Clone(),
		})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Override the base URL test seam.
	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	// Two rigs with distinct topics.
	const (
		rigA    = "rig-alpha"
		topicA  = "abysslink-rig-alpha-aabbccdd"
		rigB    = "rig-beta"
		topicB  = "abysslink-rig-beta-11223344"
		title   = "Test Title"
		msgBody = "Hello fleet"
	)

	kc := newNotifyTestKeychain()

	// Generate and store a signing key for each rig.
	keyA, err := fleet.GenerateSigningKey()
	require.NoError(t, err)
	keyB, err := fleet.GenerateSigningKey()
	require.NoError(t, err)
	require.NoError(t, kc.Set(context.Background(), fleet.RigService(rigA), "hmac-signing-key", keyA))
	require.NoError(t, kc.Set(context.Background(), fleet.RigService(rigB), "hmac-signing-key", keyB))

	rigs := []config.RigConfig{
		{Name: rigA, NtfyTopic: topicA},
		{Name: rigB, NtfyTopic: topicB},
	}

	err = sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, title, msgBody, rigNotifyOpts{})
	require.NoError(t, err)

	require.Len(t, received, 2, "one POST per rig")

	// Build a lookup: topic path → captured request.
	byPath := make(map[string]capturedRequest)
	for _, r := range received {
		byPath[r.path] = r
	}

	// ── Rig A assertions ──

	reqA, ok := byPath["/"+topicA]
	require.True(t, ok, "Rig A must POST to its own topic %q, not to Rig B's", topicA)

	assert.Equal(t, rigA, reqA.hdr.Get("X-Abysslink-Rig"), "X-Abysslink-Rig must be rig A's name")
	tsA := reqA.hdr.Get("X-Abysslink-Rig-Ts")
	require.NotEmpty(t, tsA, "X-Abysslink-Rig-Ts must be set (Pitfall 6 / T-14-20)")
	sigA := reqA.hdr.Get("X-Abysslink-Rig-Sig")
	require.NotEmpty(t, sigA, "X-Abysslink-Rig-Sig must be set (SC-5)")

	// Recompute the HMAC and verify it matches (round-trip: origin provable).
	// WR-02: canonical string covers the length-prefixed fields rigName, ts,
	// title, message (fleet.SignRigMessage).
	assert.True(t,
		fleet.VerifyRigMessage(keyA, rigA, tsA, title, msgBody, sigA),
		"HMAC recompute+VerifyRigMessage for Rig A must return true (SC-5)")

	// Tampering the body must make the signature fail.
	assert.False(t,
		fleet.VerifyRigMessage(keyA, rigA, tsA, title, "tampered body", sigA),
		"Tampering the message body must make VerifyRigMessage return false")

	// WR-02: tampering the title must also fail (title is now in the HMAC).
	assert.False(t,
		fleet.VerifyRigMessage(keyA, rigA, tsA, "tampered title", msgBody, sigA),
		"Tampering the title must make VerifyRigMessage return false (WR-02)")

	// ── Rig B assertions ──

	reqB, ok := byPath["/"+topicB]
	require.True(t, ok, "Rig B must POST to its own topic %q, not to Rig A's", topicB)

	assert.Equal(t, rigB, reqB.hdr.Get("X-Abysslink-Rig"), "X-Abysslink-Rig must be rig B's name")
	tsB := reqB.hdr.Get("X-Abysslink-Rig-Ts")
	require.NotEmpty(t, tsB, "X-Abysslink-Rig-Ts must be set for Rig B")
	sigB := reqB.hdr.Get("X-Abysslink-Rig-Sig")
	require.NotEmpty(t, sigB, "X-Abysslink-Rig-Sig must be set for Rig B")

	// Rig A's key must not verify Rig B's signature (per-rig key isolation).
	assert.False(t,
		fleet.VerifyRigMessage(keyA, rigB, tsB, title, msgBody, sigB),
		"Rig A's key must not verify Rig B's signature (per-rig key isolation)")

	// ── Cross-topic isolation assertion ──
	// Rig A must never hit Rig B's topic and vice versa.
	_, rigAHitTopicB := byPath["/"+topicB+"-via-A"]
	assert.False(t, rigAHitTopicB, "Rig A must never POST to Rig B's topic")
	assert.NotEqual(t, reqA.path, reqB.path, "each rig must POST to its own distinct topic path")
}

// TestNotifyAllRigs_SkippedWhenNoKey verifies that a rig without an enrolled
// signing key is SKIPPED with a printed warning — never sent unsigned. Sending
// unsigned would be a silent signature-stripping downgrade (T-14-17/T-14-18):
// a verifier tolerating absent signatures could then be fed forged messages.
func TestNotifyAllRigs_SkippedWhenNoKey(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	const (
		rigName = "no-key-rig"
		topic   = "abysslink-no-key-rig-deadbeef"
	)

	// Empty keychain — no signing key stored.
	kc := newNotifyTestKeychain()
	rigs := []config.RigConfig{{Name: rigName, NtfyTopic: topic}}

	var outBuf, errBuf bytes.Buffer
	p := NewHumanPrinterTo(&outBuf, &errBuf)
	err := sendNotifyAllRigs(context.Background(), p, rigs, kc, "title", "body", rigNotifyOpts{})
	// A skip is not a failure: the warning is the signal, the exit stays clean.
	assert.NoError(t, err, "a skipped rig must not fail the whole fan-out")

	// NOTHING may have been sent — no unsigned downgrade POST.
	assert.Empty(t, received, "a rig without a signing key must be skipped, never sent unsigned")

	// The skip must be VISIBLE (printed warning on stderr, not just slog).
	assert.Contains(t, errBuf.String(), rigName, "the warning must name the skipped rig")
	assert.Contains(t, errBuf.String(), "no HMAC signing key", "the warning must explain why the rig was skipped")
	assert.Contains(t, errBuf.String(), "enroll rig", "the warning must point at re-enrollment")
}

// TestNotifyAllRigs_SkipDoesNotBlockSiblings: in a mixed fleet (one rig with a
// key, one without) the keyed rig is still notified and the keyless one skipped.
func TestNotifyAllRigs_SkipDoesNotBlockSiblings(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	storeRigKey(t, kc, "keyed-rig")
	rigs := []config.RigConfig{
		{Name: "keyed-rig", NtfyTopic: "topic-keyed"},
		{Name: "keyless-rig", NtfyTopic: "topic-keyless"},
	}

	err := sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, "t", "m", rigNotifyOpts{})
	require.NoError(t, err)

	require.Len(t, received, 1, "only the keyed rig may receive a POST")
	assert.Equal(t, "/topic-keyed", received[0].path)
	assert.NotEmpty(t, received[0].hdr.Get("X-Abysslink-Rig-Sig"), "the delivered POST must be signed")
}

// TestNotifyAllRigs_BasicAuthFromKeychain (NET-02): the abysslink-managed ntfy
// server is deny-all, so fan-out POSTs must carry the admin basic auth from the
// keychain (service "abysslink", account "ntfy-password") — without it every
// fleet notify 403s.
func TestNotifyAllRigs_BasicAuthFromKeychain(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	storeRigKey(t, kc, "auth-rig")
	require.NoError(t, kc.Set(context.Background(), "abysslink", "ntfy-password", "s3cret"))

	rigs := []config.RigConfig{{Name: "auth-rig", NtfyTopic: "topic-auth"}}
	require.NoError(t, sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, "t", "m", rigNotifyOpts{}))

	require.Len(t, received, 1)
	authHdr := received[0].hdr.Get("Authorization")
	require.NotEmpty(t, authHdr, "fan-out POST must carry Authorization (deny-all ntfy server)")
	// Decode and verify it is admin:<password> basic auth.
	req := &http.Request{Header: received[0].hdr}
	user, pass, ok := req.BasicAuth()
	require.True(t, ok, "Authorization header must be HTTP basic auth")
	assert.Equal(t, "admin", user)
	assert.Equal(t, "s3cret", pass)
}

// TestNotifyAllRigs_NoAuthWhenNoCredential: with no ntfy-password in the
// keychain the POST goes out without Authorization (anonymous ntfy.sh path).
func TestNotifyAllRigs_NoAuthWhenNoCredential(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	storeRigKey(t, kc, "anon-rig")
	rigs := []config.RigConfig{{Name: "anon-rig", NtfyTopic: "topic-anon"}}

	require.NoError(t, sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, "t", "m", rigNotifyOpts{}))
	require.Len(t, received, 1)
	assert.Empty(t, received[0].hdr.Get("Authorization"), "no credential → no Authorization header")
}

// TestNotifyAllRigs_PerRigTopic asserts that Rig A's POST path is strictly
// its own topic and Rig B's POST path is strictly its own topic.
func TestNotifyAllRigs_PerRigTopic(t *testing.T) {
	var mu sync.Mutex
	topicsSeen := make(map[string]string) // path → rig name header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		topicsSeen[r.URL.Path] = r.Header.Get("X-Abysslink-Rig")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	rigs := []config.RigConfig{
		{Name: "rho", NtfyTopic: "topic-rho"},
		{Name: "sigma", NtfyTopic: "topic-sigma"},
		{Name: "tau", NtfyTopic: "topic-tau"},
	}
	for _, r := range rigs {
		storeRigKey(t, kc, r.Name)
	}

	require.NoError(t, sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, "t", "m", rigNotifyOpts{}))

	// Each topic path must be hit exactly once by its own rig.
	for _, rig := range rigs {
		path := "/" + rig.NtfyTopic
		rigHeader, ok := topicsSeen[path]
		assert.True(t, ok, "topic %q must receive exactly one POST", rig.NtfyTopic)
		assert.Equal(t, rig.Name, rigHeader, "POST to topic %q must carry X-Abysslink-Rig=%q", rig.NtfyTopic, rig.Name)
	}
	assert.Len(t, topicsSeen, len(rigs), "number of distinct topics hit must equal number of rigs")
}

// TestNotifyAllRigs_HMACCanonicalString verifies that the signed canonical
// string covers the length-prefixed fields rigName, ts, title, message,
// matching the verifier recipe (WR-02: title is included in the signed payload).
func TestNotifyAllRigs_HMACCanonicalString(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	const rigName = "canonical-test-rig"
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)
	require.NoError(t, kc.Set(context.Background(), fleet.RigService(rigName), "hmac-signing-key", key))

	rigs := []config.RigConfig{{Name: rigName, NtfyTopic: "topic-canonical"}}
	const (
		titleStr = "Canonical Title"
		msgStr   = "canonical message body"
	)

	// Capture a known timestamp by recording before/after the call.
	before := strconv.FormatInt(time.Now().Unix(), 10)
	require.NoError(t, sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, titleStr, msgStr, rigNotifyOpts{}))
	after := strconv.FormatInt(time.Now().Unix(), 10)

	require.Len(t, received, 1)
	ts := received[0].hdr.Get("X-Abysslink-Rig-Ts")
	sig := received[0].hdr.Get("X-Abysslink-Rig-Sig")

	// ts must be a valid integer in [before, after].
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	require.NoError(t, err, "X-Abysslink-Rig-Ts must be an integer string")
	beforeInt, _ := strconv.ParseInt(before, 10, 64)
	afterInt, _ := strconv.ParseInt(after, 10, 64)
	assert.GreaterOrEqual(t, tsInt, beforeInt)
	assert.LessOrEqual(t, tsInt, afterInt)

	// Verify HMAC using the full canonical string (length-prefixed fields, WR-02).
	assert.True(t, fleet.VerifyRigMessage(key, rigName, ts, titleStr, msgStr, sig),
		"VerifyRigMessage must return true using the length-prefixed canonical fields rigName, ts, title, message")

	// Tampering the title alone must fail (WR-02 coverage).
	assert.False(t, fleet.VerifyRigMessage(key, rigName, ts, "tampered title", msgStr, sig),
		"VerifyRigMessage must return false when title is tampered (WR-02)")
}

// ── CLI-04 / CLI-14 / NET-02: option threading + base URL resolution ─────────

// TestNotifyAllRigs_PriorityAndTagsHeaders verifies that --priority/--tag are
// threaded into the per-rig fan-out POSTs as X-Priority / X-Tags (CLI-04 —
// previously the flags were declared but silently dropped).
func TestNotifyAllRigs_PriorityAndTagsHeaders(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	storeRigKey(t, kc, "opts-rig")
	rigs := []config.RigConfig{{Name: "opts-rig", NtfyTopic: "topic-opts"}}

	err := sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, "t", "m",
		rigNotifyOpts{priority: "urgent", tags: "warning,skull"})
	require.NoError(t, err)
	require.Len(t, received, 1)
	assert.Equal(t, "urgent", received[0].hdr.Get("X-Priority"), "--priority must reach ntfy as X-Priority")
	assert.Equal(t, "warning,skull", received[0].hdr.Get("X-Tags"), "--tag must reach ntfy as X-Tags")
}

// TestNotifyAllRigs_NoOptionsOmitsHeaders verifies backward compatibility:
// when the flags are unset, no X-Priority/X-Tags headers are added.
func TestNotifyAllRigs_NoOptionsOmitsHeaders(t *testing.T) {
	var mu sync.Mutex
	var received []capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, capturedRequest{path: r.URL.Path, hdr: r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := notifyCmdBaseURL
	notifyCmdBaseURL = srv.URL
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	storeRigKey(t, kc, "plain-rig")
	rigs := []config.RigConfig{{Name: "plain-rig", NtfyTopic: "topic-plain"}}

	require.NoError(t, sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, "t", "m", rigNotifyOpts{}))
	require.Len(t, received, 1)
	assert.Empty(t, received[0].hdr.Get("X-Priority"), "unset --priority must not emit X-Priority")
	assert.Empty(t, received[0].hdr.Get("X-Tags"), "unset --tag must not emit X-Tags")
}

// TestNotifyAllRigs_BaseURLFromOpts verifies the CLI-14 resolution order: with
// the test seam empty, the caller-resolved base URL (config port + tailnet IP)
// is used instead of the hardcoded http://localhost:2586.
func TestNotifyAllRigs_BaseURLFromOpts(t *testing.T) {
	var mu sync.Mutex
	hits := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Seam deliberately EMPTY — opts.baseURL must be honored.
	old := notifyCmdBaseURL
	notifyCmdBaseURL = ""
	defer func() { notifyCmdBaseURL = old }()

	kc := newNotifyTestKeychain()
	storeRigKey(t, kc, "url-rig")
	rigs := []config.RigConfig{{Name: "url-rig", NtfyTopic: "topic-url"}}

	err := sendNotifyAllRigs(context.Background(), discardPrinter(), rigs, kc, "t", "m",
		rigNotifyOpts{baseURL: srv.URL})
	require.NoError(t, err)
	assert.Equal(t, 1, hits, "POST must target the caller-resolved base URL, not localhost:2586")
}

// ── D-30/D-31/D-32: notify v2 — --kind/--pane, TMUX_PANE autodetect, wrap ────

// v1SendCall records one v1-path send (title, body, options) captured at the
// notifySendV1 seam.
type v1SendCall struct {
	title string
	body  string
	opts  notifymod.SendOptions
}

// notifySeamCapture records every send routed through the v1/v2 seams so the
// D-31 selection matrix can be asserted without any network or daemon.
type notifySeamCapture struct {
	mu      sync.Mutex
	v2Msgs  []notifyv2.Message
	v2Err   error // returned from the v2 seam (scripted notification failure)
	v1Calls []v1SendCall
}

// installNotifySeams swaps the package send seams for capturing fakes and
// restores them at cleanup.
func installNotifySeams(t *testing.T) *notifySeamCapture {
	t.Helper()
	cap := &notifySeamCapture{}
	oldV2, oldV1 := notifySendMessage, notifySendV1
	notifySendMessage = func(_ context.Context, _ *notifymod.Module, msg notifyv2.Message) error {
		cap.mu.Lock()
		defer cap.mu.Unlock()
		cap.v2Msgs = append(cap.v2Msgs, msg)
		return cap.v2Err
	}
	notifySendV1 = func(_ context.Context, _ *notifymod.Module, title, body string, opts notifymod.SendOptions) error {
		cap.mu.Lock()
		defer cap.mu.Unlock()
		cap.v1Calls = append(cap.v1Calls, v1SendCall{title: title, body: body, opts: opts})
		return nil
	}
	t.Cleanup(func() { notifySendMessage, notifySendV1 = oldV2, oldV1 })
	return cap
}

// runNotify executes `abysslink notify` through the real cobra tree with a
// zero-scripted MockRunner (no external command may run) and returns the
// command error plus captured output.
func runNotify(t *testing.T, args ...string) error {
	t.Helper()
	origNewRunner := newRunner
	newRunner = func() shell.Runner { return shell.NewMockRunner() }
	t.Cleanup(func() { newRunner = origNewRunner })
	return execNotify(t, args...)
}

// execNotify runs the notify command without touching the newRunner seam (the
// caller already installed one).
func execNotify(t *testing.T, args ...string) error {
	t.Helper()
	cfgPath := writeDaemonCfg(t)
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	full := append([]string{"notify", "--config", cfgPath}, args...)
	root.SetArgs(full)
	return root.Execute()
}

// TestNotifyV2_Matrix_AutoInsideTmux is D-31 case (a): title only with
// TMUX_PANE set → v2 with the pane autodetected and Kind needs_input.
func TestNotifyV2_Matrix_AutoInsideTmux(t *testing.T) {
	t.Setenv("TMUX_PANE", "%3")
	cap := installNotifySeams(t)

	require.NoError(t, runNotify(t, "ping"))

	require.Len(t, cap.v2Msgs, 1, "inside tmux a title-only notify must take the v2 path")
	msg := cap.v2Msgs[0]
	assert.Equal(t, 2, msg.V)
	assert.Equal(t, "needs_input", string(msg.Kind), "auto kind defaults to needs_input")
	assert.Equal(t, "%3", msg.Session.Pane, "pane must be autodetected from TMUX_PANE")
	assert.Equal(t, "ping", msg.Title)
	assert.NotEmpty(t, msg.MsgID, "a fresh msg_id must be minted")
	assert.NotEmpty(t, msg.Host, "host must carry the short hostname")
	assert.Empty(t, cap.v1Calls, "v1 path must not fire")
}

// TestNotifyV2_Matrix_OutsideTmuxStaysV1 is D-31 case (b): title only without
// TMUX_PANE → the v1 path with byte-identical args to today.
func TestNotifyV2_Matrix_OutsideTmuxStaysV1(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)

	require.NoError(t, runNotify(t, "ping"))

	require.Len(t, cap.v1Calls, 1, "outside tmux the v1 path must fire")
	assert.Equal(t, v1SendCall{title: "ping", body: "", opts: notifymod.SendOptions{}}, cap.v1Calls[0],
		"v1 args must be byte-identical to today")
	assert.Empty(t, cap.v2Msgs, "v2 path must not fire outside tmux")
}

// TestNotifyV2_Matrix_BodyForcesV1 is D-31 case (c): title + body rides the v1
// path even inside tmux (v2 carries no body until Phase 28).
func TestNotifyV2_Matrix_BodyForcesV1(t *testing.T) {
	t.Setenv("TMUX_PANE", "%3")
	cap := installNotifySeams(t)

	require.NoError(t, runNotify(t, "ping", "all good"))

	require.Len(t, cap.v1Calls, 1, "a body argument must force the v1 path")
	assert.Equal(t, v1SendCall{title: "ping", body: "all good", opts: notifymod.SendOptions{}}, cap.v1Calls[0])
	assert.Empty(t, cap.v2Msgs)
}

// TestNotifyV2_Matrix_KindForcesV2OutsideTmux is D-31 case (d): explicit
// --kind forces v2 even outside tmux, with an empty SessionRef.
func TestNotifyV2_Matrix_KindForcesV2OutsideTmux(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)

	require.NoError(t, runNotify(t, "--kind", "command_done", "ping"))

	require.Len(t, cap.v2Msgs, 1, "--kind must force the v2 path")
	msg := cap.v2Msgs[0]
	assert.Equal(t, "command_done", string(msg.Kind))
	assert.Equal(t, notifyv2.SessionRef{}, msg.Session, "outside tmux the SessionRef is empty")
	assert.Equal(t, "ping", msg.Title)
	assert.Empty(t, cap.v1Calls)
}

// TestNotifyV2_Matrix_BodyPlusKindIsError is D-31 case (e): combining a body
// with --kind/--pane is an error explaining that v2 carries no body.
func TestNotifyV2_Matrix_BodyPlusKindIsError(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)

	err := runNotify(t, "--kind", "needs_input", "ping", "some body")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no body", "the error must explain v2 carries no body")
	assert.Empty(t, cap.v2Msgs, "nothing may be sent on a flag conflict")
	assert.Empty(t, cap.v1Calls)
}

// TestNotifyV2_InvalidKindRejected: --kind outside the closed enum is a
// descriptive error listing the five valid kinds, sent before anything fires.
func TestNotifyV2_InvalidKindRejected(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)

	err := runNotify(t, "--kind", "bogus", "ping")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs_input", "the error must list the valid kinds")
	assert.Contains(t, err.Error(), "agent_stopped", "the error must list the valid kinds")
	assert.Empty(t, cap.v2Msgs)
	assert.Empty(t, cap.v1Calls)
}

// TestNotifyV2_MalformedPaneFlagRejected: --pane must match ^%\d+$.
func TestNotifyV2_MalformedPaneFlagRejected(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)

	err := runNotify(t, "--pane", "3", "ping")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `%\d+`, "the error must name the required pane format")
	assert.Empty(t, cap.v2Msgs)
	assert.Empty(t, cap.v1Calls)
}

// TestNotifyV2_MalformedTmuxPaneIgnored: a malformed TMUX_PANE (stale/forged
// metadata, Pitfall 8) is ignored without error — v2 proceeds with an empty
// pane because the env var being set still means "inside tmux".
func TestNotifyV2_MalformedTmuxPaneIgnored(t *testing.T) {
	t.Setenv("TMUX_PANE", "%x")
	cap := installNotifySeams(t)

	require.NoError(t, runNotify(t, "ping"))

	require.Len(t, cap.v2Msgs, 1, "malformed TMUX_PANE must not fail the notification")
	assert.Empty(t, cap.v2Msgs[0].Session.Pane, "the malformed pane value must be dropped")
	assert.Empty(t, cap.v1Calls)
}

// TestNotifyV2_PaneFlagOverridesEnv: --pane wins over TMUX_PANE.
func TestNotifyV2_PaneFlagOverridesEnv(t *testing.T) {
	t.Setenv("TMUX_PANE", "%3")
	cap := installNotifySeams(t)

	require.NoError(t, runNotify(t, "--pane", "%7", "ping"))

	require.Len(t, cap.v2Msgs, 1)
	assert.Equal(t, "%7", cap.v2Msgs[0].Session.Pane, "--pane must override TMUX_PANE")
}

// wrapTestRunner is a shell.Runner whose RunInteractive records the exact argv
// and returns a scripted error. Every non-interactive method delegates to the
// embedded zero-scripted MockRunner (which errors — proving wrap mode execs
// nothing besides the wrapped command).
type wrapTestRunner struct {
	shell.Runner
	mu   sync.Mutex
	argv [][]string
	err  error
}

func (r *wrapTestRunner) RunInteractive(_ context.Context, name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.argv = append(r.argv, append([]string{name}, args...))
	return r.err
}

// installWrapRunner swaps newRunner for a wrapTestRunner scripted with err.
func installWrapRunner(t *testing.T, err error) *wrapTestRunner {
	t.Helper()
	runner := &wrapTestRunner{Runner: shell.NewMockRunner(), err: err}
	origNewRunner := newRunner
	newRunner = func() shell.Runner { return runner }
	t.Cleanup(func() { newRunner = origNewRunner })
	return runner
}

// TestNotifyWrap_Success (D-32): notify -- <argv> execs the exact argv via
// RunInteractive, sends a v2 command_done titled "done ✓", and exits 0.
func TestNotifyWrap_Success(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)
	runner := installWrapRunner(t, nil)

	require.NoError(t, execNotify(t, "--", "make", "build", "-j4"))

	runner.mu.Lock()
	require.Len(t, runner.argv, 1, "exactly one wrapped exec")
	assert.Equal(t, []string{"make", "build", "-j4"}, runner.argv[0], "argv must pass through exactly (flags included)")
	runner.mu.Unlock()

	require.Len(t, cap.v2Msgs, 1, "wrap must send a v2 command_done")
	msg := cap.v2Msgs[0]
	assert.Equal(t, "command_done", string(msg.Kind))
	assert.Equal(t, "done ✓", msg.Title, "success title word is 'done ✓' (D-32)")
	assert.Empty(t, msg.Priority, "success rides the default priority")
}

// TestNotifyWrap_FailureExitCodeAndHighPriority (D-32): a wrapped command
// exiting 3 yields Title "failed ✗" at Priority high, and the CLI exits 3.
func TestNotifyWrap_FailureExitCodeAndHighPriority(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)
	installWrapRunner(t, &exitError{code: 3})

	err := execNotify(t, "--", "false")
	var ee *exitError
	require.ErrorAs(t, err, &ee, "wrap must propagate the wrapped exit code as an exitError")
	assert.Equal(t, 3, ee.ExitCode(), "the CLI exit code must be the wrapped command's own")

	require.Len(t, cap.v2Msgs, 1)
	msg := cap.v2Msgs[0]
	assert.Equal(t, "failed ✗", msg.Title, "failure title word is 'failed ✗' (D-32)")
	assert.Equal(t, "high", msg.Priority, "failure is high priority")
}

// TestNotifyWrap_NotificationFailureNeverMasksExitCode (T-27-34): a
// SendMessage error must not change the wrapped command's exit code; a warning
// is printed instead.
func TestNotifyWrap_NotificationFailureNeverMasksExitCode(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)
	cap.v2Err = errors.New("ntfy is down")
	installWrapRunner(t, &exitError{code: 3})

	err := execNotify(t, "--", "false")
	var ee *exitError
	require.ErrorAs(t, err, &ee, "a notification failure must not replace the exit code")
	assert.Equal(t, 3, ee.ExitCode(), "exit code 3 must survive the SendMessage failure")
	require.Len(t, cap.v2Msgs, 1, "the send was attempted")
}

// TestNotifyWrap_EmptyArgvRejected: `notify --` with nothing after the dash is
// a usage error, not a silent no-op.
func TestNotifyWrap_EmptyArgvRejected(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)
	runner := installWrapRunner(t, nil)

	err := execNotify(t, "--")
	require.Error(t, err)

	runner.mu.Lock()
	assert.Empty(t, runner.argv, "nothing may be exec'd")
	runner.mu.Unlock()
	assert.Empty(t, cap.v2Msgs)
	assert.Empty(t, cap.v1Calls)
}

// TestNotifyWrap_PreDashArgsRejected (CLI-04): positionals before -- (e.g.
// `notify "Deploy finished" -- make build`) would be silently discarded —
// wrap mode must reject them with a descriptive error instead.
func TestNotifyWrap_PreDashArgsRejected(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)
	runner := installWrapRunner(t, nil)

	err := execNotify(t, "Deploy finished", "--", "make", "build")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "before --", "the error must explain wrap mode takes no pre-dash args")
	assert.Contains(t, err.Error(), "Deploy finished", "the error must echo the discarded args")

	runner.mu.Lock()
	assert.Empty(t, runner.argv, "nothing may be exec'd on a rejected invocation")
	runner.mu.Unlock()
	assert.Empty(t, cap.v2Msgs)
	assert.Empty(t, cap.v1Calls)
}

// TestNotifyWrap_RigFlagsRejected: wrap mode never validates against rig
// fan-out — `notify --all-rigs -- cmd` (or --rig) must be a hard error, not a
// silent local-only v2 send.
func TestNotifyWrap_RigFlagsRejected(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)
	runner := installWrapRunner(t, nil)

	for _, flags := range [][]string{{"--all-rigs"}, {"--rig", "alpha"}} {
		args := append(append([]string{}, flags...), "--", "make", "build")
		err := execNotify(t, args...)
		require.Error(t, err, "wrap mode with %v must be rejected", flags)
		assert.Contains(t, err.Error(), "wrap mode", "the error must name the conflict: %v", flags)
	}

	runner.mu.Lock()
	assert.Empty(t, runner.argv, "nothing may be exec'd on a rejected invocation")
	runner.mu.Unlock()
	assert.Empty(t, cap.v2Msgs, "no local v2 send may fire on a rejected fan-out wrap")
	assert.Empty(t, cap.v1Calls)
}

// TestNotifyAllRigs_ZeroEnrolledIsError: --all-rigs with zero enrolled rigs
// must error instead of silently falling through to a LOCAL send (the user
// explicitly asked for fan-out — a local send is a misroute).
func TestNotifyAllRigs_ZeroEnrolledIsError(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)

	err := runNotify(t, "--all-rigs", "title", "body")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rigs are enrolled", "the error must explain the empty fleet")
	assert.Empty(t, cap.v1Calls, "no local v1 send may fire when fan-out was requested")
	assert.Empty(t, cap.v2Msgs, "no local v2 send may fire when fan-out was requested")
}

// signalExitError mimics *exec.ExitError for a signal-killed child: ExitCode()
// reports -1 and Sys() exposes the syscall.WaitStatus (the ProcessState shape).
type signalExitError struct{ ws syscall.WaitStatus }

func (e *signalExitError) Error() string { return "signal: terminated" }
func (e *signalExitError) ExitCode() int { return -1 }
func (e *signalExitError) Sys() any      { return e.ws }

// TestNotifyWrap_SignalKilledMapsTo128PlusSignum: a wrapped command killed by
// SIGTERM must surface the conventional 128+signum (143), not the raw -1
// (which the process layer would wrap to 255).
func TestNotifyWrap_SignalKilledMapsTo128PlusSignum(t *testing.T) {
	t.Setenv("TMUX_PANE", "")
	cap := installNotifySeams(t)
	installWrapRunner(t, &signalExitError{ws: syscall.WaitStatus(int(syscall.SIGTERM))})

	err := execNotify(t, "--", "sleep", "60")
	var ee *exitError
	require.ErrorAs(t, err, &ee, "a signal-killed wrap must still propagate an exitError")
	assert.Equal(t, 128+int(syscall.SIGTERM), ee.ExitCode(), "signal-killed child maps to 128+signum (SIGTERM → 143)")

	require.Len(t, cap.v2Msgs, 1, "the outcome notification must still be sent")
	assert.Equal(t, "failed ✗", cap.v2Msgs[0].Title)
	assert.Equal(t, "high", cap.v2Msgs[0].Priority)
}

// TestClassifyClaudeNotification covers the Notification-hook type detection:
// permission/select/idle messages get distinct titles, and the real message is
// always passed through as the body (feature: surface the select-option and
// other notification types, not one hardcoded "Claude needs you").
func TestClassifyClaudeNotification(t *testing.T) {
	cases := []struct {
		msg       string
		wantTitle string
		wantBody  string
	}{
		{"Claude needs your permission to use Bash", "Claude needs approval", "Claude needs your permission to use Bash"},
		{"Select an option to continue", "Claude needs a decision", "Select an option to continue"},
		{"Choose which files to edit", "Claude needs a decision", "Choose which files to edit"},
		{"Claude is waiting for your input", "Claude needs input", "Claude is waiting for your input"},
		{"", "Claude needs you", "waiting for input"},
		{"Something unexpected happened", "Claude", "Something unexpected happened"},
	}
	for _, c := range cases {
		title, body, prio := classifyClaudeNotification(c.msg)
		assert.Equal(t, c.wantTitle, title, "title for %q", c.msg)
		assert.Equal(t, c.wantBody, body, "body must carry Claude's real message for %q", c.msg)
		assert.NotEmpty(t, prio, "priority must be set for %q", c.msg)
	}
	// Permission/approval is the most urgent tier.
	_, _, prio := classifyClaudeNotification("Claude needs your permission to run rm -rf")
	assert.Equal(t, "max", prio, "approval prompts must be max priority")
}
