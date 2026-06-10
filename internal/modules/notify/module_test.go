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

package notify

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendDirect_PostsToNtfy(t *testing.T) {
	var receivedTitle, receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTitle = r.Header.Get("X-Title")
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirect(context.Background(), "hello title", "hello body")
	require.NoError(t, err)
	assert.Equal(t, "hello title", receivedTitle)
	assert.Equal(t, "hello body", receivedBody)
}

func TestSendDirect_NonOKStatus_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad credentials"))
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirect(context.Background(), "t", "b")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

// ── CLI-04: SendDirectWithOptions threads priority / tags / topic ────────────

// TestSendDirectWithOptions_HeadersAndTopic verifies that priority and tags
// become the ntfy X-Priority / X-Tags headers and that the topic override
// replaces the configured default topic in the URL path.
func TestSendDirectWithOptions_HeadersAndTopic(t *testing.T) {
	var gotPath, gotPriority, gotTags string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotPriority = r.Header.Get("X-Priority")
		gotTags = r.Header.Get("X-Tags")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{
		Priority: "high",
		Tags:     "warning",
		Topic:    "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, "/ops", gotPath, "--topic must override the configured default topic")
	assert.Equal(t, "high", gotPriority, "--priority must be sent as X-Priority")
	assert.Equal(t, "warning", gotTags, "--tag must be sent as X-Tags")
}

// TestSendDirectWithOptions_ZeroValueBackCompat verifies that zero options
// behave exactly like the historical SendDirect: default topic, no
// X-Priority/X-Tags headers.
func TestSendDirectWithOptions_ZeroValueBackCompat(t *testing.T) {
	var gotPath, gotPriority, gotTags string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotPriority = r.Header.Get("X-Priority")
		gotTags = r.Header.Get("X-Tags")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	require.NoError(t, m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{}))
	assert.Equal(t, "/alerts", gotPath, "zero options must use the configured default topic")
	assert.Empty(t, gotPriority, "zero options must not set X-Priority")
	assert.Empty(t, gotTags, "zero options must not set X-Tags")
}

// TestSendDirectWithOptions_ClickHeader verifies that SendOptions.Click becomes
// the ntfy X-Click header (D-16: tap-to-open ssh:// deep link) and that an
// empty Click sets no header at all.
func TestSendDirectWithOptions_ClickHeader(t *testing.T) {
	var gotClick string
	var clickPresent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClick = r.Header.Get("X-Click")
		_, clickPresent = r.Header["X-Click"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{
		Click: "ssh://mo@rig-1",
	})
	require.NoError(t, err)
	assert.True(t, clickPresent, "non-empty Click must set the X-Click header")
	assert.Equal(t, "ssh://mo@rig-1", gotClick, "X-Click must carry the exact configured value")

	// Empty Click → no X-Click header.
	require.NoError(t, m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{}))
	assert.False(t, clickPresent, "empty Click must not set X-Click")
}

// TestSendWithOptions_ZeroValueGuardStillComparable verifies that adding the
// Click string field keeps SendOptions comparable so the zero-options fast-path
// guard in SendWithOptions (opts == SendOptions{}) still compiles and works.
func TestSendWithOptions_ZeroValueGuardStillComparable(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	// Comparability is compile-level: SendWithOptions' own
	// `opts == (SendOptions{})` guard would not build if the Click field
	// broke it. Behavioral: zero options still deliver via the direct
	// fallback to the configured default topic (no daemon is listening).
	require.NoError(t, m.SendWithOptions(context.Background(), "t", "b", SendOptions{}))
	assert.Equal(t, "/alerts", gotPath)
}

// TestSendDirectWithOptions_InvalidTopicRejected verifies that a topic override
// outside the ntfy topic charset is refused before any request is built (the
// override is a URL path segment — it must never alter the request path).
func TestSendDirectWithOptions_InvalidTopicRejected(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirectWithOptions(context.Background(), "t", "b", SendOptions{Topic: "../evil"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid topic")
}

// ── SendMessage (v2 socket-first with validated direct fallback) ─────────────

// startFakeDaemonSocket starts an HTTP server on a unix socket at
// dir/abysslinkd.sock and points XDG_RUNTIME_DIR at dir so daemon.SocketPath()
// resolves to it. The dir lives under /tmp (not t.TempDir): macOS caps
// sun_path at ~104 bytes and /var/folders paths overflow it.
func startFakeDaemonSocket(t *testing.T, handler http.Handler) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "abl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)

	ln, err := net.Listen("unix", filepath.Join(dir, "abysslinkd.sock"))
	require.NoError(t, err)
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// noDaemon points XDG_RUNTIME_DIR at an empty short-lived dir so the daemon
// socket dial always fails — a deterministic "daemon unreachable" state even
// when a real abysslinkd happens to run on the developer machine.
func noDaemon(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "abl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
}

// validV2Message returns a Message that passes notifyv2.Validate.
func validV2Message() notifyv2.Message {
	return notifyv2.Message{
		V:       2,
		MsgID:   notifyv2.NewMsgID(),
		Kind:    notifyv2.KindNeedsInput,
		Host:    "rig-1",
		Session: notifyv2.SessionRef{Pane: "%3"},
		Title:   "needs input",
	}
}

// newSendMessageModule returns a notify Module with the module enabled.
func newSendMessageModule() *Module {
	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	return New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
}

// TestSendMessage_SocketPath_PostsV2JSON verifies the daemon-socket fast path:
// SendMessage POSTs the raw v2 JSON (containing "v":2 and the msg_id) to
// /notify and returns nil on 2xx — the direct ntfy path must not fire.
func TestSendMessage_SocketPath_PostsV2JSON(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotBody, gotContentType string
	startFakeDaemonSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPath, gotBody, gotContentType = r.URL.Path, string(b), r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))

	directHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	m := newSendMessageModule()
	msg := validV2Message()
	require.NoError(t, m.SendMessage(context.Background(), msg))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "/notify", gotPath, "v2 send must hit the daemon /notify route")
	assert.Contains(t, gotBody, `"v":2`, "POSTed body must be the v2 wire JSON")
	assert.Contains(t, gotBody, msg.MsgID, "POSTed body must carry the msg_id")
	assert.Equal(t, "application/json", gotContentType)
	assert.Zero(t, directHits, "daemon accepted — the direct ntfy path must not fire")
}

// TestSendMessage_FallbackRendersDirect verifies the unreachable-daemon
// fallback: Validate + Render + direct ntfy delivery with the rendered compact
// title, kind-derived priority/tags, and NO X-Click (the daemon owns click
// composition).
func TestSendMessage_FallbackRendersDirect(t *testing.T) {
	noDaemon(t)

	var mu sync.Mutex
	var hdr http.Header
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hdr = r.Header.Clone()
		gotPath = r.URL.Path
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	m := newSendMessageModule()
	require.NoError(t, m.SendMessage(context.Background(), validV2Message()))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "/alerts", gotPath, "fallback delivers to the per-rig topic (D-20)")
	assert.Equal(t, "rig-1 · %3 needs input", hdr.Get("X-Title"), "X-Title must carry the rendered compact title")
	assert.Equal(t, "3", hdr.Get("X-Priority"), "needs_input default priority is 3")
	assert.Equal(t, "question", hdr.Get("X-Tags"), "needs_input tag is question")
	assert.Empty(t, hdr.Get("X-Click"), "the daemon owns click composition — fallback sends no X-Click")
}

// TestSendMessage_FallbackInvalidMessage_SendsNothing verifies the no-bypass
// D-17 gate holds client-side: with the daemon unreachable, an invalid Message
// (bad ULID) returns the Validate error and zero HTTP requests are sent.
func TestSendMessage_FallbackInvalidMessage_SendsNothing(t *testing.T) {
	noDaemon(t)

	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	m := newSendMessageModule()
	msg := validV2Message()
	msg.MsgID = "not-a-ulid"
	err := m.SendMessage(context.Background(), msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ULID", "the Validate error must surface")

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, hits, "an invalid message must send zero HTTP requests in the fallback")
}

// TestSendMessage_DaemonRejection_SurfacesError verifies that a daemon 422
// surfaces as a descriptive error to the caller (the CLI prints it; no silent
// drop, no fallback to direct delivery).
func TestSendMessage_DaemonRejection_SurfacesError(t *testing.T) {
	startFakeDaemonSocket(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("notifyv2: title must be non-empty"))
	}))

	directHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	m := newSendMessageModule()
	err := m.SendMessage(context.Background(), validV2Message())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "422", "the daemon status code must be named")
	assert.Contains(t, err.Error(), "title must be non-empty", "the daemon's rejection reason must surface")
	assert.Zero(t, directHits, "a daemon rejection must NOT fall back to direct delivery")
}
