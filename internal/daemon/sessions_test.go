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

package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/session"
)

// These tests are INTERNAL (package daemon, unlike the server_test.go harness)
// because the D-15 suppression test must arm dispatcher cooldown state
// directly — there is no exported heuristic-origin dispatch path until the
// plan-27-07 bridge, and the bridge tests live in bridge_test.go.

// shortSessionsDir mirrors shortRuntimeDir (daemon_test.go, package
// daemon_test — internal tests cannot reach it): macOS limits Unix socket
// paths to ~104 bytes, so t.TempDir() under /var/folders is too long.
func shortSessionsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "abl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeSessionSource is a canned-snapshot SessionSource for /sessions tests.
type fakeSessionSource struct{ snap session.Snapshot }

func (f *fakeSessionSource) Snapshot() session.Snapshot { return f.snap }

// startSessionsServer spins up a daemon Server on a temp Unix socket (the
// server_test.go harness shape), optionally wiring src via SetSessionRegistry,
// and returns the server (for dispatcher-state setup), a socket-dialing HTTP
// client, and a cancel func.
func startSessionsServer(t *testing.T, src SessionSource) (*Server, *http.Client, context.CancelFunc) {
	t.Helper()
	dir := shortSessionsDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	srv := NewServer(&captureNotifier{}, nil, nil)
	if src != nil {
		srv.SetSessionRegistry(src)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Run(ctx) }()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", SocketPath())
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
	return srv, client, cancel
}

// getSessions GETs /sessions over the test socket and returns the status code
// plus the decoded JSON body (nil on non-200).
func getSessions(t *testing.T, client *http.Client) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://unix/sessions", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body), "body: %s", raw)
	return resp.StatusCode, body
}

// paneFromBody walks the sessions/windows/panes tree for paneID.
func paneFromBody(t *testing.T, body map[string]any, paneID string) map[string]any {
	t.Helper()
	sessions, ok := body["sessions"].([]any)
	require.True(t, ok, "sessions must be a JSON array")
	for _, s := range sessions {
		sm, ok := s.(map[string]any)
		require.True(t, ok)
		windows, ok := sm["windows"].([]any)
		require.True(t, ok)
		for _, w := range windows {
			wm, ok := w.(map[string]any)
			require.True(t, ok)
			panes, ok := wm["panes"].([]any)
			require.True(t, ok)
			for _, p := range panes {
				pm, ok := p.(map[string]any)
				require.True(t, ok)
				if pm["id"] == paneID {
					return pm
				}
			}
		}
	}
	t.Fatalf("pane %s not found in /sessions body", paneID)
	return nil
}

// twoPaneSnapshot is the canonical happy-path fixture: one session/window with
// a shell pane and a needs_input claudecode pane.
func twoPaneSnapshot(since time.Time) session.Snapshot {
	return session.Snapshot{
		Epoch:       3,
		Status:      session.StatusOK,
		TmuxVersion: "3.6b",
		Sessions: []session.SessionState{{
			ID:       "$1",
			Name:     "work",
			Attached: 1,
			Windows: []session.WindowState{{
				ID:   "@2",
				Name: "editor",
				Panes: []session.PaneState{
					{ID: "%1", Active: true, Consumer: "shell"},
					{ID: "%3", Consumer: "claudecode", NeedsInput: true, NeedsInputSince: since},
				},
			}},
		}},
	}
}

// TestSessions_HappySnapshot: a two-pane snapshot (one needs_input) renders as
// 200 JSON with status ok, the epoch, the nested tree, and needs_input_since
// only on the needs_input pane.
func TestSessions_HappySnapshot(t *testing.T) {
	since := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	_, client, cancel := startSessionsServer(t, &fakeSessionSource{snap: twoPaneSnapshot(since)})
	defer cancel()

	code, body := getSessions(t, client)
	require.Equal(t, http.StatusOK, code)

	assert.Equal(t, "ok", body["status"])
	assert.Equal(t, float64(3), body["epoch"])
	assert.Equal(t, "3.6b", body["tmux_version"])

	sessions, ok := body["sessions"].([]any)
	require.True(t, ok)
	require.Len(t, sessions, 1)
	sess := sessions[0].(map[string]any)
	assert.Equal(t, "$1", sess["id"])
	assert.Equal(t, "work", sess["name"])
	assert.Equal(t, float64(1), sess["attached"])

	windows := sess["windows"].([]any)
	require.Len(t, windows, 1)
	win := windows[0].(map[string]any)
	assert.Equal(t, "@2", win["id"])
	assert.Equal(t, "editor", win["name"])
	require.Len(t, win["panes"].([]any), 2)

	shellPane := paneFromBody(t, body, "%1")
	assert.Equal(t, true, shellPane["active"])
	assert.Equal(t, false, shellPane["alternate_screen"])
	assert.Equal(t, "shell", shellPane["consumer"])
	assert.Equal(t, false, shellPane["needs_input"])
	_, hasSince := shellPane["needs_input_since"]
	assert.False(t, hasSince, "needs_input_since must be omitted when not needs_input")

	niPane := paneFromBody(t, body, "%3")
	assert.Equal(t, "claudecode", niPane["consumer"])
	assert.Equal(t, true, niPane["needs_input"])
	assert.Equal(t, since.Format(time.RFC3339), niPane["needs_input_since"])
}

// TestSessions_SuppressionFields (D-15): a pane with active dispatcher
// suppression shows suppressed_count and cooldown_until; a pane without shows
// neither key (omitempty in both directions).
func TestSessions_SuppressionFields(t *testing.T) {
	since := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	srv, client, cancel := startSessionsServer(t, &fakeSessionSource{snap: twoPaneSnapshot(since)})
	defer cancel()

	until := time.Now().Add(2 * time.Minute).Truncate(time.Second)
	key := cooldownKey{epoch: 3, pane: "%3", kind: notifyv2.KindNeedsInput}
	srv.dispatch.mu.Lock()
	srv.dispatch.cooldown[key] = until
	srv.dispatch.suppressed[key] = 2
	srv.dispatch.mu.Unlock()

	code, body := getSessions(t, client)
	require.Equal(t, http.StatusOK, code)

	suppressed := paneFromBody(t, body, "%3")
	assert.Equal(t, float64(2), suppressed["suppressed_count"])
	assert.Equal(t, until.Format(time.RFC3339), suppressed["cooldown_until"])

	clean := paneFromBody(t, body, "%1")
	_, hasCount := clean["suppressed_count"]
	assert.False(t, hasCount, "suppressed_count must be omitted when zero")
	_, hasUntil := clean["cooldown_until"]
	assert.False(t, hasUntil, "cooldown_until must be omitted when no cooldown is active")
}

// TestSessions_DegradedStatuses (D-26/D-27): the registry's honest degraded
// status strings pass through verbatim with an EMPTY (never null, never
// fabricated) sessions list — and always 200, never a 5xx.
func TestSessions_DegradedStatuses(t *testing.T) {
	for _, status := range []string{
		"tmux: unavailable",
		"tmux: unsupported (3.1, need >= 3.2)",
	} {
		t.Run(status, func(t *testing.T) {
			_, client, cancel := startSessionsServer(t, &fakeSessionSource{snap: session.Snapshot{Status: status}})
			defer cancel()

			code, body := getSessions(t, client)
			require.Equal(t, http.StatusOK, code)
			assert.Equal(t, status, body["status"])
			sessions, ok := body["sessions"].([]any)
			require.True(t, ok, "sessions must be [] (present and non-null) when degraded")
			assert.Empty(t, sessions)
		})
	}
}

// TestSessions_RegistryDisabled: with no SetSessionRegistry call, /sessions
// reports "registry: disabled" with an empty sessions list — still 200.
func TestSessions_RegistryDisabled(t *testing.T) {
	_, client, cancel := startSessionsServer(t, nil)
	defer cancel()

	code, body := getSessions(t, client)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "registry: disabled", body["status"])
	assert.Equal(t, float64(0), body["epoch"])
	sessions, ok := body["sessions"].([]any)
	require.True(t, ok, "sessions must be [] (present and non-null) when disabled")
	assert.Empty(t, sessions)
}

// TestSessions_MethodGuard: non-GET methods are rejected with 405.
func TestSessions_MethodGuard(t *testing.T) {
	_, client, cancel := startSessionsServer(t, nil)
	defer cancel()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://unix/sessions", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}
