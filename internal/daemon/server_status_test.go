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
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
)

// stubNotifier is a no-op Notifier for the status server tests.
type stubNotifier struct{}

func (stubNotifier) Send(_ context.Context, _, _ string) error { return nil }

// startStatusServer spins up a daemon Server on a temp socket and returns an
// HTTP client wired to that socket plus a cancel func. Optional configure
// funcs run against the Server before it starts (e.g. SetExecCounter).
// The socket dir comes from shortRuntimeDir (daemon_test.go): macOS limits Unix
// socket paths to ~104 bytes and t.TempDir() under /var/folders exceeds it.
func startStatusServer(t *testing.T, cfg *config.Config, configure ...func(*daemon.Server)) (*http.Client, context.CancelFunc) {
	t.Helper()
	dir := shortRuntimeDir(t)
	sock := filepath.Join(dir, "abysslinkd.sock")
	t.Setenv("XDG_RUNTIME_DIR", dir)
	// Ensure the socket path resolves under our temp dir.
	_ = os.Remove(sock)

	srv := daemon.NewServer(stubNotifier{}, nil, cfg)
	for _, fn := range configure {
		fn(srv)
	}
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

	// Wait until the socket is up.
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

func statusCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Tailnet.Hostname = "my-secret-host"
	cfg.Tailnet.Lock.Enabled = true
	cfg.Backend.Type = "tailscale"
	return cfg
}

func doStatus(t *testing.T, client *http.Client, method string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "http://unix/status", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func TestDaemonStatus_Method(t *testing.T) {
	client, cancel := startStatusServer(t, statusCfg())
	defer cancel()

	resp := doStatus(t, client, http.MethodGet)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doStatus(t, client, http.MethodPost)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestDaemonStatus_Schema(t *testing.T) {
	client, cancel := startStatusServer(t, statusCfg())
	defer cancel()

	resp := doStatus(t, client, http.MethodGet)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var out struct {
		Version    string `json:"version"`
		Backend    string `json:"backend"`
		RigID      string `json:"rig_id"`
		Reachable  bool   `json:"reachable"`
		LockStatus string `json:"lock_status"`
		Doctor     struct {
			Fatal int `json:"fatal"`
			Warn  int `json:"warn"`
			Pass  int `json:"pass"`
		} `json:"doctor"`
		Uptime string `json:"uptime"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.NotEmpty(t, out.Version)
	assert.Equal(t, "tailscale", out.Backend)
	assert.Equal(t, "locked", out.LockStatus)
	assert.NotEmpty(t, out.Uptime)
}

func TestDaemonStatus_RigIDOpaque(t *testing.T) {
	client, cancel := startStatusServer(t, statusCfg())
	defer cancel()

	resp := doStatus(t, client, http.MethodGet)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var out struct {
		RigID string `json:"rig_id"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.NotEmpty(t, out.RigID)
	assert.NotContains(t, out.RigID, "my-secret-host", "rig_id must be opaque, not the raw hostname")
	assert.False(t, strings.Contains(string(body), "my-secret-host"), "no raw hostname anywhere in /status")
}

// TestDaemonStatus_PostureCompleteStub is the WR-05 regression: /status must
// expose posture_complete=false this phase so consumers do not read the
// hardcoded reachable=true and zeroed doctor counts as an authoritative
// all-clear on a security-posture endpoint.
func TestDaemonStatus_PostureCompleteStub(t *testing.T) {
	client, cancel := startStatusServer(t, statusCfg())
	defer cancel()

	resp := doStatus(t, client, http.MethodGet)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), `"posture_complete"`, "posture_complete must be present")

	var out struct {
		PostureComplete bool `json:"posture_complete"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.False(t, out.PostureComplete, "posture_complete must be false while doctor wiring is a stub (WR-05)")
}

// TestDaemonStatus_GateExecCounter: /status exposes the gate decorator's live
// exec counter via SetExecCounter — the proof that the observe-only seam
// intercepts every module/consumer exec before Phase 30 makes it load-bearing.
func TestDaemonStatus_GateExecCounter(t *testing.T) {
	client, cancel := startStatusServer(t, statusCfg(), func(srv *daemon.Server) {
		srv.SetExecCounter(func() uint64 { return 7 })
	})
	defer cancel()

	resp := doStatus(t, client, http.MethodGet)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), `"gate_execs_observed"`, "counter field must be present")

	var out struct {
		GateExecsObserved uint64 `json:"gate_execs_observed"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Equal(t, uint64(7), out.GateExecsObserved, "field must reflect the injected counter")
}

// TestDaemonStatus_GateExecCounterUnset: with no counter wired the field is
// present and zero — never an error, never omitted-vs-crash ambiguity.
func TestDaemonStatus_GateExecCounterUnset(t *testing.T) {
	client, cancel := startStatusServer(t, statusCfg())
	defer cancel()

	resp := doStatus(t, client, http.MethodGet)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), `"gate_execs_observed"`, "field must be present even when no gate is wired")

	var out struct {
		GateExecsObserved uint64 `json:"gate_execs_observed"`
	}
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Zero(t, out.GateExecsObserved, "nil-safe default is 0, not a crash")
}

func TestDaemonStatus_ContentType(t *testing.T) {
	client, cancel := startStatusServer(t, statusCfg())
	defer cancel()

	resp := doStatus(t, client, http.MethodGet)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}
