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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Dry-run: no write calls, returns nil ─────────────────────────────────────

func TestServerNetBirdInitDryRun(t *testing.T) {
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"

	runner := shell.NewMockRunner() // no calls expected
	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})
	_ = p
	cc := &cmdContext{cfg: cfg, runner: runner, dryRun: true, apply: false}

	err := netbirdInitRunE(context.Background(), cfg, cc, runner, "")
	require.NoError(t, err)
}

// ── Linux path: missing --binary-path → error with acquisition message ────────

func TestServerNetBirdInitLinuxMissingBinaryPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"

	runner := shell.NewMockRunner()
	cc := &cmdContext{cfg: cfg, runner: runner, dryRun: false, apply: true}

	err := netbirdInitRunE(context.Background(), cfg, cc, runner, "")
	require.Error(t, err)
	errMsg := err.Error()
	assert.Contains(t, errMsg, "--binary-path required on Linux")
	// Verify acquisition routes are mentioned.
	assert.Contains(t, errMsg, "github.com/netbirdio/netbird")
}

// ── Linux path: binary version below floor → error mentioning v0.57.0 ────────

func TestServerNetBirdInitLinuxVersionBelowFloor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"

	// Mock: --version returns an old version below floor.
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "netbird-server version v0.30.0\n", ExitCode: 0}},
	)
	cc := &cmdContext{cfg: cfg, runner: runner, dryRun: false, apply: true}

	err := netbirdInitRunE(context.Background(), cfg, cc, runner, "/path/to/old-netbird-server")
	require.Error(t, err)
	errMsg := err.Error()
	assert.Contains(t, errMsg, "below minimum floor")
	assert.Contains(t, errMsg, "v0.57.0")
	assert.Contains(t, errMsg, "CVE-2025-10678")
}

// ── ZITADEL probe: returns 200 with admin user → error mentioning CVE ────────

func TestServerNetBirdInitZitadelProbe200Fail(t *testing.T) {
	// Mock ZITADEL probe: returns HTTP 200 with admin user results.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		result := map[string]any{
			"result": []any{map[string]any{"userName": "zitadel-admin@example.com"}},
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer srv.Close()

	// Write a config.yaml with a ZITADEL issuer (must contain "zitadel" to trigger probe).
	// We use a URL that contains "zitadel" but redirects probes to the mock server.
	// Since we can't create a URL with "zitadel" in it for the local mock, we test the
	// probe function directly with a fake issuer base pointing to the mock server.
	tmpCfgDir := t.TempDir()
	cfgPath := tmpCfgDir + "/config.yaml"
	// The issuer must contain "zitadel" for the probe to fire.
	// We use a synthetic issuer that contains "zitadel" but maps to our test server URL.
	cfgContent := "server:\n  auth:\n    issuer: https://zitadel.example.com\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	// Test the probe function directly with the mock server URL as the issuer base.
	// This verifies the HTTP 200 → FAIL path without DNS.
	err := runNetBirdZitadelProbe(context.Background(), srv.URL, p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CVE-2025-10678")
	assert.Contains(t, err.Error(), "provisioning refused")
}

// ── ZITADEL probe: returns 401 → init continues past probe (no error) ─────────

func TestServerNetBirdInitZitadelProbe401Pass(t *testing.T) {
	// Mock ZITADEL probe: returns HTTP 401 (default creds rejected = PASS).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	// Test the probe function directly with the mock server URL as the issuer base.
	// HTTP 401 = PASS (default admin credential is not active).
	err := runNetBirdZitadelProbe(context.Background(), srv.URL, p)
	require.NoError(t, err)
}

// ── Linux path: no ZITADEL (Dex) → SKIP, no error ──────────────────────────

func TestServerNetBirdInitZitadelDexSkip(t *testing.T) {
	tmpCfgDir := t.TempDir()
	cfgPath := tmpCfgDir + "/config.yaml"
	// Dex default: no "zitadel" in auth.issuer.
	cfgContent := "server:\n  auth:\n    issuer: https://dex.example.com\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))

	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	// Should return nil (SKIP path — Dex is not ZITADEL).
	err := netbirdZitadelInitProbe(context.Background(), cfgPath, p)
	require.NoError(t, err)
}

// ── Status: SSHCheck WARN appears in output ───────────────────────────────────

func TestServerNetBirdStatusSSHCheckWarn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"

	var runner *shell.MockRunner
	if runtime.GOOS == "linux" {
		runner = shell.NewMockRunner(
			// version check
			shell.Call{Result: shell.Result{Stdout: "v0.71.4\n", ExitCode: 0}},
			// systemctl is-active
			shell.Call{Result: shell.Result{Stdout: "active\n", ExitCode: 0}},
		)
	} else {
		runner = shell.NewMockRunner(
			// docker ps
			shell.Call{Result: shell.Result{Stdout: "", ExitCode: 0}},
		)
	}

	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})
	cc := &cmdContext{cfg: cfg, runner: runner, dryRun: false, apply: false}

	err := netbirdStatusRunE(context.Background(), cc, p)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "SSHCheck not available on NetBird")
}

// ── DOS-01: ZITADEL probe oversized body is rejected ─────────────────────────

// TestServerNetbird_BoundedRead verifies that an HTTP response body larger than
// MaxBackendBody returns an error containing "exceeded" and does NOT return nil.
// This is the D-05 bounded-read regression test (DOS-01 / T-25-03-01).
func TestServerNetbird_BoundedRead(t *testing.T) {
	// Serve a body exactly (MaxBackendBody+1) bytes — one byte past the ceiling.
	// limitio.MaxBackendBody = 8 MiB. We use a streaming handler to avoid
	// allocating 8 MiB in the test process; bytes.Repeat is fine at 1 byte.
	const oneMiB = 1 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write MaxBackendBody+1 bytes: 8*1024*1024+1.
		chunk := make([]byte, oneMiB)
		for i := 0; i < 8; i++ {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte{0x00}) // the one extra byte that triggers overflow
	}))
	defer srv.Close()

	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	err := runNetBirdZitadelProbe(context.Background(), srv.URL, p)
	require.Error(t, err, "oversized response body must return an error")
	assert.Contains(t, err.Error(), "exceeded", "error must mention 'exceeded' for bounded-read violation")
}
