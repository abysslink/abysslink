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

package backend_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// nbDoctorCfg builds a minimal config.Config for NetBird doctor check tests.
func nbDoctorCfg(serverURL, cfgPath string) *config.Config {
	cfg := config.Defaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = serverURL
	cfg.Server.NetBird.ConfigPath = cfgPath
	return cfg
}

// writeNbConfig writes a NetBird YAML config to path with optional overrides.
// base is the config_minimal.yaml structure (Dex IdP, no ZITADEL).
func writeNbConfig(t *testing.T, path string, m map[string]any) {
	t.Helper()
	base := map[string]any{
		"disableAnonymousMetrics": true,
		"disableGeoliteUpdate":    true,
		"metricsPort":             9090,
		"server": map[string]any{
			"listenAddress": "127.0.0.1:443",
			"auth": map[string]any{
				"issuer": "http://localhost:5556/dex",
			},
		},
	}
	for k, v := range m {
		base[k] = v
	}
	data, err := yaml.Marshal(base)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

// ── TestNbSSSHCheckAlwaysFirst ─────────────────────────────────────────────────

// TestNetBirdDoctorChecks_NbSSHCheckIsFirst asserts that nb-sshcheck is always
// the first (index 0) finding in the returned slice, regardless of config state.
func TestNetBirdDoctorChecks_NbSSHCheckIsFirst(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)

	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), nil)

	require.NotEmpty(t, findings)
	assert.Equal(t, "nb-sshcheck", findings[0].Check, "first finding must be nb-sshcheck")
	assert.Equal(t, backend.DoctorWarning, findings[0].Severity, "nb-sshcheck must be WARN")
	assert.Contains(t, findings[0].Message, "WARN: SSHCheck not available on NetBird — checkPeriod enforcement disabled",
		"nb-sshcheck message must contain verbatim required string")
}

// TestNetBirdDoctorChecks_Returns9Findings asserts exactly 9 findings are returned.
func TestNetBirdDoctorChecks_Returns9Findings(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)

	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)

	// Provide enough runner calls for nb-version and nb-proc-user + nb-runtime (macOS).
	var mockCalls []shell.Call
	if runtime.GOOS == "darwin" {
		// nb-version: binary is empty on darwin — no runner call expected
		// nb-proc-user: darwin skips
		// nb-runtime: 3 probes (docker, colima, podman)
		mockCalls = []shell.Call{
			{Result: shell.Result{ExitCode: 1}}, // docker info fails
			{Result: shell.Result{ExitCode: 1}}, // colima status fails
			{Result: shell.Result{ExitCode: 1}}, // podman info fails
		}
	} else {
		// nb-version: binary path empty on linux → uses "netbird-server"
		mockCalls = []shell.Call{
			{Result: shell.Result{Stdout: "netbird-server version v0.71.4\n", ExitCode: 0}},
			// nb-proc-user: linux systemctl
			{Result: shell.Result{Stdout: "User=netbird-server\n", ExitCode: 0}},
		}
	}
	runner := shell.NewMockRunner(mockCalls...)

	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)
	assert.Len(t, findings, 10, "NetBirdDoctorChecks must return exactly 10 findings (nb-lock added DOC-03)")
}

// ── nb-zitadel tests ──────────────────────────────────────────────────────────

// TestNbZitadel_SkipOnDexConfig verifies that with a Dex (non-ZITADEL) issuer,
// nb-zitadel returns DoctorOK with "SKIP" message.
func TestNbZitadel_SkipOnDexConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// Use config_minimal fixture path as template (Dex issuer).
	writeNbConfig(t, cfgPath, nil) // issuer is "http://localhost:5556/dex"

	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	mock := &doRequestFixture{responses: []mockResponse{
		{statusCode: http.StatusOK, body: nil},
	}}

	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), mock.doRequest)
	// Find nb-zitadel
	var zitadelFinding *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-zitadel" {
			zitadelFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, zitadelFinding, "nb-zitadel finding must be present")
	assert.Equal(t, backend.DoctorOK, zitadelFinding.Severity, "nb-zitadel must SKIP on non-ZITADEL config")
	assert.Contains(t, zitadelFinding.Message, "SKIP")
}

// TestNbZitadel_PassOnRejectedCreds verifies that when ZITADEL is detected but
// the probe returns 401, nb-zitadel returns DoctorOK (default creds rejected).
func TestNbZitadel_PassOnRejectedCreds(t *testing.T) {
	// Start a test server that returns 401 for the ZITADEL probe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// Write a ZITADEL config pointing at our test server.
	writeNbConfig(t, cfgPath, map[string]any{
		"server": map[string]any{
			"listenAddress": "127.0.0.1:443",
			"auth": map[string]any{
				"issuer": srv.URL + "/zitadel",
			},
		},
	})

	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), nil)

	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-zitadel" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorOK, found.Severity, "ZITADEL 401 response means creds are rejected = PASS")
}

// TestNbZitadel_FailOnActiveDefaultAdmin verifies that when ZITADEL probe returns
// 200 with results, nb-zitadel returns DoctorFatal (CVE-2025-10678).
func TestNbZitadel_FailOnActiveDefaultAdmin(t *testing.T) {
	// Start a test server that returns 200 with a user result.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"result": []map[string]any{
				{"userName": "zitadel-admin@instance.zitadel.example.com"},
			},
		}
		data, _ := json.Marshal(resp)
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, map[string]any{
		"server": map[string]any{
			"listenAddress": "127.0.0.1:443",
			"auth": map[string]any{
				"issuer": srv.URL + "/zitadel",
			},
		},
	})

	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), nil)

	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-zitadel" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorFatal, found.Severity, "ZITADEL 200 with results = FAIL (CVE-2025-10678)")
	assert.Contains(t, found.Message, "CVE-2025-10678")
}

// ── nb-key-type tests ─────────────────────────────────────────────────────────

// nbSetupKeyResponse builds a setup key list response for tests.
func nbSetupKeyResponse(keys []map[string]any) any {
	return keys
}

// TestNbKeyType_PassAllOneOff verifies PASS when all keys are one-off + valid expiry.
func TestNbKeyType_PassAllOneOff(t *testing.T) {
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	body := nbSetupKeyResponse([]map[string]any{
		{"id": "k1", "name": "key-1", "type": "one-off", "expires": future, "revoked": false},
	})
	mock := &doRequestFixture{responses: []mockResponse{
		{statusCode: http.StatusOK, body: body},
	}}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)

	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), mock.doRequest)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-key-type" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorOK, found.Severity)
}

// TestNbKeyType_FailReusableKey verifies FAIL when a key has type "reusable".
func TestNbKeyType_FailReusableKey(t *testing.T) {
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	body := nbSetupKeyResponse([]map[string]any{
		{"id": "k1", "name": "reusable-key", "type": "reusable", "expires": future, "revoked": false},
	})
	mock := &doRequestFixture{responses: []mockResponse{
		{statusCode: http.StatusOK, body: body},
	}}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)

	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), mock.doRequest)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-key-type" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorFatal, found.Severity, "reusable key must FAIL")
}

// TestNbKeyType_FailZeroExpires verifies FAIL when a key has zero expires.
func TestNbKeyType_FailZeroExpires(t *testing.T) {
	body := nbSetupKeyResponse([]map[string]any{
		// zero-time expiry (Go will parse this as zero time)
		{"id": "k1", "name": "no-expiry-key", "type": "one-off", "expires": "0001-01-01T00:00:00Z", "revoked": false},
	})
	mock := &doRequestFixture{responses: []mockResponse{
		{statusCode: http.StatusOK, body: body},
	}}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)

	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), mock.doRequest)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-key-type" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorFatal, found.Severity, "zero expires must FAIL")
}

// ── nb-api-auth tests ─────────────────────────────────────────────────────────

// TestNbAPIAuth_Pass verifies PASS when GET /api/groups returns 200.
func TestNbAPIAuth_Pass(t *testing.T) {
	mock := &doRequestFixture{responses: []mockResponse{
		{statusCode: http.StatusOK, body: []any{}},
	}}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)

	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), mock.doRequest)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-api-auth" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorOK, found.Severity)
}

// TestNbAPIAuth_Fail verifies FAIL when GET /api/groups returns 401.
func TestNbAPIAuth_Fail(t *testing.T) {
	mock := &doRequestFixture{responses: []mockResponse{
		{statusCode: http.StatusUnauthorized, body: nil},
	}}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)

	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, shell.NewMockRunner(), mock.doRequest)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-api-auth" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorFatal, found.Severity)
}

// ── nb-version tests ─────────────────────────────────────────────────────────

// TestNbVersion_Pass verifies PASS when binary reports v0.71.4 (above floor).
func TestNbVersion_Pass(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("nb-version uses container path on darwin — binary not checked")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	cfg.Server.NetBird.BinaryPath = "/usr/local/bin/netbird-server"

	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "netbird-server version v0.71.4\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "User=netbird-server\n", ExitCode: 0}},
	)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-version" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorOK, found.Severity)
}

// TestNbVersion_Fail verifies FAIL when binary reports v0.30.0 (below floor v0.57.0).
func TestNbVersion_Fail(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("nb-version uses container path on darwin — binary not checked")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	cfg.Server.NetBird.BinaryPath = "/usr/local/bin/netbird-server"

	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "netbird-server version v0.30.0\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "User=netbird-server\n", ExitCode: 0}},
	)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-version" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorFatal, found.Severity, "v0.30.0 is below floor v0.57.0")
}

// ── nb-proc-user tests ────────────────────────────────────────────────────────

// TestNbProcUser_LinuxPass verifies PASS when systemctl returns "User=netbird-server".
func TestNbProcUser_LinuxPass(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nb-proc-user linux path only runs on linux")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	cfg.Server.NetBird.BinaryPath = "/usr/local/bin/netbird-server"

	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "netbird-server version v0.71.4\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "User=netbird-server\n", ExitCode: 0}},
	)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-proc-user" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorOK, found.Severity)
}

// TestNbProcUser_LinuxFail verifies FAIL when systemctl returns "User=root".
func TestNbProcUser_LinuxFail(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nb-proc-user linux path only runs on linux")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	cfg.Server.NetBird.BinaryPath = "/usr/local/bin/netbird-server"

	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "netbird-server version v0.71.4\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "User=root\n", ExitCode: 0}},
	)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)
	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-proc-user" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorFatal, found.Severity, "User=root must FAIL")
}

// ── TestNbRuntime tests ───────────────────────────────────────────────────────

// TestNbRuntime_MacOSPass verifies PASS when docker info returns exit 0 (macOS).
func TestNbRuntime_MacOSPass(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("nb-runtime macOS path only runs on darwin")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	// BinaryPath is empty on macOS (container path).

	// nb-version: empty binary path on darwin → no runner call.
	// nb-proc-user: darwin → no runner call.
	// nb-runtime: docker succeeds.
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "Server: Docker Engine\n", ExitCode: 0}}, // docker info
	)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)

	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-runtime" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorOK, found.Severity, "docker info exit 0 = PASS")
	assert.Contains(t, found.Message, "docker")
}

// TestNbRuntime_MacOSFail verifies FAIL when all runtimes (docker/colima/podman)
// return non-zero on macOS.
func TestNbRuntime_MacOSFail(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("nb-runtime macOS path only runs on darwin")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)

	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 1}}, // docker info fails
		shell.Call{Result: shell.Result{ExitCode: 1}}, // colima status fails
		shell.Call{Result: shell.Result{ExitCode: 1}}, // podman info fails
	)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)

	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-runtime" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorFatal, found.Severity, "all runtimes absent = FAIL")
}

// ── nb-lock tests ─────────────────────────────────────────────────────────────

// TestNbDoctorChecks_NbLockAlwaysPresent asserts that NetBirdDoctorChecks always
// emits an unconditional nb-lock DoctorWarning (mirrors hs-lock for NetBird).
// The nb-lock finding must be present regardless of NetBird state and must
// contain the required advisory substring (D-07).
func TestNbDoctorChecks_NbLockAlwaysPresent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)

	// Use a minimal MockRunner that supplies no version/proc output.
	// On darwin BinaryPath is empty → nb-version/nb-proc-user use no runner call;
	// on linux provide stubs so those checks don't consume the queue.
	var runner shell.Runner
	if runtime.GOOS == "darwin" {
		runner = shell.NewMockRunner()
	} else {
		cfg.Server.NetBird.BinaryPath = "/usr/local/bin/netbird-server"
		runner = shell.NewMockRunner(
			shell.Call{Result: shell.Result{Stdout: "netbird-server version v0.71.4\n", ExitCode: 0}},
			shell.Call{Result: shell.Result{Stdout: "User=netbird-server\n", ExitCode: 0}},
		)
	}

	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)

	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-lock" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "nb-lock finding must be present unconditionally")
	assert.Equal(t, backend.DoctorWarning, found.Severity, "nb-lock must be DoctorWarning")
	assert.Contains(t, found.Message, "No Tailnet Lock on NetBird — permanent advisory",
		"nb-lock message must contain the D-07 required substring")
}

// TestNbRuntime_LinuxSkip verifies that on Linux, nb-runtime returns DoctorOK
// with a "SKIP" message (native binary path, no container runtime needed).
func TestNbRuntime_LinuxSkip(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nb-runtime Linux SKIP path only runs on linux")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	writeNbConfig(t, cfgPath, nil)
	cfg := nbDoctorCfg("https://nb.example.com", cfgPath)
	cfg.Server.NetBird.BinaryPath = "/usr/local/bin/netbird-server"

	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "netbird-server version v0.71.4\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "User=netbird-server\n", ExitCode: 0}},
	)
	findings := backend.NetBirdDoctorChecks(context.Background(), cfg, runner, nil)

	var found *backend.DoctorFinding
	for i := range findings {
		if findings[i].Check == "nb-runtime" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, backend.DoctorOK, found.Severity, "Linux nb-runtime must be DoctorOK (SKIP)")
	assert.Contains(t, found.Message, "SKIP")
}
