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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// doctorCfg builds a minimal config.Config suitable for doctor check tests.
func doctorCfg(serverURL, cfgPath, dbPath string) *config.Config {
	cfg := config.Defaults()
	cfg.Backend.Type = "headscale"
	cfg.Server.Headscale.ServerURL = serverURL
	cfg.Server.Headscale.ConfigPath = cfgPath
	cfg.Server.Headscale.DBPath = dbPath
	cfg.Server.Headscale.CertExpiryWarnDays = 30
	return cfg
}

// writeHsConfig writes a minimal headscale YAML config to path with optional overrides.
func writeHsConfig(t *testing.T, path string, m map[string]any) {
	t.Helper()
	base := map[string]any{
		"server_url":          "https://headscale.example.com",
		"grpc_allow_insecure": false,
		"metrics_listen_addr": "127.0.0.1:9090",
		"derp": map[string]any{
			"server": map[string]any{
				"enabled":        true,
				"verify_clients": true,
			},
		},
		"policy":   map[string]any{"mode": "database"},
		"logtail":  map[string]any{"enabled": false},
		"database": map[string]any{"type": "sqlite", "sqlite": map[string]any{"path": "/var/lib/headscale/db.sqlite"}},
	}
	for k, v := range m {
		base[k] = v
	}
	data, err := yaml.Marshal(base)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

// mockDoRequest is a test double for the doRequest func parameter.
// It returns the given responses in sequence (or the last one repeatedly).
type doRequestFixture struct {
	responses []mockResponse
	idx       int
}

type mockResponse struct {
	statusCode int
	body       any // will be JSON-marshalled
}

func (f *doRequestFixture) doRequest(_ context.Context, _, path string, _ any) (*http.Response, error) {
	i := f.idx
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.idx++

	resp := f.responses[i]
	body, _ := json.Marshal(resp.body)
	rec := httptest.NewRecorder()
	rec.WriteHeader(resp.statusCode)
	_, _ = rec.Write(body)
	return rec.Result(), nil
}

// preAuthKeyFixture reads the testdata preauthkeys file and returns the body map.
func preAuthKeyFixture(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("testdata/headscale_preauthkeys.json")
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	return m
}

// findingByCheck finds the first Finding with the given check name.
func findingByCheck(findings []modules.Finding, check string) (modules.Finding, bool) {
	for _, f := range findings {
		if f.Check == check {
			return f, true
		}
	}
	return modules.Finding{}, false
}

// allCheckNames collects all unique check names from a slice of findings.
func allCheckNames(findings []modules.Finding) []string {
	seen := make(map[string]bool)
	var names []string
	for _, f := range findings {
		if !seen[f.Check] {
			seen[f.Check] = true
			names = append(names, f.Check)
		}
	}
	return names
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestHsDoctorChecks_AllNinePresent asserts that HeadscaleDoctorChecks returns
// findings for all nine hs-* check names when given a minimal config.
func TestHsDoctorChecks_AllNinePresent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")

	// Write a db file with tight perms.
	require.NoError(t, os.WriteFile(dbPath, []byte("dummy"), 0o600))

	writeHsConfig(t, cfgPath, nil)

	cfg := doctorCfg("https://headscale.example.com", cfgPath, dbPath)

	// Mock REST: apikey returns 200, preauthkey returns 200 with valid keys.
	fixture := &doRequestFixture{
		responses: []mockResponse{
			{statusCode: 200, body: map[string]any{"apiKeys": []any{}}},
			{statusCode: 200, body: preAuthKeyFixture(t)},
		},
	}

	runner := shell.NewMockRunner(
		shell.Call{Args: []string{"systemctl", "show", "headscale", "--property=User"}, Result: shell.Result{Stdout: "User=headscale\n", ExitCode: 0}},
		shell.Call{Args: []string{"launchctl", "list", "net.abysslink.headscale"}, Result: shell.Result{Stdout: "123 0 net.abysslink.headscale\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "headscale\n", ExitCode: 0}},
	)

	findings, err := backend.HeadscaleDoctorChecks(context.Background(), cfg, runner, fixture.doRequest)
	require.NoError(t, err)

	names := allCheckNames(findings)
	expected := []string{"hs-lock", "hs-bind", "hs-oidc-filter", "hs-derp-failclosed", "hs-db-perms", "hs-tls", "hs-proc-user", "hs-api-auth", "hs-key-expiry"}
	for _, want := range expected {
		assert.Contains(t, names, want, "expected check %q in findings", want)
	}
	assert.Len(t, names, len(expected), "expected exactly %d unique check names", len(expected))
}

// TestHsLockPermanentWarn asserts that hs-lock is always SeverityWarning with
// the exact ROADMAP text and is NEVER absent, never empty, never Pass.
func TestHsLockPermanentWarn(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")
	require.NoError(t, os.WriteFile(dbPath, []byte("x"), 0o600))
	writeHsConfig(t, cfgPath, nil)

	cfg := doctorCfg("https://headscale.example.com", cfgPath, dbPath)
	fixture := &doRequestFixture{
		responses: []mockResponse{
			{statusCode: 200, body: map[string]any{"apiKeys": []any{}}},
			{statusCode: 200, body: map[string]any{"preAuthKeys": []any{}}},
		},
	}
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "User=headscale\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "headscale\n", ExitCode: 0}},
	)

	findings, err := backend.HeadscaleDoctorChecks(context.Background(), cfg, runner, fixture.doRequest)
	require.NoError(t, err)

	f, found := findingByCheck(findings, "hs-lock")
	require.True(t, found, "hs-lock must always be present in findings")
	assert.Equal(t, modules.SeverityWarning, f.Severity, "hs-lock must always be SeverityWarning")
	assert.NotEmpty(t, f.Message, "hs-lock message must not be empty")
	assert.Contains(t, f.Message, "server-trust model only",
		"hs-lock must contain exact ROADMAP text 'server-trust model only'")
	assert.Contains(t, f.Message, "Tailnet Lock (TKA) is not available on Headscale",
		"hs-lock must contain exact ROADMAP text")
}

// TestHsKeyExpiry_ZeroExpiry asserts that a pre-auth key with zero expiry
// ("0001-01-01T00:00:00Z") triggers SeverityFatal for hs-key-expiry.
func TestHsKeyExpiry_ZeroExpiry(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")
	require.NoError(t, os.WriteFile(dbPath, []byte("x"), 0o600))
	writeHsConfig(t, cfgPath, nil)

	cfg := doctorCfg("https://headscale.example.com", cfgPath, dbPath)

	// preAuthKeys fixture has one zero-expiry key (id=2, "0001-01-01T00:00:00Z").
	fixture := &doRequestFixture{
		responses: []mockResponse{
			{statusCode: 200, body: map[string]any{"apiKeys": []any{}}},
			{statusCode: 200, body: preAuthKeyFixture(t)},
		},
	}
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "User=headscale\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "headscale\n", ExitCode: 0}},
	)

	findings, err := backend.HeadscaleDoctorChecks(context.Background(), cfg, runner, fixture.doRequest)
	require.NoError(t, err)

	f, found := findingByCheck(findings, "hs-key-expiry")
	require.True(t, found, "hs-key-expiry must be present in findings")
	assert.Equal(t, modules.SeverityFatal, f.Severity,
		"hs-key-expiry must be SeverityFatal for zero-expiry key (issue #1579)")
}

// TestHsDerpFailclosed_OpenRelay asserts SeverityFatal when
// derp.server.enabled=true but verify_clients=false.
func TestHsDerpFailclosed_OpenRelay(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")
	require.NoError(t, os.WriteFile(dbPath, []byte("x"), 0o600))

	// Config with derp enabled but verify_clients=false — open relay.
	writeHsConfig(t, cfgPath, map[string]any{
		"derp": map[string]any{
			"server": map[string]any{
				"enabled":        true,
				"verify_clients": false,
			},
		},
	})

	cfg := doctorCfg("https://headscale.example.com", cfgPath, dbPath)
	fixture := &doRequestFixture{
		responses: []mockResponse{
			{statusCode: 200, body: map[string]any{"apiKeys": []any{}}},
			{statusCode: 200, body: map[string]any{"preAuthKeys": []any{}}},
		},
	}
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "User=headscale\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "headscale\n", ExitCode: 0}},
	)

	findings, err := backend.HeadscaleDoctorChecks(context.Background(), cfg, runner, fixture.doRequest)
	require.NoError(t, err)

	f, found := findingByCheck(findings, "hs-derp-failclosed")
	require.True(t, found)
	assert.Equal(t, modules.SeverityFatal, f.Severity,
		"embedded DERP with verify_clients=false is an open relay (SeverityFatal)")
}

// TestHsOidcFilter_SkipWhenAbsent asserts no FAIL finding for hs-oidc-filter
// when no oidc section is configured.
func TestHsOidcFilter_SkipWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")
	require.NoError(t, os.WriteFile(dbPath, []byte("x"), 0o600))
	writeHsConfig(t, cfgPath, nil) // no oidc key

	cfg := doctorCfg("https://headscale.example.com", cfgPath, dbPath)
	fixture := &doRequestFixture{
		responses: []mockResponse{
			{statusCode: 200, body: map[string]any{"apiKeys": []any{}}},
			{statusCode: 200, body: map[string]any{"preAuthKeys": []any{}}},
		},
	}
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "User=headscale\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "headscale\n", ExitCode: 0}},
	)

	findings, err := backend.HeadscaleDoctorChecks(context.Background(), cfg, runner, fixture.doRequest)
	require.NoError(t, err)

	f, found := findingByCheck(findings, "hs-oidc-filter")
	if found {
		// If present, must not be FAIL (should be PASS or absent)
		assert.NotEqual(t, modules.SeverityFatal, f.Severity,
			"hs-oidc-filter must not FAIL when OIDC is not configured")
	}
}

// TestHsOidcFilter_FailWhenOpen asserts SeverityFatal when oidc.issuer is set
// but all filter lists are empty (D-12).
func TestHsOidcFilter_FailWhenOpen(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")
	require.NoError(t, os.WriteFile(dbPath, []byte("x"), 0o600))

	// OIDC issuer set, all filter lists empty — open registration.
	writeHsConfig(t, cfgPath, map[string]any{
		"oidc": map[string]any{
			"issuer":          "https://idp.example.com",
			"allowed_domains": []string{},
			"allowed_users":   []string{},
			"allowed_groups":  []string{},
		},
	})

	cfg := doctorCfg("https://headscale.example.com", cfgPath, dbPath)
	fixture := &doRequestFixture{
		responses: []mockResponse{
			{statusCode: 200, body: map[string]any{"apiKeys": []any{}}},
			{statusCode: 200, body: map[string]any{"preAuthKeys": []any{}}},
		},
	}
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "User=headscale\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "headscale\n", ExitCode: 0}},
	)

	findings, err := backend.HeadscaleDoctorChecks(context.Background(), cfg, runner, fixture.doRequest)
	require.NoError(t, err)

	f, found := findingByCheck(findings, "hs-oidc-filter")
	require.True(t, found, "hs-oidc-filter must be present when OIDC is configured")
	assert.Equal(t, modules.SeverityFatal, f.Severity,
		"hs-oidc-filter must FAIL when issuer set with all filter lists empty (D-12)")
}

// TestValidateHeadscaleTLS_MissingCert asserts that ValidateHeadscaleTLS returns
// a non-nil error when the BYO cert file does not exist.
func TestValidateHeadscaleTLS_MissingCert(t *testing.T) {
	cfg := config.Defaults()
	cfg.Server.Headscale.ACME = false
	cfg.Server.Headscale.TLSCertPath = "/nonexistent/path/tls.crt"
	cfg.Server.Headscale.TLSKeyPath = "/nonexistent/path/tls.key"
	cfg.Server.Headscale.CertExpiryWarnDays = 30
	cfg.Server.Headscale.ServerURL = "https://headscale.example.com"

	err := backend.ValidateHeadscaleTLS(context.Background(), cfg)
	assert.Error(t, err, "ValidateHeadscaleTLS must return error for missing BYO cert")
}

// TestValidateHeadscaleTLS_ACMEMissingHostname asserts that ValidateHeadscaleTLS
// returns an error when ACME mode is enabled but ServerURL is empty (cannot
// derive ACME hostname).
func TestValidateHeadscaleTLS_ACMEMissingHostname(t *testing.T) {
	cfg := config.Defaults()
	cfg.Server.Headscale.ACME = true
	cfg.Server.Headscale.ServerURL = "" // empty — cannot derive ACME hostname

	err := backend.ValidateHeadscaleTLS(context.Background(), cfg)
	assert.Error(t, err, "ValidateHeadscaleTLS must return error when ACME hostname cannot be derived")
	assert.True(t, strings.Contains(err.Error(), "hostname") || strings.Contains(err.Error(), "server_url"),
		"error must mention hostname or server_url, got: %v", err)
}

// TestHsBindFail_MetricsExposed asserts SeverityFatal when metrics_listen_addr
// is 0.0.0.0 (exposes metrics endpoint publicly).
func TestHsBindFail_MetricsExposed(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")
	require.NoError(t, os.WriteFile(dbPath, []byte("x"), 0o600))

	writeHsConfig(t, cfgPath, map[string]any{
		"metrics_listen_addr": "0.0.0.0:9090",
	})

	cfg := doctorCfg("https://headscale.example.com", cfgPath, dbPath)
	fixture := &doRequestFixture{
		responses: []mockResponse{
			{statusCode: 200, body: map[string]any{"apiKeys": []any{}}},
			{statusCode: 200, body: map[string]any{"preAuthKeys": []any{}}},
		},
	}
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "User=headscale\n", ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "headscale\n", ExitCode: 0}},
	)

	findings, err := backend.HeadscaleDoctorChecks(context.Background(), cfg, runner, fixture.doRequest)
	require.NoError(t, err)

	f, found := findingByCheck(findings, "hs-bind")
	require.True(t, found)
	assert.Equal(t, modules.SeverityFatal, f.Severity,
		"metrics_listen_addr=0.0.0.0 exposes metrics publicly (SeverityFatal)")
}
