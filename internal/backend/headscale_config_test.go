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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
)

// makeHeadscaleConfig builds a config.HeadscaleServer pointing at the temp-dir paths.
func makeHeadscaleConfig(cfgPath, dbPath string) config.HeadscaleServer {
	return config.HeadscaleServer{
		ServerURL:          "https://headscale.example.com",
		ConfigPath:         cfgPath,
		DBPath:             dbPath,
		CertExpiryWarnDays: 30,
		PreAuthKeyExpiry:   "1h",
	}
}

// writeMinimalHeadscaleYAML writes a baseline headscale config.yaml to path.
func writeMinimalHeadscaleYAML(t *testing.T, path string, extra map[string]any) {
	t.Helper()
	base := map[string]any{
		"server_url":  "https://old.example.com",
		"listen_addr": ":443",
	}
	for k, v := range extra {
		base[k] = v
	}
	data, err := yaml.Marshal(base)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

// TestMergeHeadscaleConfig_SetsRequiredKeys verifies that all required
// hardened keys are set after a merge:
//   - grpc_allow_insecure: false
//   - metrics_listen_addr: 127.0.0.1:9090
//   - derp.server.verify_clients: true
//   - policy.mode: database
//   - logtail.enabled: false
//   - database.type: sqlite
//   - server_url: https://headscale.example.com
func TestMergeHeadscaleConfig_SetsRequiredKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")

	writeMinimalHeadscaleYAML(t, cfgPath, nil)

	hs := makeHeadscaleConfig(cfgPath, dbPath)
	err := backend.MergeHeadscaleConfig(context.Background(), cfgPath, hs, false)
	require.NoError(t, err)

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	// Top-level scalar keys
	assert.Equal(t, false, result["grpc_allow_insecure"], "grpc_allow_insecure must be false")
	assert.Equal(t, "127.0.0.1:9090", result["metrics_listen_addr"], "metrics_listen_addr must be loopback-only")
	assert.Equal(t, "https://headscale.example.com", result["server_url"], "server_url must match hs.ServerURL")

	// Nested logtail
	logtail, ok := result["logtail"].(map[string]any)
	require.True(t, ok, "logtail must be a map")
	assert.Equal(t, false, logtail["enabled"], "logtail.enabled must be false")

	// Nested policy
	policy, ok := result["policy"].(map[string]any)
	require.True(t, ok, "policy must be a map")
	assert.Equal(t, "database", policy["mode"], "policy.mode must be database")

	// Nested database
	database, ok := result["database"].(map[string]any)
	require.True(t, ok, "database must be a map")
	assert.Equal(t, "sqlite", database["type"], "database.type must be sqlite")
	sqlite, ok := database["sqlite"].(map[string]any)
	require.True(t, ok, "database.sqlite must be a map")
	assert.Equal(t, dbPath, sqlite["path"], "database.sqlite.path must match hs.DBPath")

	// Nested derp.server
	derp, ok := result["derp"].(map[string]any)
	require.True(t, ok, "derp must be a map")
	srv, ok := derp["server"].(map[string]any)
	require.True(t, ok, "derp.server must be a map")
	assert.Equal(t, true, srv["verify_clients"], "derp.server.verify_clients must be true")
	assert.Equal(t, true, srv["enabled"], "derp.server.enabled must be true")
}

// TestMergeHeadscaleConfig_NoVerifyClientURLFailOpen asserts that the string
// "verify_client_url_fail_open" NEVER appears in the output config — it is a
// derper-binary flag, not a Headscale config key (R-02, RESEARCH.md Pitfall 1).
func TestMergeHeadscaleConfig_NoVerifyClientURLFailOpen(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")

	writeMinimalHeadscaleYAML(t, cfgPath, nil)

	hs := makeHeadscaleConfig(cfgPath, dbPath)
	require.NoError(t, backend.MergeHeadscaleConfig(context.Background(), cfgPath, hs, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	assert.False(t, strings.Contains(string(data), "verify_client_url_fail_open"),
		"verify_client_url_fail_open must NEVER appear in headscale config.yaml output")
}

// TestMergeHeadscaleConfig_PreservesUserKeys asserts that keys outside the
// hardened set (e.g., oidc.issuer, dns.*, node_update_check_interval) are
// preserved unchanged after a merge.
func TestMergeHeadscaleConfig_PreservesUserKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")

	// Write a config with user-controlled keys that must survive the merge.
	writeMinimalHeadscaleYAML(t, cfgPath, map[string]any{
		"oidc": map[string]any{
			"issuer":       "https://idp.example.com",
			"client_id":    "my-client",
			"client_secret": "supersecret",
		},
		"node_update_check_interval": "24h",
		"dns": map[string]any{
			"nameservers": []string{"1.1.1.1", "8.8.8.8"},
		},
	})

	hs := makeHeadscaleConfig(cfgPath, dbPath)
	require.NoError(t, backend.MergeHeadscaleConfig(context.Background(), cfgPath, hs, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	// oidc.issuer must be preserved
	oidc, ok := result["oidc"].(map[string]any)
	require.True(t, ok, "oidc must be preserved")
	assert.Equal(t, "https://idp.example.com", oidc["issuer"], "oidc.issuer must be preserved")

	// node_update_check_interval must be preserved
	assert.Equal(t, "24h", result["node_update_check_interval"], "node_update_check_interval must be preserved")

	// dns must be preserved
	dns, ok := result["dns"].(map[string]any)
	require.True(t, ok, "dns must be preserved")
	nameservers, ok := dns["nameservers"].([]any)
	require.True(t, ok, "dns.nameservers must be preserved")
	assert.Len(t, nameservers, 2, "both nameservers must be preserved")
}

// TestMergeHeadscaleConfig_Idempotent asserts that re-running MergeHeadscaleConfig
// on an already-hardened config produces identical output bytes.
func TestMergeHeadscaleConfig_Idempotent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")

	writeMinimalHeadscaleYAML(t, cfgPath, nil)

	hs := makeHeadscaleConfig(cfgPath, dbPath)

	// First merge
	require.NoError(t, backend.MergeHeadscaleConfig(context.Background(), cfgPath, hs, false))
	data1, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	// Second merge — must produce same result
	require.NoError(t, backend.MergeHeadscaleConfig(context.Background(), cfgPath, hs, false))
	data2, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	assert.Equal(t, string(data1), string(data2), "MergeHeadscaleConfig must be idempotent")
}

// TestMergeHeadscaleConfig_DryRun asserts that in dryRun mode, no file changes
// are written (original file content is unchanged).
func TestMergeHeadscaleConfig_DryRun(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")

	writeMinimalHeadscaleYAML(t, cfgPath, nil)
	original, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	hs := makeHeadscaleConfig(cfgPath, dbPath)
	require.NoError(t, backend.MergeHeadscaleConfig(context.Background(), cfgPath, hs, true))

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(after), "dry-run must not mutate the file")
}

// TestMergeHeadscaleConfig_BYOTLSKeys asserts that BYO mode (ACME=false) sets
// tls_cert_path and tls_key_path from the hs struct and does NOT set ACME keys.
func TestMergeHeadscaleConfig_BYOTLSKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")

	writeMinimalHeadscaleYAML(t, cfgPath, nil)

	hs := makeHeadscaleConfig(cfgPath, dbPath)
	hs.ACME = false
	hs.TLSCertPath = "/etc/headscale/tls.crt"
	hs.TLSKeyPath = "/etc/headscale/tls.key"

	require.NoError(t, backend.MergeHeadscaleConfig(context.Background(), cfgPath, hs, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	assert.Equal(t, "/etc/headscale/tls.crt", result["tls_cert_path"])
	assert.Equal(t, "/etc/headscale/tls.key", result["tls_key_path"])
	// ACME keys must NOT be present in BYO mode
	assert.Nil(t, result["tls_letsencrypt_hostname"], "ACME hostname must not be set in BYO mode")
}

// TestMergeHeadscaleConfig_ACMETLSKeys asserts that ACME mode (ACME=true) sets
// letsencrypt keys and does NOT set tls_cert_path or tls_key_path.
func TestMergeHeadscaleConfig_ACMETLSKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "db.sqlite")

	writeMinimalHeadscaleYAML(t, cfgPath, nil)

	hs := makeHeadscaleConfig(cfgPath, dbPath)
	hs.ACME = true
	hs.ServerURL = "https://headscale.example.com"

	require.NoError(t, backend.MergeHeadscaleConfig(context.Background(), cfgPath, hs, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	assert.Equal(t, "headscale.example.com", result["tls_letsencrypt_hostname"])
	assert.Equal(t, "HTTP-01", result["tls_letsencrypt_challenge_type"])
	assert.Equal(t, ":http", result["tls_letsencrypt_listen"])
	// BYO keys must NOT be set in ACME mode
	assert.Nil(t, result["tls_cert_path"], "tls_cert_path must not be set in ACME mode")
	assert.Nil(t, result["tls_key_path"], "tls_key_path must not be set in ACME mode")
}
