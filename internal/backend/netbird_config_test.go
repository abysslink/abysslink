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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
)

// makeNetBirdConfig builds a config.NetBirdServer for tests.
func makeNetBirdConfig(cfgPath string) config.NetBirdServer {
	return config.NetBirdServer{
		ServerURL:  "https://nb.example.com",
		ConfigPath: cfgPath,
	}
}

// writeMinimalNetBirdYAML writes a baseline netbird config.yaml to path.
func writeMinimalNetBirdYAML(t *testing.T, path string, extra map[string]any) {
	t.Helper()
	base := map[string]any{
		"server": map[string]any{
			"listenAddress": "127.0.0.1:443",
			"auth": map[string]any{
				"issuer": "http://localhost:5556/dex",
			},
		},
	}
	for k, v := range extra {
		base[k] = v
	}
	data, err := yaml.Marshal(base)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

// TestMergeNetBirdConfig_SetsRequiredKeys verifies that all required hardened
// keys are set after a merge:
//   - disableAnonymousMetrics: true
//   - disableGeoliteUpdate: true
//   - metricsPort: 9090
func TestMergeNetBirdConfig_SetsRequiredKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	writeMinimalNetBirdYAML(t, cfgPath, nil)

	nb := makeNetBirdConfig(cfgPath)
	err := backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, false)
	require.NoError(t, err)

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	assert.Equal(t, true, result["disableAnonymousMetrics"], "disableAnonymousMetrics must be true")
	assert.Equal(t, true, result["disableGeoliteUpdate"], "disableGeoliteUpdate must be true")
	assert.Equal(t, 9090, result["metricsPort"], "metricsPort must be 9090")
}

// TestMergeNetBirdConfig_Idempotent asserts that re-running MergeNetBirdConfig
// on an already-hardened config produces identical output bytes (idempotent).
func TestMergeNetBirdConfig_Idempotent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	writeMinimalNetBirdYAML(t, cfgPath, nil)

	nb := makeNetBirdConfig(cfgPath)

	// First merge.
	require.NoError(t, backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, false))
	data1, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	// Second merge — must produce same result.
	require.NoError(t, backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, false))
	data2, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	assert.Equal(t, string(data1), string(data2), "MergeNetBirdConfig must be idempotent")
}

// TestMergeNetBirdConfig_MetricsPortCorrection verifies that a wrong metricsPort
// is corrected to 9090 on merge.
func TestMergeNetBirdConfig_MetricsPortCorrection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	// Write config with wrong metricsPort.
	writeMinimalNetBirdYAML(t, cfgPath, map[string]any{
		"metricsPort": 8888,
	})

	nb := makeNetBirdConfig(cfgPath)
	require.NoError(t, backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))
	assert.Equal(t, 9090, result["metricsPort"], "metricsPort must be corrected to 9090")
}

// TestMergeNetBirdConfig_TLSCertInjection verifies that when nb.TLSCertFile is
// set, server.tls.certFile and server.tls.keyFile are injected.
func TestMergeNetBirdConfig_TLSCertInjection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	// Config has no tls section initially.
	writeMinimalNetBirdYAML(t, cfgPath, nil)

	nb := makeNetBirdConfig(cfgPath)
	nb.TLSCertFile = "/etc/netbird/tls/server.crt"
	nb.TLSKeyFile = "/etc/netbird/tls/server.key"

	require.NoError(t, backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	srv, ok := result["server"].(map[string]any)
	require.True(t, ok, "server must be a map")

	tlsMap, ok := srv["tls"].(map[string]any)
	require.True(t, ok, "server.tls must be a map")

	assert.Equal(t, "/etc/netbird/tls/server.crt", tlsMap["certFile"], "server.tls.certFile must match")
	assert.Equal(t, "/etc/netbird/tls/server.key", tlsMap["keyFile"], "server.tls.keyFile must match")
}

// TestMergeNetBirdConfig_NoTLSWhenCertEmpty verifies that no tls keys are
// injected when nb.TLSCertFile is empty (user manages TLS externally).
func TestMergeNetBirdConfig_NoTLSWhenCertEmpty(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	writeMinimalNetBirdYAML(t, cfgPath, nil)

	nb := makeNetBirdConfig(cfgPath)
	// TLSCertFile is empty — tls section must NOT be injected.

	require.NoError(t, backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	srv, ok := result["server"].(map[string]any)
	require.True(t, ok, "server must be a map")
	// tls sub-key must be absent
	_, hasTLS := srv["tls"]
	assert.False(t, hasTLS, "server.tls must NOT be set when TLSCertFile is empty")
}

// TestMergeNetBirdConfig_DryRun asserts that in dryRun mode, no file changes
// are written (original file content is unchanged).
func TestMergeNetBirdConfig_DryRun(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	writeMinimalNetBirdYAML(t, cfgPath, nil)
	original, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	nb := makeNetBirdConfig(cfgPath)
	require.NoError(t, backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, true))

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(after), "dry-run must not mutate the file")
}

// TestMergeNetBirdConfig_MissingFile verifies that when the config file does
// not exist, an empty map base is used and hardened keys appear in the output.
func TestMergeNetBirdConfig_MissingFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// Do NOT create the file.

	nb := makeNetBirdConfig(cfgPath)
	require.NoError(t, backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	assert.Equal(t, true, result["disableAnonymousMetrics"])
	assert.Equal(t, true, result["disableGeoliteUpdate"])
	assert.Equal(t, 9090, result["metricsPort"])
}

// TestMergeNetBirdConfig_PreservesUserKeys asserts that keys outside the
// hardened set (server.auth.issuer, server.listenAddress, etc.) are preserved.
func TestMergeNetBirdConfig_PreservesUserKeys(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	writeMinimalNetBirdYAML(t, cfgPath, map[string]any{
		"logLevel": "debug",
	})

	nb := makeNetBirdConfig(cfgPath)
	require.NoError(t, backend.MergeNetBirdConfig(context.Background(), cfgPath, nb, false))

	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, yaml.Unmarshal(data, &result))

	// User-owned key must survive.
	assert.Equal(t, "debug", result["logLevel"], "logLevel must be preserved")

	// server.auth.issuer must be preserved.
	srv, ok := result["server"].(map[string]any)
	require.True(t, ok)
	auth, ok := srv["auth"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "http://localhost:5556/dex", auth["issuer"], "auth.issuer must be preserved")
}
