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

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
)

func TestDefaults(t *testing.T) {
	cfg := config.Defaults()
	assert.Equal(t, 1, cfg.Version)
	assert.True(t, cfg.Tailnet.SSH)
	assert.True(t, cfg.Tailnet.Lock.Enabled)
	assert.Equal(t, 2, cfg.Tailnet.Lock.DisablementSecrets)
	assert.False(t, cfg.Tailnet.Lock.ShareWithSupport)
	assert.Equal(t, "mobile", cfg.Mobile.Tag)
	assert.Equal(t, "12h", cfg.Mobile.SSHCheckPeriod)
	assert.Contains(t, cfg.Mobile.Ports, "tcp/22")
	assert.Equal(t, "tailscale", cfg.Modules.SSH.Mode)
	assert.True(t, cfg.Modules.SSH.Enabled)
	assert.True(t, cfg.Modules.Tmux.Enabled)
	assert.Equal(t, "main", cfg.Modules.Tmux.Session)
	assert.True(t, cfg.Modules.Mosh.Enabled)
	assert.True(t, cfg.Modules.Notify.Enabled)
	assert.Equal(t, "rig", cfg.Modules.Notify.DefaultTopic)
	assert.True(t, cfg.Modules.Ntfy.Enabled)
	assert.True(t, cfg.Modules.Watch.Enabled)
	assert.False(t, cfg.ClaudeCode.Enabled)
	assert.Equal(t, "keychain", cfg.ClaudeCode.APIKeySource)
	assert.Equal(t, "keep-awake", cfg.Power.ClosedLidAC)
	assert.Equal(t, "required", cfg.Hardening.FileVault)
	assert.Equal(t, "required", cfg.Hardening.LUKS)
	assert.True(t, cfg.Hardening.FirewallStealth)
	assert.True(t, cfg.Hardening.UFWDefaultDeny)
	assert.True(t, cfg.Hardening.DisableMacOSSSHD)
}

func TestRoundTrip(t *testing.T) {
	cfg, err := config.Load("testdata/valid.yaml")
	require.NoError(t, err)
	require.NoError(t, config.Validate(cfg))
	assert.Equal(t, "you@example.com", cfg.Identity.Email)
	assert.Equal(t, "you", cfg.Identity.UnixUser)
	assert.Equal(t, "mac-dev", cfg.Tailnet.Hostname)
	assert.True(t, cfg.Tailnet.SSH)
	assert.True(t, cfg.Tailnet.Lock.Enabled)
	assert.Equal(t, "tailscale", cfg.Modules.SSH.Mode)
	assert.False(t, cfg.ClaudeCode.Enabled)
}

func TestYamlExampleValidates(t *testing.T) {
	cfg, err := config.Load("../../abysslink.yaml.example")
	require.NoError(t, err, "abysslink.yaml.example must load without error")
	require.NoError(t, config.Validate(cfg), "abysslink.yaml.example must pass validation")
}

func TestUnknownKey(t *testing.T) {
	_, err := config.Load("testdata/unknown-key.yaml")
	require.Error(t, err, "unknown YAML fields must be rejected")
}

func TestLoad_RejectsFunnelKey(t *testing.T) {
	// Tailscale Funnel exposes ports publicly — banned at schema level via KnownFields(true).
	dir := t.TempDir()
	p := filepath.Join(dir, "funnel.yaml")
	require.NoError(t, os.WriteFile(p, []byte("version: 1\nfunnel: true\n"), 0o600))
	_, err := config.Load(p)
	require.Error(t, err, "funnel: key must be rejected")
}

func TestValidate_InvalidEmail(t *testing.T) {
	cfg, err := config.Load("testdata/invalid-email.yaml")
	require.NoError(t, err)
	err = config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email")
}

func TestValidate_EmptyHostname(t *testing.T) {
	cfg, err := config.Load("testdata/invalid-hostname.yaml")
	require.NoError(t, err)
	err = config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hostname")
}

func TestValidate_InvalidPeriod(t *testing.T) {
	cfg, err := config.Load("testdata/invalid-period.yaml")
	require.NoError(t, err)
	err = config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh_check_period")
}

func TestValidate_UnsupportedVersion(t *testing.T) {
	cfg := config.Defaults()
	cfg.Version = 99
	cfg.Identity.Email = "a@b.com"
	cfg.Identity.UnixUser = "user"
	cfg.Tailnet.Hostname = "host"
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

func TestValidate_InvalidSSHMode(t *testing.T) {
	cfg := config.Defaults()
	cfg.Version = 1
	cfg.Identity.Email = "a@b.com"
	cfg.Identity.UnixUser = "user"
	cfg.Tailnet.Hostname = "host"
	cfg.Modules.SSH.Mode = "invalid"
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh.mode")
}

func TestValidate_InvalidAPIKeySource(t *testing.T) {
	cfg := config.Defaults()
	cfg.Version = 1
	cfg.Identity.Email = "a@b.com"
	cfg.Identity.UnixUser = "user"
	cfg.Tailnet.Hostname = "host"
	cfg.ClaudeCode.APIKeySource = "vault"
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key_source")
}

// TestRigConfig_UnmarshalRigs verifies that a YAML document with a rigs: list
// unmarshals into []RigConfig with all fields populated (D-FS-01).
func TestRigConfig_UnmarshalRigs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rigs.yaml")
	content := `version: 1
identity:
  email: you@example.com
  unix_user: you
tailnet:
  hostname: mac-dev
  ssh: true
rigs:
  - name: laptop
    hostname: laptop.tailnet
    ntfy_topic: abysslink-laptop-a1b2c3d4
    backend: tailscale
    last_seen: "2026-06-01T12:00:00Z"
  - name: workstation
    hostname: ws.tailnet
    ntfy_topic: abysslink-ws-e5f6a7b8
    backend: tailscale
`
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	cfg, err := config.Load(p)
	require.NoError(t, err)
	require.Len(t, cfg.Rigs, 2)
	assert.Equal(t, "laptop", cfg.Rigs[0].Name)
	assert.Equal(t, "laptop.tailnet", cfg.Rigs[0].Hostname)
	assert.Equal(t, "abysslink-laptop-a1b2c3d4", cfg.Rigs[0].NtfyTopic)
	assert.Equal(t, "tailscale", cfg.Rigs[0].Backend)
	assert.Equal(t, "2026-06-01T12:00:00Z", cfg.Rigs[0].LastSeen)
	assert.Equal(t, "workstation", cfg.Rigs[1].Name)
	assert.Equal(t, "", cfg.Rigs[1].LastSeen) // omitempty — absent
}

// TestRigConfig_LegacyScalarRig verifies that a YAML document that still uses
// the legacy scalar rig: key parses without a strict-mode KnownFields error
// (Open Question 3 backward-compat alias).
func TestRigConfig_LegacyScalarRig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "legacy.yaml")
	content := `version: 1
identity:
  email: you@example.com
  unix_user: you
tailnet:
  hostname: mac-dev
  ssh: true
rig:
  name: myrig
`
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	cfg, err := config.Load(p)
	require.NoError(t, err, "legacy rig: key must parse under strict mode")
	assert.Equal(t, "myrig", cfg.Rig.Name)
}

// TestRigConfig_RoundTrip verifies that Marshal(cfg) then Load() preserves the
// Rigs slice contents (order + fields).
func TestRigConfig_RoundTrip(t *testing.T) {
	cfg := config.Defaults()
	cfg.Identity.Email = "you@example.com"
	cfg.Identity.UnixUser = "you"
	cfg.Tailnet.Hostname = "mac-dev"
	cfg.Rigs = []config.RigConfig{
		{Name: "rig-a", Hostname: "rig-a.ts", NtfyTopic: "topic-a", Backend: "tailscale"},
		{Name: "rig-b", Hostname: "rig-b.ts", NtfyTopic: "topic-b", Backend: "headscale", LastSeen: "2026-06-01T00:00:00Z"},
	}

	data, err := config.Marshal(cfg)
	require.NoError(t, err)

	dir := t.TempDir()
	p := filepath.Join(dir, "rt.yaml")
	require.NoError(t, os.WriteFile(p, data, 0o600))

	loaded, err := config.Load(p)
	require.NoError(t, err)
	require.Len(t, loaded.Rigs, 2)
	assert.Equal(t, "rig-a", loaded.Rigs[0].Name)
	assert.Equal(t, "rig-b.ts", loaded.Rigs[1].Hostname)
	assert.Equal(t, "headscale", loaded.Rigs[1].Backend)
	assert.Equal(t, "2026-06-01T00:00:00Z", loaded.Rigs[1].LastSeen)
}

// TestRigConfig_DefaultsEmpty verifies that Defaults() returns a nil/empty Rigs
// slice (no rigs enrolled by default).
func TestRigConfig_DefaultsEmpty(t *testing.T) {
	cfg := config.Defaults()
	assert.Empty(t, cfg.Rigs, "Defaults() must return an empty Rigs slice")
}

// validObsBaseConfig returns a Config that passes all pre-existing Validate
// checks, so observability-specific assertions are isolated.
func validObsBaseConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Version = 1
	cfg.Identity.Email = "a@b.com"
	cfg.Identity.UnixUser = "user"
	cfg.Tailnet.Hostname = "host"
	return cfg
}

func TestValidateObservability(t *testing.T) {
	tests := []struct {
		name      string
		bindAddr  string
		wantErr   bool
		errSubstr string
	}{
		{name: "rejects 0.0.0.0", bindAddr: "0.0.0.0:9090", wantErr: true, errSubstr: "OBS-03"},
		{name: "rejects double colon", bindAddr: "::", wantErr: true, errSubstr: "OBS-03"},
		{name: "rejects bracketed v6 any", bindAddr: "[::]:9090", wantErr: true, errSubstr: "OBS-03"},
		{name: "accepts empty", bindAddr: "", wantErr: false},
		{name: "accepts tailnet ip", bindAddr: "100.64.0.1", wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validObsBaseConfig()
			cfg.Observability.Metrics.BindAddr = tc.bindAddr
			err := config.Validate(cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDefaultsObservabilityOff(t *testing.T) {
	cfg := config.Defaults()
	assert.False(t, cfg.Observability.Metrics.Enabled, "metrics must default OFF")
	assert.False(t, cfg.Observability.Digest.Enabled, "digest must default OFF")
}
