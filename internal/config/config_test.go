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
