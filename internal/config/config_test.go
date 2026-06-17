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
	"time"

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
	// Load now calls Validate internally (D-01 fail-closed). The invalid-email
	// fixture has a syntactically invalid email address so Load returns an error.
	_, err := config.Load("testdata/invalid-email.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email")
}

func TestValidate_EmptyHostname(t *testing.T) {
	// Load now calls Validate internally (D-01 fail-closed). The invalid-hostname
	// fixture has an empty hostname so Load returns an error.
	_, err := config.Load("testdata/invalid-hostname.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hostname")
}

func TestValidate_InvalidPeriod(t *testing.T) {
	// Load now calls Validate internally (D-01 fail-closed). The invalid-period
	// fixture has an invalid ssh_check_period value so Load returns an error.
	_, err := config.Load("testdata/invalid-period.yaml")
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

// validBackendBaseConfig returns the minimal Config required to pass all
// pre-existing Validate checks so that backend-specific assertions are isolated.
func validBackendBaseConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Version = 1
	cfg.Identity.Email = "a@b.com"
	cfg.Identity.UnixUser = "user"
	cfg.Tailnet.Hostname = "my-rig"
	return cfg
}

// TestValidateNetBirdHTTP verifies that a NetBird server_url with the http://
// scheme is rejected with a message citing PAT leakage (NET-02/A7).
func TestValidateNetBirdHTTP(t *testing.T) {
	cfg := validBackendBaseConfig()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "http://nb.example.com"
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use https://")
}

// TestValidateNetBirdHTTPS verifies that a NetBird server_url with the https://
// scheme passes the scheme check (NET-02).
func TestValidateNetBirdHTTPS(t *testing.T) {
	cfg := validBackendBaseConfig()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	err := config.Validate(cfg)
	require.NoError(t, err)
}

// TestValidateHostname verifies that tailnet.hostname values with a leading dash
// or non-lowercase charset are rejected, and that valid labels are accepted (NET-03/A8).
func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name      string
		hostname  string
		wantErr   bool
		errSubstr string
	}{
		{name: "reject_leading_dash", hostname: "-badhost", wantErr: true, errSubstr: "not a valid hostname"},
		{name: "reject_uppercase", hostname: "MYRIG", wantErr: true, errSubstr: "not a valid hostname"},
		{name: "accept_valid_label", hostname: "my-rig", wantErr: false},
		{name: "accept_multi_label", hostname: "my.rig.example", wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validBackendBaseConfig()
			cfg.Tailnet.Hostname = tc.hostname
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

// TestValidateWatchPanes verifies the D-06/NET-03 flag-injection gate for tmux
// pane names. Each element of cfg.Modules.Watch.Panes is passed verbatim to
// `tmux capture-pane -t <pane>`, so a value beginning with `-` would be parsed
// as a tmux flag (A8 — same class as tailscale hostname injection).
func TestValidateWatchPanes(t *testing.T) {
	tests := []struct {
		name      string
		panes     []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid_pane",
			panes:   []string{"main"},
			wantErr: false,
		},
		{
			name:    "valid_multi_pane",
			panes:   []string{"main", "editor"},
			wantErr: false,
		},
		{
			name:      "reject_leading_dash",
			panes:     []string{"-kill-server"},
			wantErr:   true,
			errSubstr: "A8/NET-03",
		},
		{
			name:      "reject_flag_injection",
			panes:     []string{"main", "--kill-server"},
			wantErr:   true,
			errSubstr: "A8/NET-03",
		},
		{
			name:      "reject_bad_charset",
			panes:     []string{"MYRIG"},
			wantErr:   true,
			errSubstr: "A8/NET-03",
		},
		{
			name:    "empty_panes",
			panes:   []string{},
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validBackendBaseConfig()
			cfg.Modules.Watch.Panes = tc.panes
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

// TestValidateServerURLHostname verifies that a server_url whose hostname
// component begins with dashes is rejected (DNS-safe charset, NET-03/A8), and
// that a valid URL with a port is accepted.
func TestValidateServerURLHostname(t *testing.T) {
	tests := []struct {
		name        string
		backendType string
		serverURL   string
		wantErr     bool
		errSubstr   string
	}{
		{
			name:        "reject_leading_dashes_in_hostname",
			backendType: "headscale",
			serverURL:   "https://--inject.example.com",
			wantErr:     true,
			errSubstr:   "DNS-safe",
		},
		{
			name:        "accept_valid_url_with_port",
			backendType: "headscale",
			serverURL:   "https://nb.example.com:8080",
			wantErr:     false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validBackendBaseConfig()
			cfg.Backend.Type = tc.backendType
			cfg.Server.Headscale.ServerURL = tc.serverURL
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

// TestSessionRegistryConfigRoundTrip verifies that a YAML document with a
// session_registry: section (Phase 27, BACK-03, D-01/D-05/D-07/D-08) loads,
// validates, and exposes every knob.
func TestSessionRegistryConfigRoundTrip(t *testing.T) {
	base, err := os.ReadFile("testdata/valid.yaml")
	require.NoError(t, err)
	doc := string(base) + `
session_registry:
  enabled: true
  ignore_sessions:
    - logs
  idle_secs: 12
  poll_active_secs: 3
  poll_idle_secs: 20
  prompt_regex: "READY\\$$"
  cooldown_secs: 120
`
	dir := t.TempDir()
	p := filepath.Join(dir, "session.yaml")
	require.NoError(t, os.WriteFile(p, []byte(doc), 0o600))

	cfg, err := config.Load(p)
	require.NoError(t, err)
	assert.True(t, cfg.SessionRegistry.Enabled)
	assert.Equal(t, []string{"logs"}, cfg.SessionRegistry.IgnoreSessions)
	assert.Equal(t, 12, cfg.SessionRegistry.IdleSecs)
	assert.Equal(t, 3, cfg.SessionRegistry.PollActiveSecs)
	assert.Equal(t, 20, cfg.SessionRegistry.PollIdleSecs)
	assert.Equal(t, `READY\$$`, cfg.SessionRegistry.PromptRegex)
	assert.Equal(t, 120, cfg.SessionRegistry.CooldownSecs)
}

// TestSessionRegistryConfigInvalidPromptRegex verifies that an uncompilable
// prompt_regex is rejected with an error naming the field (T-27-12: user
// regex is compiled with regexp.Compile, never MustCompile).
func TestSessionRegistryConfigInvalidPromptRegex(t *testing.T) {
	cfg := validBackendBaseConfig()
	cfg.SessionRegistry.PromptRegex = "(["
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session_registry.prompt_regex")
}

// TestSessionRegistryConfigZeroValueValid verifies zero-value-means-default
// semantics: an all-zero SessionRegistry passes validation (compiled-in
// defaults apply downstream in the registry/daemon accessors).
func TestSessionRegistryConfigZeroValueValid(t *testing.T) {
	cfg := validBackendBaseConfig()
	cfg.SessionRegistry = config.SessionRegistry{}
	require.NoError(t, config.Validate(cfg))
}

// TestSessionRegistryConfigDefaultEnabled verifies the registry defaults ON
// (the Watch defaults pattern — observe-only, no destructive surface).
func TestSessionRegistryConfigDefaultEnabled(t *testing.T) {
	cfg := config.Defaults()
	assert.True(t, cfg.SessionRegistry.Enabled)
	assert.Zero(t, cfg.SessionRegistry.IdleSecs, "timing knobs default to zero = compiled-in default")
	assert.Zero(t, cfg.SessionRegistry.CooldownSecs)
}

// TestValidate_UnixUser covers the W3 charset validation: identity.unix_user
// is interpolated into the hardened sshd drop-in (`AllowUsers %s`) and the
// tailnet ACL, so anything outside the POSIX-portable username shape must be
// rejected at config-load time.
func TestValidate_UnixUser(t *testing.T) {
	mkCfg := func(user string) *config.Config {
		cfg := config.Defaults()
		cfg.Identity.Email = "a@b.com"
		cfg.Identity.UnixUser = user
		cfg.Tailnet.Hostname = "host"
		return cfg
	}

	valid := []string{"alice", "_svc", "a", "me-2", "dev_user", "u0123456789012345678901234567890"}
	for _, u := range valid {
		assert.NoError(t, config.Validate(mkCfg(u)), "unix_user %q must be accepted", u)
	}

	invalid := []string{
		"me\nPasswordAuthentication yes", // newline → sshd directive injection (W3)
		"alice bob",                      // whitespace → extra AllowUsers entry
		"Alice",                          // uppercase
		"1user",                          // leading digit
		"-user",                          // leading dash
		"user!",                          // shell metacharacter
		"a234567890123456789012345678901234567890", // > 32 chars
	}
	for _, u := range invalid {
		err := config.Validate(mkCfg(u))
		require.Error(t, err, "unix_user %q must be rejected", u)
		assert.Contains(t, err.Error(), "unix_user")
	}
}

// TestLoad_RejectsUnixUserNewlineInjection is the end-to-end W3 test: a YAML
// file carrying a newline-embedded unix_user (legal YAML!) must fail Load —
// it would otherwise inject arbitrary directives into the hardened sshd config.
func TestLoad_RejectsUnixUserNewlineInjection(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "inject.yaml")
	content := "version: 1\n" +
		"identity:\n" +
		"  email: you@example.com\n" +
		"  unix_user: \"me\\nPasswordAuthentication yes\"\n" +
		"tailnet:\n" +
		"  hostname: mac-dev\n"
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

	_, err := config.Load(p)
	require.Error(t, err, "newline-in-unix_user must be rejected at load time (W3)")
	assert.Contains(t, err.Error(), "unix_user")
}

func TestValidateUnixUser_Exported(t *testing.T) {
	assert.NoError(t, config.ValidateUnixUser("alice"))
	assert.Error(t, config.ValidateUnixUser(""), "empty user must be rejected at use sites")
	assert.Error(t, config.ValidateUnixUser("me\nX yes"))
}

// TestLoad_EmptyFile asserts the actionable empty-config message (review INFO).
func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.yaml")
	require.NoError(t, os.WriteFile(p, nil, 0o600))

	_, err := config.Load(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is empty")
	assert.Contains(t, err.Error(), "abysslink init")
	assert.Contains(t, err.Error(), p, "the message must say WHICH file is empty")

	_, err = config.LoadForRead(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "abysslink init")
}

// TestLoad_ValidationErrorIncludesPath asserts validation failures name the
// offending file (review INFO) — users may have several config candidates.
func TestLoad_ValidationErrorIncludesPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.yaml")
	content := "version: 1\nidentity:\n  email: nope\n  unix_user: you\ntailnet:\n  hostname: mac-dev\n"
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

	_, err := config.Load(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), p, "Load validation error must include the file path")

	cfg, verr := config.LoadForRead(p)
	require.Error(t, verr)
	require.NotNil(t, cfg, "LoadForRead returns the parsed config alongside the validation error")
	assert.Contains(t, verr.Error(), p, "LoadForRead validation error must include the file path")
}

// TestContentStoreDefaults asserts the Phase 28 content-store defaults
// (BACK-06): enabled by default, port 2587, TTL 600s.
func TestContentStoreDefaults(t *testing.T) {
	cfg := config.Defaults()
	assert.True(t, cfg.ContentStore.Enabled, "content store must default ON")
	assert.Equal(t, 2587, cfg.ContentStore.Port)
	assert.Equal(t, 600, cfg.ContentStore.TTLSeconds)
	assert.Empty(t, cfg.ContentStore.BindAddr)
	assert.Equal(t, 2587, cfg.ContentStore.EffectivePort())
	assert.Equal(t, 600*time.Second, cfg.ContentStore.EffectiveTTL())
}

// TestContentStoreEffectiveZeroValues asserts the zero-means-default idiom.
func TestContentStoreEffectiveZeroValues(t *testing.T) {
	var cs config.ContentStoreConfig
	assert.Equal(t, config.DefaultContentStorePort, cs.EffectivePort())
	assert.Equal(t, time.Duration(config.DefaultContentTTLSeconds)*time.Second, cs.EffectiveTTL())
}

// TestEffectiveEnrollTTL_Default asserts the zero-means-default 300s for the
// SEPARATE bootstrap TTL knob (BACK-09), independent of the content TTL.
func TestEffectiveEnrollTTL_Default(t *testing.T) {
	var cs config.ContentStoreConfig
	assert.Equal(t, time.Duration(config.DefaultEnrollTTLSeconds)*time.Second, cs.EffectiveEnrollTTL())
	assert.Equal(t, 300*time.Second, cs.EffectiveEnrollTTL())
}

// TestEffectiveEnrollTTL_ClampsLow asserts a programmatic below-floor value is
// clamped up to the 30s floor so the store never mints a too-short bootstrap.
func TestEffectiveEnrollTTL_ClampsLow(t *testing.T) {
	cs := config.ContentStoreConfig{EnrollTTLSeconds: 5}
	assert.Equal(t, time.Duration(config.MinEnrollTTLSeconds)*time.Second, cs.EffectiveEnrollTTL())
	assert.Equal(t, 30*time.Second, cs.EffectiveEnrollTTL())
}

// TestEffectiveEnrollTTL_ClampsHigh asserts a programmatic above-ceiling value
// is clamped down to the 900s ceiling so the store never mints an unbounded
// bootstrap token.
func TestEffectiveEnrollTTL_ClampsHigh(t *testing.T) {
	cs := config.ContentStoreConfig{EnrollTTLSeconds: 5000}
	assert.Equal(t, time.Duration(config.MaxEnrollTTLSeconds)*time.Second, cs.EffectiveEnrollTTL())
	assert.Equal(t, 900*time.Second, cs.EffectiveEnrollTTL())
}

// TestValidateContentStore_EnrollTTLRejectsOutOfRange asserts a non-zero
// enroll_ttl_seconds outside [30,900] is rejected at validation, while 0 and a
// valid in-range value pass.
func TestValidateContentStore_EnrollTTLRejectsOutOfRange(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		wantErr bool
	}{
		{name: "rejects below floor", seconds: 10, wantErr: true},
		{name: "rejects above ceiling", seconds: 1000, wantErr: true},
		{name: "accepts zero (default)", seconds: 0},
		{name: "accepts in-range default", seconds: 300},
		{name: "accepts floor", seconds: 30},
		{name: "accepts ceiling", seconds: 900},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validObsBaseConfig()
			cfg.ContentStore.EnrollTTLSeconds = tc.seconds
			err := config.Validate(cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "enroll_ttl_seconds")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateContentStore(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*config.Config)
		wantErr   bool
		errSubstr string
	}{
		{name: "defaults valid", mutate: func(*config.Config) {}},
		{
			name:      "rejects wildcard bind 0.0.0.0",
			mutate:    func(c *config.Config) { c.ContentStore.BindAddr = "0.0.0.0" },
			wantErr:   true,
			errSubstr: "BACK-06",
		},
		{
			name:      "rejects wildcard bind ::",
			mutate:    func(c *config.Config) { c.ContentStore.BindAddr = "::" },
			wantErr:   true,
			errSubstr: "BACK-06",
		},
		{
			name:      "rejects DNS-name bind",
			mutate:    func(c *config.Config) { c.ContentStore.BindAddr = "rig.example.ts.net" },
			wantErr:   true,
			errSubstr: "literal IP",
		},
		{
			name:      "rejects host:port bind (literal IP only)",
			mutate:    func(c *config.Config) { c.ContentStore.BindAddr = "100.64.0.1:2587" },
			wantErr:   true,
			errSubstr: "literal IP",
		},
		{
			name:   "accepts literal tailnet IPv4",
			mutate: func(c *config.Config) { c.ContentStore.BindAddr = "100.64.0.1" },
		},
		{
			name:   "accepts literal tailnet IPv6 ULA",
			mutate: func(c *config.Config) { c.ContentStore.BindAddr = "fd7a:115c:a1e0::1234" },
		},
		{
			name:      "rejects ttl below floor",
			mutate:    func(c *config.Config) { c.ContentStore.TTLSeconds = 29 },
			wantErr:   true,
			errSubstr: "ttl_seconds",
		},
		{
			name:      "rejects ttl above ceiling",
			mutate:    func(c *config.Config) { c.ContentStore.TTLSeconds = 3601 },
			wantErr:   true,
			errSubstr: "ttl_seconds",
		},
		{name: "accepts ttl floor", mutate: func(c *config.Config) { c.ContentStore.TTLSeconds = 30 }},
		{name: "accepts ttl ceiling", mutate: func(c *config.Config) { c.ContentStore.TTLSeconds = 3600 }},
		{name: "accepts ttl zero (default)", mutate: func(c *config.Config) { c.ContentStore.TTLSeconds = 0 }},
		{
			name:      "rejects out-of-range port",
			mutate:    func(c *config.Config) { c.ContentStore.Port = 70000 },
			wantErr:   true,
			errSubstr: "content_store.port",
		},
		{
			name:      "rejects negative port",
			mutate:    func(c *config.Config) { c.ContentStore.Port = -1 },
			wantErr:   true,
			errSubstr: "content_store.port",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validObsBaseConfig()
			tc.mutate(cfg)
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

// TestGatewayDefaults checks that the default config has APNs off, FCM off,
// and UnifiedPush on — per D-14 and D-18.
func TestGatewayDefaults(t *testing.T) {
	cfg := config.Defaults()
	assert.False(t, cfg.Gateway.APNs.Enabled, "APNs must default disabled (D-14 experimental)")
	assert.False(t, cfg.Gateway.FCM.Enabled, "FCM must default disabled (D-14 experimental)")
	assert.True(t, cfg.Gateway.UnifiedPush.Enabled, "UnifiedPush must default enabled (D-18 sovereign path)")
	assert.Equal(t, "keychain", cfg.Gateway.APNs.KeySource, "APNs key_source must default to keychain")
	assert.Equal(t, "keychain", cfg.Gateway.FCM.CredsSource, "FCM creds_source must default to keychain")
}

// TestGatewayValidateAPNsBundleRequired ensures that enabling APNs without a
// bundle_id returns a validation error (research Q1 / plan must-have).
func TestGatewayValidateAPNsBundleRequired(t *testing.T) {
	cfg := validObsBaseConfig()
	cfg.Gateway.APNs.Enabled = true
	cfg.Gateway.APNs.BundleID = "" // explicit blank
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle_id")
}

// TestGatewayValidateKeySource ensures that an invalid key_source is rejected.
func TestGatewayValidateKeySource(t *testing.T) {
	cfg := validObsBaseConfig()
	cfg.Gateway.APNs.KeySource = "invalid-source"
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key_source")
}

// TestGatewayValidateOK confirms that a fully specified gateway config passes
// validation (APNs enabled with bundle_id, valid key_source and creds_source).
func TestGatewayValidateOK(t *testing.T) {
	cfg := validObsBaseConfig()
	cfg.Gateway.APNs.Enabled = true
	cfg.Gateway.APNs.BundleID = "com.example.app"
	cfg.Gateway.APNs.KeySource = "keychain"
	cfg.Gateway.FCM.Enabled = true
	cfg.Gateway.FCM.CredsSource = "file"
	cfg.Gateway.UnifiedPush.Enabled = true
	require.NoError(t, config.Validate(cfg))
}

// TestDefaultConfig_Gate verifies that Defaults() returns Gate.Enforcing=false
// (shadow mode per D-04 — enforcing is opt-in, never the default).
func TestDefaultConfig_Gate(t *testing.T) {
	cfg := config.Defaults()
	assert.False(t, cfg.Gate.Enforcing, "Gate.Enforcing must default to false (shadow mode per D-04)")
}

// TestDefaultConfig_Approval verifies that Defaults() returns the correct
// approval defaults: TimeoutSeconds=120, ExtraCritical nil/empty (D-09).
func TestDefaultConfig_Approval(t *testing.T) {
	cfg := config.Defaults()
	assert.Equal(t, 120, cfg.Approval.TimeoutSeconds, "Approval.TimeoutSeconds must default to 120 (D-09)")
	assert.Empty(t, cfg.Approval.ExtraCritical, "Approval.ExtraCritical must default to nil/empty")
}

// TestValidate_ApprovalTimeoutFloor verifies that Validate() rejects a
// TimeoutSeconds below the 10-second floor (D-09 floor prevents instant-deny DoS).
func TestValidate_ApprovalTimeoutFloor(t *testing.T) {
	cfg := validObsBaseConfig()
	cfg.Approval.TimeoutSeconds = 5 // below 10s floor
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "approval.timeout_seconds")
}

// TestValidate_ApprovalTimeoutOK verifies that Validate() accepts a
// TimeoutSeconds value above the floor (D-09).
func TestValidate_ApprovalTimeoutOK(t *testing.T) {
	cfg := validObsBaseConfig()
	cfg.Approval.TimeoutSeconds = 30 // above floor
	require.NoError(t, config.Validate(cfg))
}
