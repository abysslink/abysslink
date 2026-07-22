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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadSentinelYAML writes a minimal v1 config with the given sentinel stanza and
// loads it through the strict fail-closed Load path.
func loadSentinelYAML(t *testing.T, sentinelStanza string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "abysslink.yaml")
	doc := "version: 1\n" +
		"identity:\n  email: op@example.com\n  unix_user: op\n" +
		"tailnet:\n  hostname: rig-test\n" +
		sentinelStanza
	require.NoError(t, os.WriteFile(p, []byte(doc), 0o600))
	return Load(p)
}

// TestSentinel_DefaultsOff: the detector ships OFF (opt-in) and quarantine ships
// OFF (the always-on default posture is flag+audit only).
func TestSentinel_DefaultsOff(t *testing.T) {
	cfg := Defaults()
	assert.False(t, cfg.Sentinel.Enabled, "sentinel must default OFF (opt-in)")
	assert.False(t, cfg.Sentinel.Quarantine, "sentinel quarantine must default OFF (self-DoS avoidance)")
}

// TestValidateSentinel_TightenOnlyAccepted: zero (=default) and values at or
// below the shipped window bounds are accepted.
func TestValidateSentinel_TightenOnlyAccepted(t *testing.T) {
	for _, tc := range []SentinelConfig{
		{Enabled: true},
		{Enabled: true, WindowExecs: 1, WindowSeconds: 1},
		{Enabled: true, WindowExecs: SentinelDefaultWindowExecs, WindowSeconds: SentinelDefaultWindowSeconds},
		{Enabled: true, ExtraSensitivePaths: []string{"vault.txt"}, EgressAllowlist: []string{"*.corp.example"}},
	} {
		cfg := Defaults()
		cfg.Sentinel = tc
		require.NoError(t, validateSentinel(cfg), "%+v should be accepted", tc)
	}
}

// TestValidateSentinel_LooseningRejected: a window LARGER than the shipped
// default is rejected (never clamped) — the tighten-only contract.
func TestValidateSentinel_LooseningRejected(t *testing.T) {
	cases := []SentinelConfig{
		{Enabled: true, WindowExecs: SentinelDefaultWindowExecs + 1},
		{Enabled: true, WindowSeconds: SentinelDefaultWindowSeconds + 1},
		{Enabled: true, WindowExecs: -1},
		{Enabled: true, WindowSeconds: -5},
	}
	for _, tc := range cases {
		cfg := Defaults()
		cfg.Sentinel = tc
		assert.Error(t, validateSentinel(cfg), "%+v must be rejected as loosening", tc)
	}
}

// TestValidateSentinel_OverbroadEgressRejected: an egress_allowlist entry broad
// enough to swallow a whole address space — a /0 universe CIDR or a bare
// top-level-domain wildcard — would silently make the detector vacuous, so it is
// a load error (the same tighten-only contract the window bounds enforce).
func TestValidateSentinel_OverbroadEgressRejected(t *testing.T) {
	cases := []SentinelConfig{
		{Enabled: true, EgressAllowlist: []string{"0.0.0.0/0"}},
		{Enabled: true, EgressAllowlist: []string{"::/0"}},
		{Enabled: true, EgressAllowlist: []string{"*.com"}},
		{Enabled: true, EgressAllowlist: []string{"*.net"}},
		{Enabled: true, EgressAllowlist: []string{"ok.example", "*.org"}},
	}
	for _, tc := range cases {
		cfg := Defaults()
		cfg.Sentinel = tc
		assert.Error(t, validateSentinel(cfg), "%+v must be rejected as an over-broad allowlist", tc)
	}

	// Narrow entries — a specific host, a real subnet, a multi-label suffix —
	// remain accepted.
	for _, tc := range []SentinelConfig{
		{Enabled: true, EgressAllowlist: []string{"mirror.corp.example.com"}},
		{Enabled: true, EgressAllowlist: []string{"10.0.0.0/8"}},
		{Enabled: true, EgressAllowlist: []string{"*.corp.example.com"}},
	} {
		cfg := Defaults()
		cfg.Sentinel = tc
		require.NoError(t, validateSentinel(cfg), "%+v is narrow and must be accepted", tc)
	}
}

// TestValidateSentinel_EmptyListEntryRejected: an empty allowlist/path entry is
// a load error.
func TestValidateSentinel_EmptyListEntryRejected(t *testing.T) {
	cfg := Defaults()
	cfg.Sentinel = SentinelConfig{Enabled: true, EgressAllowlist: []string{"ok.example", "  "}}
	assert.Error(t, validateSentinel(cfg))

	cfg2 := Defaults()
	cfg2.Sentinel = SentinelConfig{Enabled: true, ExtraSensitivePaths: []string{""}}
	assert.Error(t, validateSentinel(cfg2))
}

// TestValidateSentinel_ContractHoldsEvenWhenDisabled: a loosening value can
// never be pre-loaded under a disabled stanza.
func TestValidateSentinel_ContractHoldsEvenWhenDisabled(t *testing.T) {
	cfg := Defaults()
	cfg.Sentinel = SentinelConfig{Enabled: false, WindowExecs: 999}
	assert.Error(t, validateSentinel(cfg), "the tighten-only contract must hold even when disabled")
}

// TestSentinel_UnknownKeyRejected: a deliberately-absent weakening key is a
// fatal strict-decode error (the Funnel pattern via KnownFields(true)).
func TestSentinel_UnknownKeyRejected(t *testing.T) {
	_, err := loadSentinelYAML(t, "sentinel:\n  enabled: true\n  disable_rules: true\n")
	require.Error(t, err, "an unknown sentinel weakening key must be rejected at decode")

	// A well-formed enabled stanza with an ADD-ONLY allowlist loads cleanly.
	cfg, err := loadSentinelYAML(t, "sentinel:\n  enabled: true\n  egress_allowlist:\n    - \"*.corp.example\"\n")
	require.NoError(t, err)
	assert.True(t, cfg.Sentinel.Enabled)
	assert.Equal(t, []string{"*.corp.example"}, cfg.Sentinel.EgressAllowlist)
}
