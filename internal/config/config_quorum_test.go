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

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/config"
)

// loadQuorumYAML writes a minimal v1 config with the given quorum stanza and
// loads it through the strict fail-closed Load path.
func loadQuorumYAML(t *testing.T, quorumStanza string) (*config.Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "abysslink.yaml")
	doc := "version: 1\n" +
		"identity:\n  email: op@example.com\n  unix_user: op\n" +
		"tailnet:\n  hostname: rig-test\n" +
		quorumStanza
	require.NoError(t, os.WriteFile(p, []byte(doc), 0o600))
	return config.Load(p)
}

// TestQuorumDefaults_EnabledShadow: Defaults ships quorum evaluation ON while
// enforcement still rides gate.enforcing (which ships false).
func TestQuorumDefaults_EnabledShadow(t *testing.T) {
	cfg := config.Defaults()
	assert.True(t, cfg.Quorum.Enabled, "quorum evaluation + shadow audit are default-ON (E4.1)")
	assert.False(t, cfg.Gate.Enforcing, "enforcement still rides the single D-04 arm switch")
	assert.Zero(t, cfg.Quorum.SpendThresholdUSD, "zero numerics mean compiled defaults")
}

// TestValidateQuorum_TightenOnlyAccepted: everything strictly tighter than
// the shipped defaults loads cleanly.
func TestValidateQuorum_TightenOnlyAccepted(t *testing.T) {
	cfg, err := loadQuorumYAML(t, `quorum:
  enabled: true
  protected_paths: ["/srv/prod-inventory"]
  protected_branches: ["release"]
  extra_patterns: ["prod-db"]
  canary_paths: ["HONEYTOKEN-7f3a"]
  spend_threshold_usd: 25
  rate_max_ops: 5
  rate_window_seconds: 600
  tier_overrides:
    force-push: critical
    rm-recursive-force: critical
`)
	require.NoError(t, err, "a strictly-tighter quorum stanza must load")
	assert.Equal(t, 25.0, cfg.Quorum.SpendThresholdUSD)
	assert.Equal(t, 5, cfg.Quorum.RateMaxOps)
	assert.Equal(t, 600, cfg.Quorum.RateWindowSeconds)

	ec := cfg.Quorum.EngineConfig(true)
	assert.True(t, ec.Enforcing)
	assert.Equal(t, approve.TierCritical, ec.TierOverrides["force-push"])
	assert.Equal(t, []string{"/srv/prod-inventory"}, ec.ProtectedPaths)
	assert.Equal(t, []string{"HONEYTOKEN-7f3a"}, ec.CanaryMarkers)
}

// TestValidateQuorum_LooseningRejected: every loosening below the shipped
// defaults is a config LOAD ERROR — rejected, never clamped.
func TestValidateQuorum_LooseningRejected(t *testing.T) {
	cases := []struct {
		label  string
		stanza string
	}{
		{"raised spend threshold", "quorum:\n  enabled: true\n  spend_threshold_usd: 100\n"},
		{"negative spend threshold", "quorum:\n  enabled: true\n  spend_threshold_usd: -1\n"},
		// yaml.v3 resolves `.nan` to a float64 NaN; every ordered comparison
		// against NaN is false, so without an explicit IsNaN guard it would slip
		// past the range check and silently disable the spend gate.
		{"NaN spend threshold", "quorum:\n  enabled: true\n  spend_threshold_usd: .nan\n"},
		{"+Inf spend threshold", "quorum:\n  enabled: true\n  spend_threshold_usd: .inf\n"},
		{"more destructive ops per window", "quorum:\n  enabled: true\n  rate_max_ops: 50\n"},
		{"shorter (looser) rate window", "quorum:\n  enabled: true\n  rate_window_seconds: 60\n"},
		// A window so long it overflows time.Duration would silently DISABLE the
		// destructive-op rate cap (a config-driven loosening below the floor) —
		// rejected at load, never accepted.
		{"overflowing rate window", "quorum:\n  enabled: true\n  rate_window_seconds: 10000000000\n"},
		{"tier lowering", "quorum:\n  enabled: true\n  tier_overrides:\n    protected-path-write: sensitive\n"},
		{"unknown rule code", "quorum:\n  enabled: true\n  tier_overrides:\n    no-such-rule: critical\n"},
		{"unknown tier name", "quorum:\n  enabled: true\n  tier_overrides:\n    force-push: relaxed\n"},
		{"empty protected path entry", "quorum:\n  enabled: true\n  protected_paths: [\"\"]\n"},
		{"empty canary entry", "quorum:\n  enabled: true\n  canary_paths: [\" \"]\n"},
	}
	for _, c := range cases {
		_, err := loadQuorumYAML(t, c.stanza)
		require.Error(t, err, "%s must be a load error, never clamped", c.label)
		assert.Contains(t, err.Error(), "quorum", c.label)
	}
}

// TestLoad_RejectsQuorumFloorKey and friends: the deliberately-absent knobs
// are rejected at the SCHEMA level by KnownFields(true) — the Funnel pattern.
// No struct field exists for them, so their presence is a fatal decode error;
// there is no code path that could honor them.
func TestLoad_RejectsQuorumFloorKey(t *testing.T) {
	_, err := loadQuorumYAML(t, "quorum:\n  floor: []\n")
	require.Error(t, err, "quorum.floor must be rejected by KnownFields(true)")
}

func TestLoad_RejectsQuorumDisableFloorKey(t *testing.T) {
	_, err := loadQuorumYAML(t, "quorum:\n  disable_floor: true\n")
	require.Error(t, err, "quorum.disable_floor must be rejected by KnownFields(true)")
}

func TestLoad_RejectsQuorumRemovePatternsKey(t *testing.T) {
	_, err := loadQuorumYAML(t, "quorum:\n  remove_patterns: [\"rm-root\"]\n")
	require.Error(t, err, "quorum.remove_patterns must be rejected by KnownFields(true)")
}

func TestLoad_RejectsQuorumDryRunFirstKey(t *testing.T) {
	_, err := loadQuorumYAML(t, "quorum:\n  dry_run_first: false\n")
	require.Error(t, err, "quorum.dry_run_first must be rejected (always on when enabled)")
}

func TestLoad_RejectsQuorumVerifierTimeoutKey(t *testing.T) {
	_, err := loadQuorumYAML(t, "quorum:\n  verifier_timeout: 60\n")
	require.Error(t, err, "quorum.verifier_timeout must be rejected by KnownFields(true)")
}

func TestLoad_RejectsQuorumEnforcingKey(t *testing.T) {
	_, err := loadQuorumYAML(t, "quorum:\n  enforcing: true\n")
	require.Error(t, err, "quorum.enforcing must be rejected — gate.enforcing is the only arm switch")
}

// TestQuorum_ZeroValuesLoadCleanly: the zero-value stanza (and an omitted
// stanza) both pass validation — zero means "use the compiled default".
func TestQuorum_ZeroValuesLoadCleanly(t *testing.T) {
	cfg, err := loadQuorumYAML(t, "quorum:\n  enabled: false\n")
	require.NoError(t, err)
	assert.False(t, cfg.Quorum.Enabled)

	cfg, err = loadQuorumYAML(t, "")
	require.NoError(t, err)
	assert.True(t, cfg.Quorum.Enabled, "an omitted stanza inherits the default-ON evaluation")
}
