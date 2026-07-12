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

// loadDuressYAML writes a minimal v1 config with the given stanza(s) appended
// and loads it through the strict fail-closed Load path (primes identity +
// tailnet so Validate reaches the duress/decoy validators).
func loadDuressYAML(t *testing.T, stanza string) (*config.Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "abysslink.yaml")
	doc := "version: 1\n" +
		"identity:\n  email: op@example.com\n  unix_user: op\n" +
		"tailnet:\n  hostname: rig-test\n" +
		stanza
	require.NoError(t, os.WriteFile(p, []byte(doc), 0o600))
	return config.Load(p)
}

func TestDuressDecoy_DefaultsOff(t *testing.T) {
	cfg := config.Defaults()
	assert.False(t, cfg.Duress.Enabled, "duress ships OFF (opt-in)")
	assert.False(t, cfg.Decoy.Enabled, "decoy ships OFF (opt-in)")
	// Zero value resolves to the keychain source (the only storing selector).
	assert.Equal(t, config.DuressSecretSourceKeychain, cfg.Duress.ResolvedSecretSource())
}

func TestDuress_ZeroValuesLoadClean(t *testing.T) {
	// An omitted stanza inherits the disabled default and validates cleanly.
	cfg, err := loadDuressYAML(t, "")
	require.NoError(t, err)
	assert.False(t, cfg.Duress.Enabled)
	assert.False(t, cfg.Decoy.Enabled)
}

func TestValidateDuress_SecretSourceEnum(t *testing.T) {
	cases := []struct {
		name    string
		stanza  string
		wantErr bool
	}{
		{"disabled_ignores_bad_source", "duress:\n  enabled: false\n  secret_source: bogus\n", false},
		{"enabled_keychain_ok", "duress:\n  enabled: true\n  secret_source: keychain\n", false},
		{"enabled_empty_source_ok", "duress:\n  enabled: true\n", false},
		{"enabled_none_ok", "duress:\n  enabled: true\n  secret_source: none\n", false},
		{"enabled_plaintext_rejected", "duress:\n  enabled: true\n  secret_source: plaintext\n", true},
		{"enabled_file_rejected", "duress:\n  enabled: true\n  secret_source: file\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadDuressYAML(t, tc.stanza)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateDecoy_Hostname(t *testing.T) {
	t.Run("enabled_safe_hostname_ok", func(t *testing.T) {
		_, err := loadDuressYAML(t, "decoy:\n  enabled: true\n  hostname: workstation\n")
		require.NoError(t, err)
	})
	t.Run("enabled_unsafe_hostname_rejected", func(t *testing.T) {
		_, err := loadDuressYAML(t, "decoy:\n  enabled: true\n  hostname: \"-injected flag\"\n")
		require.Error(t, err, "an argv-injection hostname must be rejected")
	})
	t.Run("disabled_ignores_hostname", func(t *testing.T) {
		_, err := loadDuressYAML(t, "decoy:\n  enabled: false\n  hostname: \"-bad\"\n")
		require.NoError(t, err, "a disabled decoy never constrains")
	})
}

// TestDuress_KnownFieldsRejectsWipeKeys asserts the schema deliberately has NO
// destructive-wipe or plaintext-credential field: any such key is rejected by
// KnownFields(true) — the same mechanism that rejects `funnel`. A destructive
// duress-wipe is an explicit anti-feature and must be impossible to configure.
func TestDuress_KnownFieldsRejectsWipeKeys(t *testing.T) {
	for _, stanza := range []string{
		"duress:\n  enabled: true\n  wipe: true\n",
		"duress:\n  enabled: true\n  wipe_real: true\n",
		"duress:\n  enabled: true\n  destroy: true\n",
		"duress:\n  enabled: true\n  plaintext_pin: 1234\n",
		"decoy:\n  enabled: true\n  wipe_real: true\n",
		"decoy:\n  enabled: true\n  plaintext_pin: 1234\n",
		"decoy:\n  enabled: true\n  reveal_real: true\n",
	} {
		_, err := loadDuressYAML(t, stanza)
		require.Error(t, err, "weakening/destructive key must be rejected at the schema level: %q", stanza)
	}
}
