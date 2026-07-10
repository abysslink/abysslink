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

// TestHardwareKeysConfig_DefaultsOff asserts hardware keys are OPT-IN and
// ship OFF (HWK-01..04): a default config and a config without the stanza
// both decode to disabled — zero behavior change for existing users.
func TestHardwareKeysConfig_DefaultsOff(t *testing.T) {
	cfg := config.Defaults()
	assert.False(t, cfg.HardwareKeys.Enabled, "hardware keys must default OFF (opt-in)")
	assert.Empty(t, cfg.HardwareKeys.Provider)

	// A pre-Phase-37 YAML without the stanza must load with the zero value.
	loaded, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	require.NoError(t, err)
	assert.False(t, loaded.HardwareKeys.Enabled)
}

func TestHardwareKeysConfig_Resolvers(t *testing.T) {
	var h config.HardwareKeysConfig
	assert.Equal(t, "ed25519-sk", h.ResolvedKeyType())
	assert.Equal(t, "ssh:abysslink", h.ResolvedApplication())
	assert.Equal(t, filepath.Join("/home/u", ".ssh", "abysslink_id_sk"), h.ResolvedKeyPath("/home/u"))

	h = config.HardwareKeysConfig{KeyType: "ecdsa-sk", Application: "ssh:custom", KeyPath: "/keys/sk"}
	assert.Equal(t, "ecdsa-sk", h.ResolvedKeyType())
	assert.Equal(t, "ssh:custom", h.ResolvedApplication())
	assert.Equal(t, "/keys/sk", h.ResolvedKeyPath("/home/u"))
}

// TestHardwareKeysConfig_ResolvedKeyTypeProviderAware is the P37-01
// regression: the default enclave stanza (`abysslink enroll rig --key-kind
// secure-enclave` writes Enabled+Provider only) must resolve to ecdsa-sk —
// the enclave is P-256 only, and resolving the fido2 default ed25519-sk for
// every provider made `enroll hardware-key --apply` a guaranteed
// ErrSoftwareKey refusal on the default enclave config (dead path, though
// still fail-closed: no software key was ever minted).
func TestHardwareKeysConfig_ResolvedKeyTypeProviderAware(t *testing.T) {
	h := config.HardwareKeysConfig{Enabled: true, Provider: "secure-enclave"}
	assert.Equal(t, "ecdsa-sk", h.ResolvedKeyType(),
		"the enclave default must be ecdsa-sk, never the impossible ed25519-sk")

	h = config.HardwareKeysConfig{Enabled: true, Provider: "fido2"}
	assert.Equal(t, "ed25519-sk", h.ResolvedKeyType(), "the fido2 default is unchanged")

	// An explicit ecdsa-sk opt-down always wins for either provider.
	h = config.HardwareKeysConfig{Enabled: true, Provider: "fido2", KeyType: "ecdsa-sk"}
	assert.Equal(t, "ecdsa-sk", h.ResolvedKeyType())
}

// TestHardwareKeysConfig_ValidateTable exercises ValidateHardwareKeys through
// config.Validate: enum allowlists at the config layer (a typo like
// "ed25519" must never reach a provider), the impossible enclave+ed25519-sk
// combo, and the ssh: application prefix.
func TestHardwareKeysConfig_ValidateTable(t *testing.T) {
	base := config.Defaults()
	base.Identity.Email = "a@b.com"
	base.Identity.UnixUser = "user"
	base.Tailnet.Hostname = "rig"

	cases := []struct {
		name    string
		hk      config.HardwareKeysConfig
		wantErr string // empty = valid
	}{
		{"disabled_zero_value", config.HardwareKeysConfig{}, ""},
		{"enabled_fido2", config.HardwareKeysConfig{Enabled: true, Provider: "fido2"}, ""},
		{"enabled_enclave", config.HardwareKeysConfig{Enabled: true, Provider: "secure-enclave"}, ""},
		{"enabled_fido2_ecdsa", config.HardwareKeysConfig{Enabled: true, Provider: "fido2", KeyType: "ecdsa-sk"}, ""},
		{"enabled_enclave_ecdsa", config.HardwareKeysConfig{Enabled: true, Provider: "secure-enclave", KeyType: "ecdsa-sk"}, ""},
		{"custom_ssh_application", config.HardwareKeysConfig{Enabled: true, Provider: "fido2", Application: "ssh:myrig"}, ""},
		{"enabled_without_provider", config.HardwareKeysConfig{Enabled: true}, "requires hardware_keys.provider"},
		{"unknown_provider", config.HardwareKeysConfig{Enabled: true, Provider: "usb-toaster"}, "must be secure-enclave or fido2"},
		{"software_key_type_refused", config.HardwareKeysConfig{Enabled: true, Provider: "fido2", KeyType: "ed25519"}, "must be ed25519-sk or ecdsa-sk"},
		{"rsa_key_type_refused", config.HardwareKeysConfig{Enabled: true, Provider: "fido2", KeyType: "rsa"}, "must be ed25519-sk or ecdsa-sk"},
		{"enclave_ed25519_impossible", config.HardwareKeysConfig{Enabled: true, Provider: "secure-enclave", KeyType: "ed25519-sk"}, "impossible on the Secure Enclave"},
		{"application_prefix_enforced", config.HardwareKeysConfig{Enabled: true, Provider: "fido2", Application: "web:evil"}, "must begin with \"ssh:\""},
		{"disabled_bad_enum_still_rejected", config.HardwareKeysConfig{Enabled: false, Provider: "usb-toaster"}, "must be secure-enclave or fido2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *base
			cfg.HardwareKeys = tc.hk
			err := config.Validate(&cfg)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestHardwareKeysConfig_KnownFieldsRejectsWeakeningKeys asserts the schema
// deliberately has NO presence-weakening field: `no_touch_required` (or any
// unknown key) under hardware_keys is rejected by KnownFields(true) — the
// same mechanism that rejects `funnel`.
func TestHardwareKeysConfig_KnownFieldsRejectsWeakeningKeys(t *testing.T) {
	valid, err := os.ReadFile(filepath.Join("testdata", "valid.yaml"))
	require.NoError(t, err)

	t.Run("valid_stanza_loads", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "cfg.yaml")
		body := string(valid) + "\nhardware_keys:\n  enabled: true\n  provider: fido2\n  key_type: ed25519-sk\n"
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		cfg, lErr := config.Load(p)
		require.NoError(t, lErr)
		assert.True(t, cfg.HardwareKeys.Enabled)
		assert.Equal(t, "fido2", cfg.HardwareKeys.Provider)
	})

	t.Run("no_touch_required_rejected", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "cfg.yaml")
		body := string(valid) + "\nhardware_keys:\n  enabled: true\n  provider: fido2\n  no_touch_required: true\n"
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		_, lErr := config.Load(p)
		require.Error(t, lErr, "presence-weakening keys are excluded at the schema level")
	})

	t.Run("software_key_type_rejected_at_load", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "cfg.yaml")
		body := string(valid) + "\nhardware_keys:\n  enabled: true\n  provider: fido2\n  key_type: ed25519\n"
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		_, lErr := config.Load(p)
		require.Error(t, lErr, "a config typo must never silently mint a software key")
	})
}
