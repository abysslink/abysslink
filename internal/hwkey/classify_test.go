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

package hwkey

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyPublicKeyLine_Table(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		hardware bool
		wantErr  bool
	}{
		{"sk_ed25519", "sk-ssh-ed25519@openssh.com AAAAGnNr... host", true, false},
		{"sk_ecdsa", "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr... enclave", true, false},
		{"webauthn_sk", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAA...", true, false},
		{"sk_ed25519_cert", "sk-ssh-ed25519-cert-v01@openssh.com AAAA... id", true, false},
		{"sk_ecdsa_cert", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA...", true, false},
		{"software_ed25519", "ssh-ed25519 AAAAC3Nza... me@rig", false, false},
		{"software_rsa", "ssh-rsa AAAAB3Nza... legacy", false, false},
		{"software_ecdsa", "ecdsa-sha2-nistp256 AAAAE2Vj... agent-served-enclave", false, false},
		{"software_cert", "ssh-ed25519-cert-v01@openssh.com AAAA... signed", false, false},
		{"comment_with_spaces", "ssh-ed25519 AAAA... a comment with spaces", false, false},
		// Fail-closed: unknown/garbage is an ERROR, never Hardware=true and
		// never silently "software".
		{"unknown_token", "quantum-sk-magic@example.com AAAA...", false, true},
		{"garbage", "not a key at all", false, true},
		{"single_field", "sk-ssh-ed25519@openssh.com", false, true},
		{"empty", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ClassifyPublicKeyLine(tc.line)
			if tc.wantErr {
				require.Error(t, err)
				assert.False(t, info.Hardware, "a parse miss must NEVER classify as hardware")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.hardware, info.Hardware)
		})
	}
	t.Run("comment_captured", func(t *testing.T) {
		info, err := ClassifyPublicKeyLine("sk-ssh-ed25519@openssh.com AAAA abysslink-rig key")
		require.NoError(t, err)
		assert.Equal(t, "abysslink-rig key", info.Comment)
		assert.Equal(t, "sk-ssh-ed25519@openssh.com", info.TypeToken)
	})
}

func TestParseKeygenListLine(t *testing.T) {
	t.Run("ed25519_sk", func(t *testing.T) {
		info, err := ParseKeygenListLine("256 SHA256:Aqp2Fs0y1Wl0M/qWjLYzBFPXwCJ0vC6H0G3Yc1nQwUM me@rig (ED25519-SK)")
		require.NoError(t, err)
		assert.True(t, info.Hardware)
		assert.Equal(t, "ED25519-SK", info.TypeToken)
		assert.Equal(t, "SHA256:Aqp2Fs0y1Wl0M/qWjLYzBFPXwCJ0vC6H0G3Yc1nQwUM", info.Fingerprint)
		assert.Equal(t, "me@rig", info.Comment)
	})
	t.Run("software_ed25519", func(t *testing.T) {
		info, err := ParseKeygenListLine("256 SHA256:abcdefg me@rig (ED25519)")
		require.NoError(t, err)
		assert.False(t, info.Hardware)
	})
	t.Run("no_comment_fallback", func(t *testing.T) {
		info, err := ParseKeygenListLine("256 SHA256:abcdefg no comment (ECDSA-SK)")
		require.NoError(t, err)
		assert.True(t, info.Hardware)
		assert.Equal(t, "no comment", info.Comment)
	})
	t.Run("spacey_comment_parse_from_right", func(t *testing.T) {
		info, err := ParseKeygenListLine("256 SHA256:abcdefg a comment (with) spaces (ED25519-SK)")
		require.NoError(t, err)
		assert.True(t, info.Hardware)
		assert.Equal(t, "a comment (with) spaces", info.Comment)
	})
	t.Run("md5_form", func(t *testing.T) {
		info, err := ParseKeygenListLine("2048 MD5:aa:bb:cc:dd me@rig (RSA)")
		require.NoError(t, err)
		assert.False(t, info.Hardware)
	})
	t.Run("sk_cert_assumed_token", func(t *testing.T) {
		info, err := ParseKeygenListLine("256 SHA256:abcdefg me@rig (ED25519-SK-CERT)")
		require.NoError(t, err)
		assert.True(t, info.Hardware)
	})
	t.Run("unknown_shortname_fails_closed", func(t *testing.T) {
		info, err := ParseKeygenListLine("256 SHA256:abcdefg me@rig (QUANTUM9)")
		require.Error(t, err)
		assert.False(t, info.Hardware)
	})
	t.Run("garbage_fails_closed", func(t *testing.T) {
		_, err := ParseKeygenListLine("keygen exploded")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrParse)
	})
	t.Run("empty_fails_closed", func(t *testing.T) {
		_, err := ParseKeygenListLine("")
		require.Error(t, err)
	})
}

// TestMockProviderContract pins MockProvider to the Provider interface.
func TestMockProviderContract(t *testing.T) {
	var _ Provider = NewMockProvider()
	m := NewMockProvider()
	assert.Equal(t, KindFIDO2, m.Kind(), "unset kind defaults to fido2")
	m.ProviderKind = KindSecureEnclave
	assert.Equal(t, KindSecureEnclave, m.Kind())
}
