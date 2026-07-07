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

package secrets_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/secrets"
)

func TestSecureBytes_RoundTripAndWipeSource(t *testing.T) {
	src := []byte("super-secret-hmac-key-material!!")
	want := append([]byte(nil), src...)

	sb := secrets.NewSecureBytes(src)
	t.Cleanup(sb.Destroy)

	require.Equal(t, want, sb.Bytes(), "SecureBytes must preserve the secret")
	// The source slice is wiped in place (caller must not reuse it).
	assert.Equal(t, make([]byte, len(want)), src, "NewSecureBytes must zeroize the caller's slice")
}

func TestSecureBytes_Fingerprint(t *testing.T) {
	secret := []byte("rotate-me")
	sum := sha256.Sum256(secret)
	sb := secrets.NewSecureBytes(append([]byte(nil), secret...))
	t.Cleanup(sb.Destroy)
	assert.Equal(t, hex.EncodeToString(sum[:]), sb.Fingerprint())
}

func TestSecureBytes_DestroyIsIdempotentAndClears(t *testing.T) {
	sb := secrets.NewSecureBytes([]byte("x"))
	sb.Destroy()
	sb.Destroy() // no panic on second destroy
	assert.Nil(t, sb.Bytes(), "Bytes must be nil after Destroy")
	assert.Empty(t, sb.Fingerprint(), "Fingerprint must be empty after Destroy")
}

func TestSecureBytes_Empty(t *testing.T) {
	sb := secrets.NewSecureBytes(nil)
	t.Cleanup(sb.Destroy)
	assert.Empty(t, sb.Bytes())
}

func TestSecureBytes_LockedReportsPosture(t *testing.T) {
	sb := secrets.NewSecureBytes([]byte("k"))
	t.Cleanup(sb.Destroy)
	// On a normal dev/CI box mlock succeeds; in a memlock-constrained container
	// it may not. Either way Locked() must equal MlockAvailable()'s verdict so
	// the doctor check reports the true posture.
	assert.Equal(t, secrets.MlockAvailable(), sb.Locked())
}

func TestSecureBytes_BytesAliasIsUsable(t *testing.T) {
	// A HMAC computation over Bytes() must match the same computation over a
	// plain copy — i.e. the locked bytes are the real secret, not a mangled one.
	secret := bytes.Repeat([]byte{0xAB}, 32)
	sb := secrets.NewSecureBytes(append([]byte(nil), secret...))
	t.Cleanup(sb.Destroy)
	require.Equal(t, secret, sb.Bytes())
}
