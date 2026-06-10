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

package fleet_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/fleet"
)

// TestIdentity_HMAC verifies HMAC signing and tamper detection.
// WR-02: the canonical string covers the length-prefixed fields
// rigName, ts, title, message (see SignRigMessage).
func TestIdentity_HMAC(t *testing.T) {
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)

	rigName := "rigA"
	ts := "1700000000"
	title := "Build done"
	message := "hello"

	sig, err := fleet.SignRigMessage(key, rigName, ts, title, message)
	require.NoError(t, err)
	assert.NotEmpty(t, sig, "signature must not be empty")

	// Stable: recomputing with same inputs yields identical signature.
	sig2, err := fleet.SignRigMessage(key, rigName, ts, title, message)
	require.NoError(t, err)
	assert.Equal(t, sig, sig2, "same inputs must produce identical HMAC")

	// Signature must be lowercase hex.
	assert.Regexp(t, `^[0-9a-f]+$`, sig, "signature must be lowercase hex")

	// Tamper detection: altering rig-name returns false.
	ok := fleet.VerifyRigMessage(key, "rigB", ts, title, message, sig)
	assert.False(t, ok, "tampered rig-name must fail verification")

	// Tamper detection: altering timestamp returns false.
	ok = fleet.VerifyRigMessage(key, rigName, "9999999999", title, message, sig)
	assert.False(t, ok, "tampered timestamp must fail verification")

	// Tamper detection: altering title returns false (WR-02: title is now signed).
	ok = fleet.VerifyRigMessage(key, rigName, ts, "tampered subject", message, sig)
	assert.False(t, ok, "tampered title must fail verification (WR-02)")

	// Tamper detection: altering message returns false.
	ok = fleet.VerifyRigMessage(key, rigName, ts, title, "world", sig)
	assert.False(t, ok, "tampered message must fail verification")

	// Correct inputs verify successfully.
	ok = fleet.VerifyRigMessage(key, rigName, ts, title, message, sig)
	assert.True(t, ok, "unaltered inputs must verify")
}

// TestIdentity_HMAC_FieldBoundaryUnambiguous verifies the canonical string is
// length-prefixed: with the old "."-joined canonical, fields containing "."
// let a relay shift bytes across the title/message boundary without breaking
// the signature (e.g. title "a.b" + message "c" collided with title "a" +
// message "b.c"). Length prefixes make every split distinct.
func TestIdentity_HMAC_FieldBoundaryUnambiguous(t *testing.T) {
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)

	const (
		rigName = "rigA"
		ts      = "1700000000"
	)

	// Old dot-joined canonical: both splits produced "rigA.1700000000.a.b.c".
	sig, err := fleet.SignRigMessage(key, rigName, ts, "a.b", "c")
	require.NoError(t, err)
	assert.False(t, fleet.VerifyRigMessage(key, rigName, ts, "a", "b.c", sig),
		"shifting bytes across the title/message boundary must invalidate the signature")
	assert.True(t, fleet.VerifyRigMessage(key, rigName, ts, "a.b", "c", sig),
		"the genuine split must still verify")

	// Empty-field shift: ("x.", "") vs ("x", ".") collided under the old join.
	sig2, err := fleet.SignRigMessage(key, rigName, ts, "x.", "")
	require.NoError(t, err)
	assert.False(t, fleet.VerifyRigMessage(key, rigName, ts, "x", ".", sig2),
		"moving a delimiter byte between title and an empty message must invalidate the signature")

	// rig/ts boundary: ("rigA.1", "700") vs ("rigA", "1.700") collided too.
	sig3, err := fleet.SignRigMessage(key, "rigA.1", "700", "t", "m")
	require.NoError(t, err)
	assert.False(t, fleet.VerifyRigMessage(key, "rigA", "1.700", "t", "m", sig3),
		"shifting bytes across the rig/ts boundary must invalidate the signature")
}

// TestGenerateSigningKey verifies key generation is cryptographically random.
func TestGenerateSigningKey(t *testing.T) {
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)

	// 32 raw bytes = 64 hex characters.
	assert.Len(t, key, 64, "GenerateSigningKey must return a 64-char hex string")
	assert.Regexp(t, `^[0-9a-f]+$`, key, "key must be lowercase hex")

	// Two successive calls must differ (CSPRNG, not deterministic).
	key2, err := fleet.GenerateSigningKey()
	require.NoError(t, err)
	assert.NotEqual(t, key, key2, "successive GenerateSigningKey calls must differ")
}

// TestRigService verifies the per-rig keychain service name helper.
func TestRigService(t *testing.T) {
	assert.Equal(t, "abysslink-rig-laptop", fleet.RigService("laptop"))
	assert.Equal(t, "abysslink-rig-workstation", fleet.RigService("workstation"))
}
