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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
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

// writeLegacyField mirrors the internal length-prefixed framing so tests can
// recompute out-of-band signatures (legacy 4-field, wrong-domain, etc.) exactly
// the way identity.go does — big-endian uint64 length prefix, then the bytes.
func writeLegacyField(h hash.Hash, field string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(field)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(field))
}

// signWithFields computes an HMAC-SHA256 over an arbitrary ordered field list,
// used to forge adversarial signatures (legacy layout, wrong domain/version)
// that the production Verify must reject.
func signWithFields(t *testing.T, hexKey string, fields ...string) string {
	t.Helper()
	keyBytes, err := hex.DecodeString(hexKey)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, keyBytes)
	for _, f := range fields {
		writeLegacyField(mac, f)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// TestRigHMAC_GenuineRoundTrip_Verifies is the positive control: a signature
// produced by SignRigMessage verifies under VerifyRigMessage with the same inputs.
func TestRigHMAC_GenuineRoundTrip_Verifies(t *testing.T) {
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)

	sig, err := fleet.SignRigMessage(key, "rigA", "1700000000", "Build done", "hello")
	require.NoError(t, err)
	assert.True(t, fleet.VerifyRigMessage(key, "rigA", "1700000000", "Build done", "hello", sig),
		"genuine round-trip must verify")
}

// TestRigHMAC_CrossRigSharedKey_Rejected is the headline BKLG-03 property: two
// rigs share a key K; a signature produced for rig "A" must NOT verify when
// presented as rig "B", because rigName is a signed length-prefixed field.
func TestRigHMAC_CrossRigSharedKey_Rejected(t *testing.T) {
	sharedKey, err := fleet.GenerateSigningKey()
	require.NoError(t, err)

	const (
		ts      = "1700000000"
		title   = "Build done"
		message = "deploy complete"
	)

	// Rig A signs with the shared key.
	sigA, err := fleet.SignRigMessage(sharedKey, "rigA", ts, title, message)
	require.NoError(t, err)

	// The same key verifies A's message as A (genuine).
	assert.True(t, fleet.VerifyRigMessage(sharedKey, "rigA", ts, title, message, sigA),
		"rig A's own signature must verify for rig A")

	// Substituting rig B — even with the SAME key — must be rejected.
	assert.False(t, fleet.VerifyRigMessage(sharedKey, "rigB", ts, title, message, sigA),
		"cross-rig substitution must be rejected even with a shared key")
}

// TestRigHMAC_ReplayToOtherRig_Rejected replays rig A's exact (ts,title,message,sig)
// tuple against the rig identity a topic-bound verifier expects ("rigB") — it
// must be rejected because the signed payload still binds "rigA".
func TestRigHMAC_ReplayToOtherRig_Rejected(t *testing.T) {
	sharedKey, err := fleet.GenerateSigningKey()
	require.NoError(t, err)

	const (
		ts      = "1700000000"
		title   = "nightly"
		message = "backup ok"
	)
	sigA, err := fleet.SignRigMessage(sharedKey, "rigA", ts, title, message)
	require.NoError(t, err)

	// A receiver that expects rigB on this topic recomputes over "rigB" and rejects.
	assert.False(t, fleet.VerifyRigMessage(sharedKey, "rigB", ts, title, message, sigA),
		"replaying rig A's tuple against expected rig B must be rejected")
}

// TestRigHMAC_OldFormatSig_Rejected enforces the clean format break: a legacy
// 4-field signature (rigName, ts, title, message — no domain/version tags) must
// NOT verify under the new 6-field framing.
func TestRigHMAC_OldFormatSig_Rejected(t *testing.T) {
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)

	const (
		rigName = "rigA"
		ts      = "1700000000"
		title   = "Build done"
		message = "hello"
	)
	// Legacy layout: exactly the pre-BKLG-03 four fields, in order, same key.
	legacySig := signWithFields(t, key, rigName, ts, title, message)

	assert.False(t, fleet.VerifyRigMessage(key, rigName, ts, title, message, legacySig),
		"an old 4-field signature must be rejected (no dual-format fallback)")
}

// TestRigHMAC_WrongDomainOrVersion_Rejected proves cross-protocol/version domain
// separation: a signature computed with a different domain tag or a different
// version tag must not verify as fleet-notify-v1.
func TestRigHMAC_WrongDomainOrVersion_Rejected(t *testing.T) {
	key, err := fleet.GenerateSigningKey()
	require.NoError(t, err)

	const (
		rigName = "rigA"
		ts      = "1700000000"
		title   = "Build done"
		message = "hello"
	)

	// Wrong domain tag (e.g. a hypothetical audit signer reusing the key).
	wrongDomain := signWithFields(t, key, "abysslink-audit-sign", "v1", rigName, ts, title, message)
	assert.False(t, fleet.VerifyRigMessage(key, rigName, ts, title, message, wrongDomain),
		"a signature under a different domain tag must not verify as fleet-notify")

	// Wrong version tag (a future v2 framing under the correct domain).
	wrongVersion := signWithFields(t, key, "abysslink-fleet-notify", "v2", rigName, ts, title, message)
	assert.False(t, fleet.VerifyRigMessage(key, rigName, ts, title, message, wrongVersion),
		"a signature under a different version tag must not verify as v1")

	// Sanity: the correct domain+version DOES verify (control), computed the same way.
	correct := signWithFields(t, key, "abysslink-fleet-notify", "v1", rigName, ts, title, message)
	assert.True(t, fleet.VerifyRigMessage(key, rigName, ts, title, message, correct),
		"the genuine domain+version framing must verify")
}
