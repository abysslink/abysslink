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

package fleet

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
)

// Domain-separation tags for the fleet-notify HMAC framing (BKLG-03). These
// constants are prepended (as length-prefixed fields) to every signed message so
// a fleet-notify-v1 signature cannot be confused with any other HMAC use of the
// same key (a future audit signer, a v2 format, a different channel). The version
// tag makes any future framing change a clean, explicit bump (v2) with a built-in
// discriminator — no silent reinterpretation, no dual-format fallback.
const (
	fleetNotifyDomain  = "abysslink-fleet-notify" // protocol domain-separation tag
	fleetNotifyVersion = "v1"                     // notify signature format version
)

// RigService returns the per-rig keychain service name for a given rig name.
// The returned string is used as the `service` parameter to secrets.KeychainStore
// methods, providing per-rig secret isolation (D-KN-01).
//
// Example: RigService("laptop") → "abysslink-rig-laptop"
func RigService(name string) string {
	return "abysslink-rig-" + name
}

// GenerateSigningKey generates a 32-byte HMAC signing key using crypto/rand (CSPRNG)
// and returns it as a 64-character lowercase-hex string. The returned key is
// suitable for storage in the OS keychain (never on disk or in yaml/audit).
//
// Security: uses crypto/rand exclusively — math/rand is forbidden (T-14-03).
func GenerateSigningKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("fleet: generate signing key: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// SignRigMessage computes an HMAC-SHA256 signature over six length-prefixed
// fields, in this exact order (BKLG-03):
//
//	fleetNotifyDomain, fleetNotifyVersion, rigName, ts, title, message
//
// each written as a length-prefixed field (big-endian uint64 byte length,
// then the bytes — the internal/gate writeField idiom), where ts is an
// epoch-seconds timestamp string and title is the notification subject
// (X-Title header). The two leading domain/version tags are internal constants,
// so the public signature is unchanged and callers pass only the four canonical
// components. The hexKey parameter is the hex-encoded 32-byte signing key
// returned by GenerateSigningKey (or retrieved from the OS keychain). The
// signature is returned as a lowercase-hex string.
//
// Security: uses crypto/hmac — never hand-rolled MAC (T-14-02). Length
// prefixes make the field join unambiguous: a plain delimiter join would let
// a relay shift bytes across the title/message boundary (e.g. when a title
// contains the delimiter) without breaking the signature. The canonical
// format ensures the verifier can reconstruct the signed payload given the
// same four components (Pitfall 6: timestamp must be transmitted alongside
// the signature so the receiver can recompute — see D-NI-03).
//
// BKLG-03 domain separation: the fixed domain tag + version are folded into the
// MAC input so a fleet-notify-v1 signature cannot verify under any other
// protocol/version framing, and cross-rig substitution changes the MAC (rigName
// is a signed length-prefixed field) even when two rigs share a key. This is a
// deliberate, clean format break from the earlier 4-field framing: signatures are
// transient (never persisted), so old-format sigs simply fail verification with
// no dual-format fallback (which would reintroduce a downgrade surface).
//
// WR-02: title is included so a relay cannot alter X-Title (the displayed subject
// on the phone) without invalidating the HMAC signature.
func SignRigMessage(hexKey, rigName, ts, title, message string) (string, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("fleet: sign: decode key: %w", err)
	}
	mac := hmac.New(sha256.New, keyBytes)
	for _, field := range []string{fleetNotifyDomain, fleetNotifyVersion, rigName, ts, title, message} {
		writeRigField(mac, field)
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// writeRigField writes one length-prefixed field (big-endian uint64 byte
// length, then the bytes) into h, mirroring internal/gate's writeField.
// hash.Hash Write never returns an error.
func writeRigField(h hash.Hash, field string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(field)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(field))
}

// VerifyRigMessage recomputes the HMAC-SHA256 over the same six length-prefixed
// fields (fleetNotifyDomain, fleetNotifyVersion, rigName, ts, title, message —
// see SignRigMessage) and compares it against sigHex using hmac.Equal
// (constant-time comparison, T-14-02). Returns true only when the signature
// matches exactly. Because Verify recomputes via Sign, the domain/version tags
// are applied identically on both sides: a signature made under a different
// domain/version, or an old 4-field signature, recomputes a different expected
// MAC and is rejected.
//
// Security: never use == on MACs — timing side-channel (T-14-02 / CLAUDE.md).
func VerifyRigMessage(hexKey, rigName, ts, title, message, sigHex string) bool {
	expected, err := SignRigMessage(hexKey, rigName, ts, title, message)
	if err != nil {
		return false
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	receivedBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return hmac.Equal(expectedBytes, receivedBytes)
}
