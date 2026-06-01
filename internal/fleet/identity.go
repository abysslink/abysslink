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
	"encoding/hex"
	"fmt"
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

// SignRigMessage computes an HMAC-SHA256 signature over the canonical string
//
//	rigName + "." + ts + "." + message
//
// where ts is an epoch-seconds timestamp string. The hexKey parameter is the
// hex-encoded 32-byte signing key returned by GenerateSigningKey (or retrieved
// from the OS keychain). The signature is returned as a lowercase-hex string.
//
// Security: uses crypto/hmac — never hand-rolled MAC (T-14-02). The canonical
// string format ensures the verifier can reconstruct the signed payload given
// the same three components (Pitfall 6: timestamp must be transmitted alongside
// the signature so the receiver can recompute — see D-NI-03).
func SignRigMessage(hexKey, rigName, ts, message string) (string, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", fmt.Errorf("fleet: sign: decode key: %w", err)
	}
	mac := hmac.New(sha256.New, keyBytes)
	_, _ = mac.Write([]byte(rigName + "." + ts + "." + message))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyRigMessage recomputes the HMAC-SHA256 over rigName + "." + ts + "." +
// message and compares it against sigHex using hmac.Equal (constant-time
// comparison, T-14-02). Returns true only when the signature matches exactly.
//
// Security: never use == on MACs — timing side-channel (T-14-02 / CLAUDE.md).
func VerifyRigMessage(hexKey, rigName, ts, message, sigHex string) bool {
	expected, err := SignRigMessage(hexKey, rigName, ts, message)
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
