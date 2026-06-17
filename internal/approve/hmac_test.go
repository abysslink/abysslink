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

package approve

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testKey() []byte {
	return []byte("test-key-for-approve-hmac-32bytes!!")
}

// TestHMAC_RoundTrip: SignApproveURL then VerifyApproveURL with same key
// returns true.
func TestHMAC_RoundTrip(t *testing.T) {
	t.Parallel()
	key := testKey()
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	sig := SignApproveURL(key, "req-001", "approve", hash)
	assert.NotEmpty(t, sig, "signature must be non-empty")
	ok := VerifyApproveURL(key, "req-001", "approve", hash, sig)
	assert.True(t, ok, "round-trip must verify")
}

// TestHMAC_ActionMismatch: sign with "approve", verify with "deny" returns false.
func TestHMAC_ActionMismatch(t *testing.T) {
	t.Parallel()
	key := testKey()
	var hash [32]byte
	sig := SignApproveURL(key, "req-002", "approve", hash)
	ok := VerifyApproveURL(key, "req-002", "deny", hash, sig)
	assert.False(t, ok, "signature for 'approve' must not verify under 'deny'")
}

// TestHMAC_ConstantTime: passing a bad sig returns false (tests the constant-time
// path without inspecting internals).
func TestHMAC_ConstantTime(t *testing.T) {
	t.Parallel()
	key := testKey()
	var hash [32]byte
	badSig := "0000000000000000000000000000000000000000000000000000000000000000"
	ok := VerifyApproveURL(key, "req-003", "approve", hash, badSig)
	assert.False(t, ok, "a bad sig must return false")
}

// TestHMAC_WrongKey: verify with wrong key returns false.
func TestHMAC_WrongKey(t *testing.T) {
	t.Parallel()
	key := testKey()
	var hash [32]byte
	sig := SignApproveURL(key, "req-004", "approve", hash)
	ok := VerifyApproveURL([]byte("wrong-key"), "req-004", "approve", hash, sig)
	assert.False(t, ok, "wrong key must not verify")
}

// TestHMAC_ClosureHashMismatch: flipping one bit of the closure hash invalidates
// the signature.
func TestHMAC_ClosureHashMismatch(t *testing.T) {
	t.Parallel()
	key := testKey()
	var hash [32]byte
	sig := SignApproveURL(key, "req-005", "approve", hash)
	hash[0] ^= 0x01 // flip one bit
	ok := VerifyApproveURL(key, "req-005", "approve", hash, sig)
	assert.False(t, ok, "modified closure hash must not verify")
}

// TestHMAC_MalformedHex: VerifyApproveURL with non-hex sig returns false safely.
func TestHMAC_MalformedHex(t *testing.T) {
	t.Parallel()
	key := testKey()
	var hash [32]byte
	ok := VerifyApproveURL(key, "req-006", "approve", hash, "not-hex-!!")
	assert.False(t, ok, "malformed hex must return false")
}
