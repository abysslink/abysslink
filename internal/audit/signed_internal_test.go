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

package audit

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeSig_HexLength(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	sig := computeSig(key, SignInput{Title: "write", DiffHash: sha256.Sum256([]byte("x"))})
	assert.Len(t, sig, 64) // 32-byte HMAC-SHA256 hex-encoded
}

func TestVerifyHMAC_MatchAndMismatch(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	wrongKey := bytes.Repeat([]byte{2}, 32)
	in := SignInput{Title: "write", DiffHash: sha256.Sum256([]byte("x"))}
	sig := computeSig(key, in)

	assert.True(t, verifyHMAC(key, in, sig), "matching key+sig should verify")
	assert.False(t, verifyHMAC(wrongKey, in, sig), "wrong key must not verify")
	assert.False(t, verifyHMAC(key, in, "deadbeef"), "truncated sig must not verify")
	assert.False(t, verifyHMAC(key, in, "zz"), "non-hex sig must not verify")
	assert.False(t, verifyHMAC(key, in, ""), "empty sig must not verify")
	assert.False(t, verifyHMAC(key, SignInput{Title: "other", DiffHash: in.DiffHash}, sig),
		"wrong title must not verify")
}

func TestSignBytes_NullSeparator(t *testing.T) {
	// Canonical layout (CR-03): title \0 target \0 time \0 dryRun \0 prevHash \0 32 DiffHash bytes.
	in := SignInput{Title: "ab", Target: "t", Time: "T", DryRun: true, PrevHash: "p", DiffHash: [32]byte{0xff}}
	got := signBytes(in)
	assert.Equal(t, byte(0x00), got[2], "null byte separator after title")
	// 2(title) +1 +1(target) +1 +1(time) +1 +1(dryRun) +1 +1(prevHash) +1 +32(digest)
	wantLen := len("ab") + 1 + len("t") + 1 + len("T") + 1 + 1 + 1 + len("p") + 1 + 32
	assert.Len(t, got, wantLen)
	assert.Equal(t, byte(1), got[len("ab")+1+len("t")+1+len("T")+1], "dry_run true encoded as 0x01")
}

func TestSignBytes_CoversAllMetadataFields(t *testing.T) {
	// CR-03: flipping any signed metadata field must change the HMAC input.
	base := SignInput{Title: "write", Target: "/etc/a", Time: "2026-01-01T00:00:00Z", DryRun: false, PrevHash: "genesis", DiffHash: sha256.Sum256([]byte("x"))}
	b0 := signBytes(base)

	mutators := []func(in SignInput) SignInput{
		func(in SignInput) SignInput { in.Title = "delete"; return in },
		func(in SignInput) SignInput { in.Target = "/etc/b"; return in },
		func(in SignInput) SignInput { in.Time = "2027-01-01T00:00:00Z"; return in },
		func(in SignInput) SignInput { in.DryRun = true; return in },
		func(in SignInput) SignInput { in.PrevHash = "deadbeef"; return in },
	}
	for i, m := range mutators {
		assert.False(t, bytes.Equal(b0, signBytes(m(base))), "mutator %d must change signed bytes", i)
	}
}
