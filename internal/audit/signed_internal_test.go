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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSignBytes_LengthPrefixedFraming(t *testing.T) {
	// Canonical layout (WR-01): each variable-length field is preceded by its
	// length as a big-endian uint32, removing the field-boundary ambiguity the
	// old single-NUL separator depended on.
	//
	//	len(title) title len(target) target len(time) time dryRun(1) len(prevHash) prevHash 32 DiffHash
	in := SignInput{Title: "ab", Target: "t", Time: "T", DryRun: true, PrevHash: "p", DiffHash: [32]byte{0xff}}
	got := signBytes(in)

	// First four bytes are the big-endian length of Title ("ab" -> 2).
	assert.Equal(t, uint32(2), binary.BigEndian.Uint32(got[0:4]), "title length prefix")
	assert.Equal(t, "ab", string(got[4:6]), "title bytes follow their length")

	// Total length: 4 length prefixes + field bytes + 1 dryRun byte + 32 digest.
	wantLen := 4 + len("ab") + 4 + len("t") + 4 + len("T") + 1 + 4 + len("p") + 32
	assert.Len(t, got, wantLen)

	// dryRun=true encodes as a single 0x01 byte after the time field.
	dryRunIdx := 4 + len("ab") + 4 + len("t") + 4 + len("T")
	assert.Equal(t, byte(1), got[dryRunIdx], "dry_run true encoded as 0x01")
}

// TestSignBytes_NoBoundaryCollision is the WR-01 regression: two distinct field
// splits that the old NUL separator would serialise identically must now produce
// DIFFERENT signed bytes under length-prefixed framing.
func TestSignBytes_NoBoundaryCollision(t *testing.T) {
	a := SignInput{Title: "a\x00b", Target: "c"}
	b := SignInput{Title: "a", Target: "b\x00c"}
	assert.False(t, bytes.Equal(signBytes(a), signBytes(b)),
		"NUL-containing fields must not collide across the Title/Target boundary")
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

// counterFailStore is a KeychainStore that wraps a *secrets.MockStore but
// overrides Set to fail ONLY for the counter account (counterKeyAccount =
// "audit-counter"). All other operations are delegated to the embedded mock.
// It records whether Delete was called for (counterKeyService, counterKeyAccount).
type counterFailStore struct {
	mu          sync.Mutex
	inner       *secrets.MockStore
	deleteCalledFor map[string]bool // "service\x00account" → true
}

func newCounterFailStore(t *testing.T) *counterFailStore {
	t.Helper()
	inner := secrets.NewMockStore()
	// Pre-seed the HMAC key so NewSigned finds it without calling Set for it.
	require.NoError(t, inner.Set(context.Background(), hmacKeyService, hmacKeyAccount,
		hex.EncodeToString(bytes.Repeat([]byte{1}, 32))))
	return &counterFailStore{inner: inner, deleteCalledFor: make(map[string]bool)}
}

func (s *counterFailStore) Set(ctx context.Context, service, account, secret string) error {
	if service == counterKeyService && account == counterKeyAccount {
		return fmt.Errorf("simulated keychain write failure for counter")
	}
	return s.inner.Set(ctx, service, account, secret)
}

func (s *counterFailStore) Get(ctx context.Context, service, account string) (string, error) {
	return s.inner.Get(ctx, service, account)
}

func (s *counterFailStore) Delete(ctx context.Context, service, account string) error {
	s.mu.Lock()
	s.deleteCalledFor[service+"\x00"+account] = true
	s.mu.Unlock()
	return s.inner.Delete(ctx, service, account)
}

func (s *counterFailStore) wasDeleteCalledFor(service, account string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteCalledFor[service+"\x00"+account]
}

// TestAppend_IncrementCounterFailure_DeletesCounterKey is the AUD-02 RED test:
// when IncrementCounter fails (Set on the counter key returns an error), Append
// must DELETE the counter key so the next ReadCounter returns found=false and
// verifyCounter reports CounterStatus="unknown" instead of "mismatch".
func TestAppend_IncrementCounterFailure_DeletesCounterKey(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := newCounterFailStore(t)

	sa, err := NewSigned(logPath, kc)
	require.NoError(t, err)

	// Append should succeed despite the counter-increment failure (fail-soft
	// contract: only WriteAnchor is fatal).
	ctx := context.Background()
	appendErr := sa.Append(ctx, SignInput{Title: "write", DiffHash: sha256.Sum256([]byte("x"))}, "/etc/a", false)
	require.NoError(t, appendErr, "Append must succeed even when IncrementCounter fails")

	// AUD-02 fix: the counter key must have been deleted so the next Verify
	// reports CounterStatus="unknown" (found=false), not "mismatch".
	assert.True(t, kc.wasDeleteCalledFor(counterKeyService, counterKeyAccount),
		"Append must delete the counter key when IncrementCounter fails to prevent a false mismatch")
}
