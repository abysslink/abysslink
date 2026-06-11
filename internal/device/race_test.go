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

package device_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/secrets"
)

// touchWriteWindow mirrors the unexported touchWriteInterval (60s) from the
// device package: the minimum gap between persisted LastSeen updates. The tests
// advance the clock by multiples of it so every touch is genuinely
// write-warranted and actually contends with a concurrent revoke.
const touchWriteWindow = 60 * time.Second

// twoProcessFixture models the production split: a daemon Store (D) and a CLI
// Store (C) over the SAME devices.json, sharing the SAME audit log (so they
// share the cross-process flock) and the SAME keychain (so they see the same
// SSH CA and, with a signed writer, the same HMAC key). Each *device.Store
// stands in for a separate process; the only thing they share on disk is the
// records file and the audit log + its sibling .lock.
type twoProcessFixture struct {
	devPath string
	logPath string
	kc      *secrets.MockStore
	clk     *fakeClock
	d       *device.Store // "daemon": runs TouchLastSeen on the hot path
	c       *device.Store // "cli":    runs Revoke / RevokeAll
}

// newTwoProcessFixture builds the fixture with a real audit writer so the
// cross-process flock is genuinely exercised. signed selects NewSigned (HMAC
// hash-chain, so audit.Verify can prove the chain survived concurrent writes)
// vs. New (legacy unsigned JSONL).
func newTwoProcessFixture(t *testing.T, signed bool) *twoProcessFixture {
	t.Helper()
	dir := t.TempDir()
	devPath := filepath.Join(dir, "devices.json")
	logPath := filepath.Join(dir, "audit.log")
	kc := secrets.NewMockStore()
	clk := newFakeClock()

	newWriter := func() device.AuditWriter {
		if signed {
			sa, err := audit.NewSigned(logPath, kc)
			require.NoError(t, err)
			return sa
		}
		return audit.NewWithKeychain(logPath, kc)
	}

	return &twoProcessFixture{
		devPath: devPath,
		logPath: logPath,
		kc:      kc,
		clk:     clk,
		// Two independent Stores, two independent audit writers — exactly like
		// two processes. They converge only on the shared files.
		d: device.New(devPath, newWriter(), kc, clk.Now),
		c: device.New(devPath, newWriter(), kc, clk.Now),
	}
}

// TestRace_TouchDoesNotRevertRevoke is the deterministic reproduction of the
// reported MEDIUM: a stale daemon TouchLastSeen must not overwrite a CLI
// revocation that landed after the daemon last loaded the file.
//
// Interleaving (forced by sequencing the calls, not by luck):
//  1. D enrolls "phone" and warms its in-process cache to the PRE-revoke state.
//  2. C revokes "phone" — bearer hash blanked, file rewritten on disk.
//  3. The clock advances past the 60s touch rate-limit so D's next touch is
//     genuinely write-warranted (else the rate-limit would mask the bug).
//  4. D.TouchLastSeen runs while D's cache still says "active". With the fix it
//     re-reads under the flock, sees Revoked, and writes nothing.
//
// Without the fix, step 4 would clone D's stale cache, bump LastSeen, and write
// it back — resurrecting the revoked bearer.
func TestRace_TouchDoesNotRevertRevoke(t *testing.T) {
	ctx := context.Background()
	f := newTwoProcessFixture(t, false)

	bundle, err := f.d.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	id := mustGetID(t, f.d, "phone")

	// D warms its cache to the active state and records an initial check-in so
	// the device has a non-zero LastSeen we can later make stale.
	require.NoError(t, f.d.TouchLastSeen(ctx, id, f.clk.Now()))
	rec, ok := f.d.Get("phone")
	require.True(t, ok)
	require.False(t, rec.Revoked, "precondition: device active before revoke")

	// C revokes out-of-band (separate Store == separate process).
	require.NoError(t, f.c.Revoke(ctx, "phone"))

	// Advance the clock so D's touch is past the rate-limit window and will try
	// to write. D's in-process cache is still the pre-revoke clone.
	f.clk.Set(f.clk.Now().Add(2 * touchWriteWindow))
	require.NoError(t, f.d.TouchLastSeen(ctx, id, f.clk.Now()))

	// The revocation must survive: re-read from a fresh Store (a third
	// "process") so we assert on-disk truth, not any one cache.
	fresh := device.New(f.devPath, audit.NewWithKeychain(f.logPath, f.kc), f.kc, f.clk.Now)
	got, ok := fresh.Get("phone")
	require.True(t, ok)
	assert.True(t, got.Revoked, "revoke must NOT be reverted by the stale daemon touch")
	_, ok = fresh.VerifyBearer(bundle.Bearer)
	assert.False(t, ok, "leaked bearer must stay unauthenticated after the touch")
}

// TestRace_ConcurrentTouchVsRevoke stresses N concurrent daemon TouchLastSeen
// calls racing one CLI Revoke, over many trials, under -race. Every trial must
// end with the device revoked and the leaked bearer dead. The fix guarantees
// this because every touch's write is a read-modify-write under the same
// cross-process flock the revoke uses, so a touch can never commit on top of a
// state it did not observe the revoke in.
func TestRace_ConcurrentTouchVsRevoke(t *testing.T) {
	ctx := context.Background()

	const trials = 25
	const touchers = 8

	for trial := 0; trial < trials; trial++ {
		f := newTwoProcessFixture(t, false)
		bundle, err := f.d.Enroll(ctx, "phone", "phone")
		require.NoError(t, err)
		id := mustGetID(t, f.d, "phone")

		// Push every touch past the rate-limit so they all attempt a write and
		// genuinely contend with the revoke.
		base := f.clk.Now().Add(10 * touchWriteWindow)

		var wg sync.WaitGroup
		start := make(chan struct{})

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = f.c.Revoke(ctx, "phone")
		}()

		for i := 0; i < touchers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				// Each toucher uses a distinct, ever-advancing instant so the
				// freshness check never short-circuits the write.
				when := base.Add(time.Duration(i) * touchWriteWindow)
				_ = f.d.TouchLastSeen(ctx, id, when)
			}(i)
		}

		close(start)
		wg.Wait()

		fresh := device.New(f.devPath, audit.NewWithKeychain(f.logPath, f.kc), f.kc, f.clk.Now)
		got, ok := fresh.Get("phone")
		require.True(t, ok, "trial %d: record must exist", trial)
		require.True(t, got.Revoked, "trial %d: revoke must survive every concurrent touch", trial)
		_, ok = fresh.VerifyBearer(bundle.Bearer)
		require.False(t, ok, "trial %d: leaked bearer must stay dead", trial)
	}
}

// TestRace_AuditChainIntactUnderConcurrentWrites proves the cross-process flock
// keeps the SIGNED audit chain coherent when two "processes" append/write
// concurrently: interleaved appends would otherwise fork the hash chain or
// corrupt a JSONL line. After a storm of concurrent device mutations through
// two signed writers sharing one log, audit.Verify must report OK with no
// truncation.
func TestRace_AuditChainIntactUnderConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	f := newTwoProcessFixture(t, true)

	// Seed a few devices (serially, to get stable ids).
	ids := make([]string, 0, 4)
	for _, name := range []string{"phone", "tablet", "watch", "laptop"} {
		_, err := f.d.Enroll(ctx, name, "phone")
		require.NoError(t, err)
		ids = append(ids, mustGetID(t, f.d, name))
	}

	base := f.clk.Now().Add(10 * touchWriteWindow)
	var wg sync.WaitGroup
	start := make(chan struct{})

	// D: many concurrent touches across devices (each a real write).
	for i, id := range ids {
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func(id string, k int) {
				defer wg.Done()
				<-start
				_ = f.d.TouchLastSeen(ctx, id, base.Add(time.Duration(k)*touchWriteWindow))
			}(id, i*4+j+1)
		}
	}
	// C: revoke two of them concurrently.
	for _, name := range []string{"watch", "laptop"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			<-start
			_ = f.c.Revoke(ctx, name)
		}(name)
	}

	close(start)
	wg.Wait()

	res, err := audit.Verify(ctx, f.logPath, f.kc)
	require.NoError(t, err)
	assert.True(t, res.OK, "audit chain must stay valid after concurrent writes: %s", res.Reason)
	assert.False(t, res.TruncationDetected, "no entries may be lost to interleaving")
}

// mustGetID resolves a device name to its stable ID.
func mustGetID(t *testing.T, s *device.Store, name string) string {
	t.Helper()
	rec, ok := s.Get(name)
	require.True(t, ok, "device %q must exist", name)
	return rec.ID
}
