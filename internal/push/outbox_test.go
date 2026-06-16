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

package push

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bbolt "go.etcd.io/bbolt"

	"github.com/abysslink/abysslink/internal/notifyv2"
)

// openTestDB opens a temporary bbolt database for testing and registers cleanup.
func openTestDB(t *testing.T) *bbolt.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.Open(filepath.Join(dir, "test.db"), 0o600, &bbolt.Options{Timeout: time.Second})
	require.NoError(t, err, "open test bbolt DB")
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

// sampleEntry returns an outboxEntry for use in tests.
// ProviderToken contains a fake token — never logged.
func sampleEntry(msgID string) outboxEntry {
	return outboxEntry{
		Platform:       "unifiedpush",
		ProviderToken:  "https://ntfy.example.com/device-abc", // secret-class in prod
		MsgID:          msgID,
		Title:          "needs input",
		MetaJSON:       `{"v":2,"kind":"needs_input"}`,
		Attempts:       0,
		FirstTriedUnix: time.Now().Unix(),
		NextRetryUnix:  time.Now().Add(5 * time.Second).Unix(),
		CollapseID:     "aabbccdd00112233aabbccdd00112233",
	}
}

// TestOutboxEnqueueDequeue verifies that an enqueued entry is stored and
// then removed by Dequeue, leaving no key in the bucket.
func TestOutboxEnqueueDequeue(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	deviceID := "device-001"
	msgID := "01J7MSG000000000000000001"

	entry := sampleEntry(msgID)
	require.NoError(t, o.Enqueue(deviceID, entry), "enqueue must succeed")

	// Verify the key exists in the outbox bucket.
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketOutbox)
		require.NotNil(t, b, "outbox bucket must exist after Enqueue")
		v := b.Get(outboxKey(deviceID, msgID))
		assert.NotNil(t, v, "outbox key must exist after Enqueue")
		return nil
	})
	require.NoError(t, err)

	// Dequeue and verify the key is gone.
	require.NoError(t, o.Dequeue(deviceID, msgID), "dequeue must succeed")
	err = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketOutbox)
		if b == nil {
			return nil // bucket gone is also fine
		}
		v := b.Get(outboxKey(deviceID, msgID))
		assert.Nil(t, v, "outbox key must be absent after Dequeue")
		return nil
	})
	require.NoError(t, err)
}

// TestOutboxDequeueNonExistent verifies that dequeuing a non-existent entry
// does not return an error.
func TestOutboxDequeueNonExistent(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	err := o.Dequeue("device-ghost", "msg-ghost")
	assert.NoError(t, err, "dequeue of non-existent entry must not error")
}

// TestOutboxEnqueueMultipleDevices verifies D-09: one device's entries do not
// interfere with another's.
func TestOutboxEnqueueMultipleDevices(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	e1 := sampleEntry("msg-A")
	e2 := sampleEntry("msg-B")

	require.NoError(t, o.Enqueue("dev-1", e1))
	require.NoError(t, o.Enqueue("dev-2", e2))
	require.NoError(t, o.Dequeue("dev-1", "msg-A"))

	// dev-2's entry must still be present.
	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketOutbox)
		require.NotNil(t, b)
		v := b.Get(outboxKey("dev-2", "msg-B"))
		assert.NotNil(t, v, "dev-2 entry must survive after dev-1 dequeue")
		return nil
	})
	require.NoError(t, err)
}

// TestDedupSeen verifies the dedup lifecycle:
// mark → DedupSeen returns true → TTL-expire logic.
func TestDedupSeen(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	msgID := "msg-dedup-01"

	// Not yet marked — must be false.
	seen, err := o.DedupSeen(msgID)
	require.NoError(t, err)
	assert.False(t, seen, "unseen msgID must return false")

	// Mark with a 24h TTL.
	require.NoError(t, o.MarkSeen(msgID, dedupTTL), "MarkSeen must succeed")

	// Now must be seen.
	seen, err = o.DedupSeen(msgID)
	require.NoError(t, err)
	assert.True(t, seen, "just-marked msgID must return true")
}

// TestDedupSweep verifies that SweepDedup removes expired entries but keeps
// live ones.
func TestDedupSweep(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)

	// Mark one with a very short TTL (already expired).
	require.NoError(t, o.MarkSeen("msg-expired", -time.Second))
	// Mark one with a normal TTL (still live).
	require.NoError(t, o.MarkSeen("msg-live", dedupTTL))

	// Sweep.
	require.NoError(t, o.SweepDedup())

	// Expired entry must be gone.
	seen, err := o.DedupSeen("msg-expired")
	require.NoError(t, err)
	assert.False(t, seen, "expired entry must be swept away")

	// Live entry must remain.
	seen, err = o.DedupSeen("msg-live")
	require.NoError(t, err)
	assert.True(t, seen, "live entry must survive the sweep")
}

// TestDedupSweepEmptyBucket verifies SweepDedup is a no-op when the bucket is empty.
func TestDedupSweepEmptyBucket(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	assert.NoError(t, o.SweepDedup(), "sweep on empty DB must not error")
}

// TestOutboxSurvivesRestart proves the PUSH-02 "survive daemon restart" clause:
// dedup marks, the per-device ceiling count, and queued outbox entries all live
// in the bbolt file, so a process restart (close + reopen the same path) must
// preserve them. This guards against an accidental regression to in-memory
// state, which would silently re-allow deduped wakes and reset the ceiling on
// every daemon bounce.
func TestOutboxSurvivesRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "restart.db")
	open := func() *bbolt.DB {
		db, err := bbolt.Open(dbPath, 0o600, &bbolt.Options{Timeout: time.Second})
		require.NoError(t, err, "open bbolt at %s", dbPath)
		return db
	}

	const deviceID = "dev-restart"
	const limit = 2

	// --- First "process": write dedup, fill the ceiling, queue an entry. ---
	o1 := NewOutbox(open())
	require.NoError(t, o1.MarkSeen("msg-persist", dedupTTL))
	require.NoError(t, o1.CeilingIncr(deviceID, limit)) // count=1
	require.NoError(t, o1.CeilingIncr(deviceID, limit)) // count=2 == limit
	require.NoError(t, o1.Enqueue(deviceID, sampleEntry("msg-persist")))
	require.NoError(t, o1.db.Close(), "close DB to simulate daemon shutdown")

	// --- Second "process": reopen the SAME file. ---
	o2 := NewOutbox(open())
	t.Cleanup(func() { _ = o2.db.Close() })

	// Dedup mark survived: a re-delivery of msg-persist is still deduped.
	seen, err := o2.DedupSeen("msg-persist")
	require.NoError(t, err)
	assert.True(t, seen, "dedup mark must survive restart")

	// Ceiling count survived: the device is still at the limit, so a
	// non-exempt wake is rejected (the restart did not reset the window).
	allowed, err := o2.CeilingCheck(deviceID, notifyv2.KindNeedsInput)
	require.NoError(t, err)
	assert.False(t, allowed, "ceiling count must survive restart (still at limit)")

	// approval_request stays exempt across the restart.
	allowed, err = o2.CeilingCheck(deviceID, notifyv2.KindApprovalRequest)
	require.NoError(t, err)
	assert.True(t, allowed, "approval_request must remain exempt after restart")

	// Queued outbox entry survived: the bbolt key persists and decodes back to
	// the same entry (read via raw View — Dequeue only deletes, no read-back API).
	var got outboxEntry
	var found bool
	require.NoError(t, o2.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketOutbox)
		if b == nil {
			return nil
		}
		v := b.Get(outboxKey(deviceID, "msg-persist"))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &got)
	}))
	require.True(t, found, "queued outbox entry must survive restart")
	assert.Equal(t, "msg-persist", got.MsgID)
}

// TestCeilingCheck verifies the per-device ceiling enforcement:
// count=59 → allowed; count=60 → not allowed; approval_request always allowed.
func TestCeilingCheck(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	deviceID := "dev-ceiling"

	// approval_request is always allowed regardless of ceiling state.
	allowed, err := o.CeilingCheck(deviceID, notifyv2.KindApprovalRequest)
	require.NoError(t, err)
	assert.True(t, allowed, "approval_request must always be allowed (exempt)")

	// Fill ceiling to 59 wakes.
	for i := 0; i < 59; i++ {
		require.NoError(t, o.CeilingIncr(deviceID, defaultCeiling))
	}

	// 59th wake: still under ceiling (count < 60).
	allowed, err = o.CeilingCheck(deviceID, notifyv2.KindNeedsInput)
	require.NoError(t, err)
	assert.True(t, allowed, "count=59 must be allowed (< 60)")

	// 60th incr: hit the ceiling.
	require.NoError(t, o.CeilingIncr(deviceID, defaultCeiling))
	allowed, err = o.CeilingCheck(deviceID, notifyv2.KindNeedsInput)
	require.NoError(t, err)
	assert.False(t, allowed, "count=60 must be rejected (>= ceiling)")

	// approval_request still allowed even when ceiling is hit.
	allowed, err = o.CeilingCheck(deviceID, notifyv2.KindApprovalRequest)
	require.NoError(t, err)
	assert.True(t, allowed, "approval_request must remain allowed past ceiling")
}

// TestCeilingCheckFreshDevice verifies that a device with no ceiling entry is allowed.
func TestCeilingCheckFreshDevice(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	allowed, err := o.CeilingCheck("brand-new-device", notifyv2.KindCommandDone)
	require.NoError(t, err)
	assert.True(t, allowed, "fresh device with no ceiling entry must be allowed")
}

// TestCeilingWindowReset verifies that a new window starts when the current window expires.
func TestCeilingWindowReset(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	deviceID := "dev-reset"

	// Manually insert a ceiling entry with a window that started 2 hours ago
	// so it has already expired (window_start + 3600 < now).
	twoHoursAgo := time.Now().Add(-2 * time.Hour).Unix()
	ce := ceilingEntry{
		WindowStartUnix: twoHoursAgo,
		Count:           defaultCeiling, // at ceiling — would be blocked in old window
		Limit:           defaultCeiling,
	}
	ceData, merr := json.Marshal(ce)
	require.NoError(t, merr)

	err := db.Update(func(tx *bbolt.Tx) error {
		b, berr := tx.CreateBucketIfNotExists(bucketCeiling)
		if berr != nil {
			return berr
		}
		return b.Put([]byte(deviceID), ceData)
	})
	require.NoError(t, err)

	// CeilingCheck should return allowed=true because the window has expired.
	allowed, err := o.CeilingCheck(deviceID, notifyv2.KindNeedsInput)
	require.NoError(t, err)
	assert.True(t, allowed, "expired window must reset; device must be allowed")
}

// TestNextBackoff verifies the full-jitter exponential backoff (D-08).
func TestNextBackoff(t *testing.T) {
	t.Run("attempt=0 produces duration in [0, base=5s)", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			d := NextBackoff(0)
			assert.GreaterOrEqual(t, d, time.Duration(0), "backoff must be >= 0")
			assert.Less(t, d, backoffBase, "attempt=0 backoff must be < 5s")
		}
	})

	t.Run("attempt=10 produces duration in [0, cap=5min)", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			d := NextBackoff(10)
			assert.GreaterOrEqual(t, d, time.Duration(0), "backoff must be >= 0")
			assert.LessOrEqual(t, d, backoffCap, "attempt=10 backoff must be <= 5min")
		}
	})

	t.Run("attempt=1 produces duration in [0, 10s)", func(t *testing.T) {
		window := backoffBase * (1 << 1) // 10s
		for i := 0; i < 100; i++ {
			d := NextBackoff(1)
			assert.GreaterOrEqual(t, d, time.Duration(0))
			assert.Less(t, d, window)
		}
	})

	t.Run("negative attempt treated as 0", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			d := NextBackoff(-5)
			assert.GreaterOrEqual(t, d, time.Duration(0))
			assert.Less(t, d, backoffBase)
		}
	})

	t.Run("high attempt capped at backoffCap", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			d := NextBackoff(100)
			assert.GreaterOrEqual(t, d, time.Duration(0))
			assert.LessOrEqual(t, d, backoffCap)
		}
	})
}
