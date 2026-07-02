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
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bbolt "go.etcd.io/bbolt"
)

// stubGateway records every Send call so a test can assert whether a wake was
// dispatched. It always succeeds.
type stubGateway struct{ sends int }

func (g *stubGateway) Send(_ context.Context, _ Wake) error { g.sends++; return nil }

// transientGateway always returns a generic (transient) error, driving the
// backoff/age-bound branch of processEntry.
type transientGateway struct{}

func (transientGateway) Send(_ context.Context, _ Wake) error { return errors.New("transient failure") }

// stubDeviceStore is a minimal DeviceStore for revocation tests.
type stubDeviceStore struct{ records []DeviceRecord }

func (s *stubDeviceStore) List() []DeviceRecord { return s.records }

func (s *stubDeviceStore) RevokeByID(_ context.Context, id string) error {
	for i := range s.records {
		if s.records[i].ID == id {
			s.records[i].Revoked = true
			return nil
		}
	}
	return nil
}

// readOutboxEntry reads the stored entry for (deviceID, msgID) directly from the
// outbox bucket. Whitebox helper (same package) so a test can observe the
// re-enqueued, Attempts-incremented entry between processEntry passes.
func readOutboxEntry(t *testing.T, o *Outbox, deviceID, msgID string) (outboxEntry, bool) {
	t.Helper()
	var (
		e     outboxEntry
		found bool
	)
	err := o.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketOutbox)
		if b == nil {
			return nil
		}
		v := b.Get(outboxKey(deviceID, msgID))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &e)
	})
	require.NoError(t, err)
	return e, found
}

// TestProcessEntryNoGatewayDropsAfterMaxAttempts locks in the WR-06 safety net:
// an entry whose platform has no registered gateway must be rescheduled with
// backoff for a bounded number of attempts and then dropped, so a never-wired
// platform cannot accumulate undeliverable wakes in the outbox forever. Fan-out
// only ever produces "unifiedpush" entries today (always in the map), so this
// drop path is unreachable in production — but it is the explicit bound WR-06
// introduced and should be regression-locked before the v5 receiver wires real
// APNs/FCM platforms.
func TestProcessEntryNoGatewayDropsAfterMaxAttempts(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	counters := &GatewayCounters{}
	gateways := map[string]Gateway{} // no gateway registered for "apns"
	const deviceID = "dev-x"

	e := sampleEntry("01J7MSGAPNS0000000000000001")
	e.Platform = "apns" // platform absent from the gateways map
	require.NoError(t, o.Enqueue(deviceID, e))

	// Drive processEntry maxNoGatewayAttempts times. Each pass before the last
	// increments Attempts, reschedules with backoff (BackoffPending++), and
	// re-enqueues; the final pass dequeues (drops) the undeliverable entry.
	for i := 1; i <= maxNoGatewayAttempts; i++ {
		cur, ok := readOutboxEntry(t, o, deviceID, e.MsgID)
		require.True(t, ok, "entry must be present before attempt %d", i)
		require.EqualValues(t, i-1, cur.Attempts, "attempts must accrue across no-gateway passes")
		processEntry(context.Background(), o, gateways, nil, counters, deviceID, cur)
	}

	_, ok := readOutboxEntry(t, o, deviceID, e.MsgID)
	assert.False(t, ok, "entry must be dropped after %d no-gateway attempts", maxNoGatewayAttempts)
	assert.EqualValues(t, maxNoGatewayAttempts-1, counters.BackoffPending.Load(),
		"every intermediate reschedule (all but the final drop) accrues BackoffPending")
	assert.EqualValues(t, 0, counters.ProviderAccepted.Load(), "a no-gateway entry never reaches a provider")
	assert.EqualValues(t, 0, counters.Sent.Load(), "a no-gateway entry is never sent")
}

// TestProcessEntrySkipsRevokedDevice locks in finding [11]: a wake queued for a
// device that is revoked (or removed) before the retry tick must be dequeued and
// NEVER dispatched to the now-lost/decommissioned push endpoint — revocation
// blanks the record but does not itself dequeue in-flight entries.
func TestProcessEntrySkipsRevokedDevice(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	counters := &GatewayCounters{}
	gw := &stubGateway{}
	gateways := map[string]Gateway{"unifiedpush": gw}
	const deviceID = "dev-revoked"

	e := sampleEntry("01J7MSGREVOKED000000000001")
	require.NoError(t, o.Enqueue(deviceID, e))

	devices := &stubDeviceStore{records: []DeviceRecord{{ID: deviceID, Platform: "unifiedpush", Revoked: true}}}
	processEntry(context.Background(), o, gateways, devices, counters, deviceID, e)

	assert.Equal(t, 0, gw.sends, "a revoked device must never receive its queued wake")
	_, ok := readOutboxEntry(t, o, deviceID, e.MsgID)
	assert.False(t, ok, "the revoked-device entry must be dequeued")
	assert.EqualValues(t, 1, counters.PrunedTokens.Load(), "the skipped entry is counted as pruned")

	// An entry for a device that is absent from the store entirely is also skipped.
	e2 := sampleEntry("01J7MSGABSENT0000000000001")
	require.NoError(t, o.Enqueue("dev-absent", e2))
	processEntry(context.Background(), o, gateways, devices, counters, "dev-absent", e2)
	assert.Equal(t, 0, gw.sends, "an absent device must never receive its queued wake")
	_, ok = readOutboxEntry(t, o, "dev-absent", e2.MsgID)
	assert.False(t, ok, "the absent-device entry must be dequeued")
}

// TestProcessEntryDropsAgedOutEntry locks in finding [10]: a transiently-failing
// entry older than maxOutboxAge is dropped rather than rescheduled forever, so a
// permanently-undeliverable endpoint cannot grow the outbox unbounded.
func TestProcessEntryDropsAgedOutEntry(t *testing.T) {
	db := openTestDB(t)
	o := NewOutbox(db)
	counters := &GatewayCounters{}
	gateways := map[string]Gateway{"unifiedpush": transientGateway{}}
	const deviceID = "dev-old"

	e := sampleEntry("01J7MSGAGEDOUT0000000000001")
	e.FirstTriedUnix = time.Now().Add(-(maxOutboxAge + time.Hour)).Unix() // past the bound
	require.NoError(t, o.Enqueue(deviceID, e))

	devices := &stubDeviceStore{records: []DeviceRecord{{ID: deviceID, Platform: "unifiedpush"}}}
	processEntry(context.Background(), o, gateways, devices, counters, deviceID, e)

	_, ok := readOutboxEntry(t, o, deviceID, e.MsgID)
	assert.False(t, ok, "an entry past maxOutboxAge must be dropped, not rescheduled")
	assert.EqualValues(t, 1, counters.PrunedTokens.Load(), "the aged-out drop is counted as pruned")
	assert.EqualValues(t, 0, counters.BackoffPending.Load(), "an aged-out entry must not be rescheduled")

	// A fresh transient failure (within the age bound) still reschedules normally.
	fresh := sampleEntry("01J7MSGFRESH00000000000001")
	fresh.FirstTriedUnix = time.Now().Unix()
	require.NoError(t, o.Enqueue(deviceID, fresh))
	processEntry(context.Background(), o, gateways, devices, counters, deviceID, fresh)
	got, ok := readOutboxEntry(t, o, deviceID, fresh.MsgID)
	require.True(t, ok, "a fresh transient failure must be rescheduled, not dropped")
	assert.EqualValues(t, 1, got.Attempts, "a rescheduled entry accrues an attempt")
	assert.EqualValues(t, 1, counters.BackoffPending.Load(), "the fresh reschedule accrues BackoffPending")
}
