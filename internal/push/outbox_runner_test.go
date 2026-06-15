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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bbolt "go.etcd.io/bbolt"
)

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
