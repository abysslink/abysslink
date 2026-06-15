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
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"math/big"
	"time"

	bbolt "go.etcd.io/bbolt"

	"github.com/abysslink/abysslink/internal/notifyv2"
)

// Bucket names in the push outbox bbolt database (D-06 audit-exempt).
var (
	bucketOutbox  = []byte("outbox")  // key=deviceID+":"+msgID, val=outboxEntry JSON
	bucketDedup   = []byte("dedup")   // key=msgID, val=8-byte big-endian expires_unix
	bucketCeiling = []byte("ceiling") // key=deviceID, val=ceilingEntry JSON
)

// Outbox constants (D-05, D-07, D-08).
const (
	dedupTTL       = 24 * time.Hour // D-07: msg_id seen-set TTL
	ceilingWindow  = time.Hour      // D-05: per-device wakes-per-hour fixed window
	defaultCeiling = 60             // D-05: default wakes/hour per device

	backoffBase = 5 * time.Second // D-08: exponential backoff base
	backoffCap  = 5 * time.Minute // D-08: exponential backoff cap
)

// OutboxEntry is the JSON-serialized value stored per (device, msg_id) in the
// outbox bucket. ProviderToken is secret-class and must never appear in logs.
// Exported so the daemon composition root and fan-out path can construct and
// Enqueue entries without needing to duplicate the struct definition.
type OutboxEntry = outboxEntry

// outboxEntry is the internal storage type for OutboxEntry.
type outboxEntry struct {
	Platform       string `json:"platform"`
	ProviderToken  string `json:"provider_token"` // secret-class — never log (D-17)
	MsgID          string `json:"msg_id"`
	Title          string `json:"title"`
	MetaJSON       string `json:"meta_json"` // full notifyv2.Message JSON
	Attempts       int    `json:"attempts"`
	FirstTriedUnix int64  `json:"first_tried_unix"`
	NextRetryUnix  int64  `json:"next_retry_unix"`
	CollapseID     string `json:"collapse_id"`
}

// ceilingEntry tracks per-device wake counts in a fixed 1-hour window.
type ceilingEntry struct {
	WindowStartUnix int64 `json:"w"` // start of the current 1-hour window (unix)
	Count           int   `json:"c"` // wakes dispatched in the current window
	Limit           int   `json:"l"` // max wakes per window (default 60)
}

// Outbox manages the persistent push outbox backed by a bbolt database.
// The bbolt handle is opened at the daemon composition root (D-06 audit
// exemption) and passed here — never via internal/audit.
// All methods are goroutine-safe: bbolt serializes concurrent db.Update calls.
type Outbox struct {
	db *bbolt.DB
}

// NewOutbox wraps an already-open bbolt database. The caller (daemon
// composition root) is responsible for db.Close on daemon exit (D-06).
func NewOutbox(db *bbolt.DB) *Outbox {
	return &Outbox{db: db}
}

// outboxKey returns the bbolt key for a (deviceID, msgID) pair.
func outboxKey(deviceID, msgID string) []byte {
	return []byte(deviceID + ":" + msgID)
}

// int64ToBytes encodes a unix timestamp as an 8-byte big-endian slice.
func int64ToBytes(v int64) []byte {
	b := make([]byte, 8)
	// #nosec G115 -- post-1970 unix timestamps are non-negative; int64->uint64 cannot overflow
	binary.BigEndian.PutUint64(b, uint64(v)) //nolint:gosec // G115: unix timestamps are non-negative
	return b
}

// bytesToInt64 decodes an 8-byte big-endian slice into an int64.
func bytesToInt64(b []byte) int64 {
	if len(b) < 8 {
		return 0
	}
	// #nosec G115 -- stored unix timestamp; uint64 value from our own int64ToBytes; no overflow in practice
	return int64(binary.BigEndian.Uint64(b)) //nolint:gosec // G115: reading our own stored timestamp
}

// Enqueue adds an outbox entry for the given device. Creates the outbox bucket
// if it does not exist. Idempotent: overwrites any existing entry for the same
// (deviceID, entry.MsgID) key.
func (o *Outbox) Enqueue(deviceID string, e outboxEntry) error {
	return o.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketOutbox)
		if err != nil {
			return err
		}
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := b.Put(outboxKey(deviceID, e.MsgID), data); err != nil {
			return err
		}
		// Log metadata only — ProviderToken is secret-class (D-17).
		slog.Info("push: outbox entry enqueued",
			"device_id", deviceID,
			"msg_id", e.MsgID,
			"platform", e.Platform)
		return nil
	})
}

// Dequeue removes an outbox entry for the given (deviceID, msgID) pair.
// It is not an error to dequeue an entry that does not exist.
func (o *Outbox) Dequeue(deviceID, msgID string) error {
	return o.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketOutbox)
		if b == nil {
			return nil // bucket doesn't exist — nothing to dequeue
		}
		if err := b.Delete(outboxKey(deviceID, msgID)); err != nil {
			return err
		}
		slog.Info("push: outbox entry dequeued",
			"device_id", deviceID,
			"msg_id", msgID)
		return nil
	})
}

// DedupSeen returns true if the msg_id has been marked seen and its TTL has
// not yet expired. Returns false if the entry does not exist or has expired.
func (o *Outbox) DedupSeen(msgID string) (bool, error) {
	var seen bool
	err := o.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketDedup)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(msgID))
		if v == nil {
			return nil
		}
		expiresUnix := bytesToInt64(v)
		seen = time.Now().Unix() < expiresUnix
		return nil
	})
	return seen, err
}

// MarkSeen records a msg_id in the dedup bucket with an expiry of now+ttl.
// Overwrites any existing entry (refreshes TTL on re-delivery).
func (o *Outbox) MarkSeen(msgID string, ttl time.Duration) error {
	return o.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketDedup)
		if err != nil {
			return err
		}
		expiresUnix := time.Now().Add(ttl).Unix()
		return b.Put([]byte(msgID), int64ToBytes(expiresUnix))
	})
}

// SweepDedup deletes all dedup entries whose expiry has passed. Called at
// daemon start and on the periodic sweep timer (D-07) to bound bbolt growth.
func (o *Outbox) SweepDedup() error {
	return o.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketDedup)
		if b == nil {
			return nil
		}
		now := time.Now().Unix()
		var expired [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			if bytesToInt64(v) <= now {
				// copy key — ForEach key slice is reused
				key := make([]byte, len(k))
				copy(key, k)
				expired = append(expired, key)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range expired {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		if len(expired) > 0 {
			slog.Info("push: dedup sweep complete", "expired_count", len(expired))
		}
		return nil
	})
}

// CeilingCheck reports whether a wake is allowed under the per-device ceiling.
//
// Exemption: approval_request kind is always allowed (safety-critical; must
// never be dropped by a rate ceiling — per research open Q3 / D-13).
//
// For all other kinds: reads (or initializes) the ceiling bucket entry for
// the device and returns count < limit within the current 1-hour window. If
// the window has expired it is reset before the check.
func (o *Outbox) CeilingCheck(deviceID string, kind notifyv2.Kind) (allowed bool, err error) {
	if kind == notifyv2.KindApprovalRequest {
		// approval_request is safety-critical — exempt from ceiling (D-13 + research Q3).
		return true, nil
	}
	err = o.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketCeiling)
		if b == nil {
			allowed = true // no bucket = no entries = below ceiling
			return nil
		}
		v := b.Get([]byte(deviceID))
		if v == nil {
			allowed = true // no entry = below ceiling
			return nil
		}
		var ce ceilingEntry
		if jerr := json.Unmarshal(v, &ce); jerr != nil {
			allowed = true // corrupt entry — allow and let Incr reset it
			return nil
		}
		limit := ce.Limit
		if limit <= 0 {
			limit = defaultCeiling
		}
		// Check if the window has expired.
		windowEnd := ce.WindowStartUnix + int64(ceilingWindow.Seconds())
		if time.Now().Unix() >= windowEnd {
			// Window expired — a fresh window would start at Incr time; allow now.
			allowed = true
			return nil
		}
		allowed = ce.Count < limit
		return nil
	})
	return allowed, err
}

// CeilingIncr increments the per-device wake count in the current 1-hour
// window. If no entry exists or the window has expired, it creates/resets one
// with count=1 and limit=defaultLimit.
func (o *Outbox) CeilingIncr(deviceID string, defaultLimit int) error {
	if defaultLimit <= 0 {
		defaultLimit = defaultCeiling
	}
	return o.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketCeiling)
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		var ce ceilingEntry
		v := b.Get([]byte(deviceID))
		if v != nil {
			_ = json.Unmarshal(v, &ce) // ignore decode errors — reset below
		}

		// Reset if no entry, corrupt entry (Limit=0), or window expired.
		windowEnd := ce.WindowStartUnix + int64(ceilingWindow.Seconds())
		if ce.Limit <= 0 || now >= windowEnd {
			ce = ceilingEntry{
				WindowStartUnix: now,
				Count:           1,
				Limit:           defaultLimit,
			}
		} else {
			ce.Count++
		}

		data, err := json.Marshal(ce)
		if err != nil {
			return err
		}
		return b.Put([]byte(deviceID), data)
	})
}

// OutboxHasEntry reports whether the outbox bucket contains an entry for the
// given (deviceID, msgID) pair. Exported for whitebox test assertions in
// sibling packages (e.g. internal/daemon fan-out tests).
func OutboxHasEntry(o *Outbox, deviceID, msgID string) (bool, error) {
	key := outboxKey(deviceID, msgID)
	var found bool
	err := o.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketOutbox)
		if b == nil {
			return nil
		}
		found = b.Get(key) != nil
		return nil
	})
	return found, err
}

// NextBackoff returns a random duration in [0, min(cap, base*2^attempt)) using
// the full-jitter algorithm (D-08). Prevents thundering-herd retries across
// devices. base=5s, cap=5min.
//
// The attempt argument is clamped to 6 to prevent overflow in the shift
// (base * 2^6 = 320s which is already above the 300s cap).
func NextBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	shift := attempt
	if shift > 6 {
		shift = 6
	}
	window := backoffBase * (1 << shift) //nolint:gosec // shift is clamped to 6
	if window > backoffCap {
		window = backoffCap
	}
	if window <= 0 {
		return 0
	}
	// Use crypto/rand for the jitter draw (project security standard; math/rand is
	// disallowed by semgrep go.lang.security.audit.crypto.math_random.math-random-used).
	// crypto/rand.Int cannot return an error on Go >= 1.24 (OS entropy is checked at startup).
	n, err := crand.Int(crand.Reader, big.NewInt(int64(window)))
	if err != nil {
		// This cannot happen on a healthy OS (Go runtime aborts on broken entropy).
		// Return the cap so callers still back off.
		return window
	}
	return time.Duration(n.Int64()) //nolint:gosec // G115: n is in [0, window); window is a Duration (non-negative)
}
