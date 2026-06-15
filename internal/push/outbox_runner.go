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
	"log/slog"
	"time"

	bbolt "go.etcd.io/bbolt"

	"github.com/abysslink/abysslink/internal/notifyv2"
)

// DeviceStore is the push-runner's view of the enrolled-device registry.
// It is a minimal interface defined here (not importing internal/device) to
// keep internal/push a leaf package with no import cycles.
//
// internal/device.Store satisfies DeviceStore:
//   - List() returns all device.Record values (active and revoked); the runner
//     filters by active (non-revoked) devices with a push token.
//   - RevokeByID revokes the device record with the given stable ULID ID; it is
//     the dead-token prune path (D-12). Added to device.Store in Phase 29.
type DeviceStore interface {
	// List returns a copy of all enrolled device records (active and revoked).
	// The retry goroutine iterates this to find active devices when building
	// Wake structs from outbox entries.
	List() []DeviceRecord

	// RevokeByID permanently revokes the device with the given ID (the stable
	// ULID from DeviceRecord.ID). Called when a provider returns ErrDeadToken
	// so the dead token is pruned from the enrollment store (D-12). A missing
	// or already-revoked ID is a no-op or ErrNotFound — both are non-fatal for
	// the retry goroutine.
	RevokeByID(ctx context.Context, id string) error
}

// DeviceRecord is the push-runner's view of one enrolled device.
// It carries only the fields the retry goroutine needs: routing metadata and
// the secret-class push token. No credential plaintext is logged (D-17).
type DeviceRecord struct {
	// ID is the stable ULID for this device (used for dead-token pruning).
	ID string
	// Platform is the push platform: "apns" | "fcm" | "unifiedpush".
	Platform string
	// PushToken is the opaque push identity ("ablk_p_…" minted at enrollment).
	// Secret-class: never log (D-17).
	PushToken string
	// Revoked marks the device as permanently disabled; the runner skips revoked
	// records when building the active-device list for enqueue.
	Revoked bool
}

// retryInterval is the scan cadence of RunOutboxRetry: every 5 seconds the
// goroutine checks for outbox entries whose NextRetryUnix ≤ now (D-08).
const retryInterval = 5 * time.Second

// RunOutboxRetry is the persistent outbox retry goroutine. It scans the outbox
// bucket every retryInterval for entries with NextRetryUnix ≤ now and drives
// them through the appropriate Gateway leg:
//
//   - On nil error (provider accepted): Dequeue + MarkSeen(24h) + increment
//     ProviderAccepted counter. The per-device ceiling window is incremented at
//     ENQUEUE in the daemon fan-out path, not here (WR-02 / D-05): counting on
//     async delivery let a burst exceed the ceiling.
//   - On ErrDeadToken: prune via devices.RevokeByID + Dequeue + increment
//     PrunedTokens counter. Logs device_id only (never the provider token — D-17).
//   - On transient error: increment Attempts + schedule NextRetryUnix via
//     NextBackoff + re-Enqueue (overwrite) + increment BackoffPending counter.
//
// The goroutine exits cleanly when ctx is cancelled (daemon shutdown). It is
// exported so cmd/abysslinkd can start it in one line (D-06 wiring pattern).
func RunOutboxRetry(ctx context.Context, outbox *Outbox, gateways map[string]Gateway, devices DeviceStore, counters *GatewayCounters) {
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drainDue(ctx, outbox, gateways, devices, counters)
		}
	}
}

// drainDue scans the outbox bucket for entries with NextRetryUnix ≤ now and
// dispatches each one through the appropriate gateway.
func drainDue(ctx context.Context, outbox *Outbox, gateways map[string]Gateway, devices DeviceStore, counters *GatewayCounters) {
	type pendingEntry struct {
		deviceID string
		entry    outboxEntry
	}
	var due []pendingEntry

	// Collect due entries under a read transaction.
	_ = outbox.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketOutbox)
		if b == nil {
			return nil
		}
		now := time.Now().Unix()
		return b.ForEach(func(k, v []byte) error {
			var e outboxEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return nil // skip corrupt entries
			}
			if e.NextRetryUnix > now {
				return nil // not yet due
			}
			// Extract deviceID from key (format: deviceID:msgID).
			key := string(k)
			colon := findLastColon(key, len(e.MsgID))
			if colon < 0 {
				return nil // malformed key; skip
			}
			deviceID := key[:colon]
			due = append(due, pendingEntry{deviceID: deviceID, entry: e})
			return nil
		})
	})

	for _, p := range due {
		if ctx.Err() != nil {
			return // daemon shutting down
		}
		processEntry(ctx, outbox, gateways, devices, counters, p.deviceID, p.entry)
	}
}

// findLastColon returns the index of the colon separator in an outbox key of
// the form "deviceID:msgID", given the known length of the msgID suffix. It
// returns -1 when the key is too short or malformed.
func findLastColon(key string, msgIDLen int) int {
	idx := len(key) - msgIDLen - 1
	if idx < 0 || key[idx] != ':' {
		return -1
	}
	return idx
}

// processEntry dispatches one outbox entry through its gateway and handles the
// result: success → Dequeue + MarkSeen; dead-token → prune; transient → backoff.
func processEntry(ctx context.Context, outbox *Outbox, gateways map[string]Gateway, devices DeviceStore, counters *GatewayCounters, deviceID string, e outboxEntry) {
	gw, ok := gateways[e.Platform]
	if !ok {
		// No gateway registered for this platform (e.g. APNs disabled).
		// Reschedule with backoff to avoid a tight loop and leave the entry for
		// when the operator enables the leg and restarts the daemon.
		e.Attempts++
		e.NextRetryUnix = time.Now().Add(NextBackoff(e.Attempts)).Unix()
		_ = outbox.Enqueue(deviceID, e)
		counters.BackoffPending.Add(1)
		slog.Info("push: no gateway for platform; retry scheduled",
			"device_id", deviceID,
			"msg_id", e.MsgID,
			"platform", e.Platform,
			"attempt", e.Attempts,
			"next_retry_unix", e.NextRetryUnix)
		return
	}

	// Reconstruct the notifyv2.Message from the stored JSON.
	var msg notifyv2.Message
	if e.MetaJSON != "" {
		_ = json.Unmarshal([]byte(e.MetaJSON), &msg)
	}

	wake := Wake{
		DeviceID:      deviceID,
		Platform:      e.Platform,
		ProviderToken: e.ProviderToken, // secret-class — never log
		Msg:           msg,
		CollapseID:    e.CollapseID,
	}

	counters.Sent.Add(1)
	sendErr := gw.Send(ctx, wake)

	switch {
	case sendErr == nil:
		// Provider accepted: remove from outbox, mark seen.
		//
		// WR-02: the per-device ceiling window is incremented at ENQUEUE (in the
		// daemon fan-out path), NOT here. Incrementing on successful send let a
		// burst sail past the ceiling because deliveries complete asynchronously
		// (this loop fires every 5s); the count must advance where CeilingCheck's
		// decision is made.
		if err := outbox.Dequeue(deviceID, e.MsgID); err != nil {
			slog.Warn("push: dequeue after send failed", "device_id", deviceID, "msg_id", e.MsgID, "err", err)
		}
		if err := outbox.MarkSeen(e.MsgID, dedupTTL); err != nil {
			slog.Warn("push: mark-seen after send failed", "msg_id", e.MsgID, "err", err)
		}
		counters.ProviderAccepted.Add(1)

	case errors.Is(sendErr, ErrDeadToken):
		// Provider confirmed dead token: prune from device store + dequeue (D-12).
		// Device IDs (ULIDs) are routing metadata, not secrets — safe to log (D-17).
		slog.Warn("push: dead token pruned", "device_id", deviceID)
		if devices != nil {
			if pruneErr := devices.RevokeByID(ctx, deviceID); pruneErr != nil {
				slog.Warn("push: dead-token device revoke failed", "device_id", deviceID, "err", pruneErr)
			}
		}
		if err := outbox.Dequeue(deviceID, e.MsgID); err != nil {
			slog.Warn("push: dequeue after dead-token failed", "device_id", deviceID, "msg_id", e.MsgID, "err", err)
		}
		counters.PrunedTokens.Add(1)

	default:
		// Transient error: schedule next retry with full-jitter exponential backoff.
		e.Attempts++
		e.NextRetryUnix = time.Now().Add(NextBackoff(e.Attempts)).Unix()
		if err := outbox.Enqueue(deviceID, e); err != nil {
			slog.Warn("push: re-enqueue for retry failed", "device_id", deviceID, "msg_id", e.MsgID, "err", err)
		}
		counters.BackoffPending.Add(1)
		slog.Info("push: retry scheduled",
			"device_id", deviceID,
			"msg_id", e.MsgID,
			"attempt", e.Attempts,
			"next_retry_unix", e.NextRetryUnix)
		// NOTE: never log sendErr if it might contain a token/credential.
	}
}
