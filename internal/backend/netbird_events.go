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

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/abysslink/abysslink/internal/config"
)

// NetBirdTailEvents constructs a netbirdAdapter from cfg and tails audit events
// to out. When follow is false it fetches the snapshot once; when true it polls
// with bounded backoff (watermark-deduplicated, ctx-cancellable). CLI-facing
// accessor for the unexported adapter (D-05: reuse doRequest, no new client).
func NetBirdTailEvents(ctx context.Context, cfg *config.Config, out io.Writer, follow bool) error {
	return newNetBirdAdapter(cfg, nil).TailEvents(ctx, out, follow)
}

// defaultEventPollStart / defaultEventPollMax bound the --follow polling backoff.
// NetBird's audit-events endpoint (GET /api/events/audit) has no streaming or
// cursor support, so --follow re-polls the snapshot with bounded exponential
// backoff (start → double on idle → cap), resetting on new events
// (T-21-04-04: bounded backoff, ctx-cancellable).
const (
	defaultEventPollStart = 2 * time.Second
	defaultEventPollMax   = 30 * time.Second
)

// nbAuditEvent is a single audit event from GET /api/events/audit.
// Only the fields needed for CLI display are modelled; the API returns more.
type nbAuditEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Activity  string    `json:"activity"`
}

// ListEvents returns the current snapshot of audit events via
// GET /api/events/audit. The endpoint has no pagination/cursor parameters, so
// this is a full snapshot of all events visible to the API key.
func (a *netbirdAdapter) ListEvents(ctx context.Context) ([]nbAuditEvent, error) {
	resp, err := a.doRequest(ctx, http.MethodGet, "/api/events/audit", nil)
	if err != nil {
		return nil, fmt.Errorf("netbird: list events: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netbird: list events: HTTP %d", resp.StatusCode)
	}
	data, err := readLimited(resp.Body, maxBackendBody)
	if err != nil {
		return nil, fmt.Errorf("netbird: list events: read response: %w", err)
	}
	var events []nbAuditEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("netbird: list events: decode: %w", err)
	}
	return events, nil
}

// TailEvents fetches audit events and writes each as a JSON line to out.
//
// When follow is false, it fetches the snapshot once and returns.
//
// When follow is true, it enters a bounded-backoff polling loop. The audit
// endpoint is a full snapshot with no cursor, so dedup keys off the last-printed
// event ID (falling back to its timestamp): each poll prints only the events
// newer than the watermark. This is robust to the snapshot shrinking then
// regrowing (rotation/purge) — a count-based watermark silently dropped events
// in that case (WR-02). If the watermark ID is absent from a new snapshot (the
// event it pointed at was rotated out), the tail is reprinted from the start
// rather than dropped silently. The poll interval starts at a.eventPollStart,
// doubles on each idle poll, caps at a.eventPollMax, and resets to the start
// interval when new events arrive. The loop exits cleanly (nil) when ctx is
// cancelled.
func (a *netbirdAdapter) TailEvents(ctx context.Context, out io.Writer, follow bool) error {
	events, err := a.ListEvents(ctx)
	if err != nil {
		// A cancelled context is a clean exit, not an error (ctx-cancellable
		// --follow): the caller asked to stop before the first fetch completed.
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if err := writeEventLines(out, events); err != nil {
		return err
	}
	if !follow {
		return nil
	}

	watermark := newestWatermark(events)
	interval := a.eventPollStart
	if interval <= 0 {
		interval = defaultEventPollStart
	}
	maxInterval := a.eventPollMax
	if maxInterval <= 0 {
		maxInterval = defaultEventPollMax
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			newEvents, pollErr := a.ListEvents(ctx)
			if pollErr != nil {
				// Transient poll error: back off and retry; ctx cancellation still
				// exits cleanly via the select above. Do not abort the follow loop
				// on a single failed poll.
				interval = nextInterval(interval, maxInterval)
				timer.Reset(interval)
				continue
			}
			fresh := eventsAfter(newEvents, watermark)
			if len(fresh) > 0 {
				if err := writeEventLines(out, fresh); err != nil {
					return err
				}
				watermark = newestWatermark(newEvents)
				interval = a.eventPollStart
				if interval <= 0 {
					interval = defaultEventPollStart
				}
			} else {
				interval = nextInterval(interval, maxInterval)
			}
			timer.Reset(interval)
		}
	}
}

// eventWatermark identifies the last event already printed by the follow loop.
// id is the primary key; ts is a fallback for events without an id. zero
// reports whether no event has been seen yet (initial empty snapshot).
type eventWatermark struct {
	id   string
	ts   time.Time
	zero bool
}

// newestWatermark returns the watermark for the newest (last) event in the
// snapshot, treating the slice as time-ordered oldest→newest (NetBird's audit
// endpoint returns events in chronological order). An empty snapshot yields the
// zero watermark.
func newestWatermark(events []nbAuditEvent) eventWatermark {
	if len(events) == 0 {
		return eventWatermark{zero: true}
	}
	last := events[len(events)-1]
	return eventWatermark{id: last.ID, ts: last.Timestamp}
}

// eventsAfter returns the suffix of events strictly newer than wm. It locates wm
// by id (or by timestamp when the event has no id) and returns everything after
// it. If wm is the zero watermark, all events are returned. If wm cannot be
// found in the snapshot (its event was rotated/purged out), the whole snapshot
// is returned rather than silently dropping events (WR-02) — duplicates on a
// rotation boundary are preferable to silent loss.
func eventsAfter(events []nbAuditEvent, wm eventWatermark) []nbAuditEvent {
	if wm.zero {
		return events
	}
	for i, ev := range events {
		match := false
		if wm.id != "" {
			match = ev.ID == wm.id
		} else {
			match = ev.Timestamp.Equal(wm.ts)
		}
		if match {
			return events[i+1:]
		}
	}
	return events
}

// nextInterval doubles cur, capping at maxInterval (bounded exponential backoff).
func nextInterval(cur, maxInterval time.Duration) time.Duration {
	next := cur * 2
	if next > maxInterval {
		return maxInterval
	}
	return next
}

// writeEventLines encodes each event as a single JSON line to out (consistent
// with --json line-delimited output). json.Encoder.Encode appends a newline.
func writeEventLines(out io.Writer, events []nbAuditEvent) error {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return fmt.Errorf("netbird: encode event: %w", err)
		}
	}
	return nil
}
