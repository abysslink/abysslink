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
)

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
	var events []nbAuditEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, fmt.Errorf("netbird: list events: decode: %w", err)
	}
	return events, nil
}

// TailEvents fetches audit events and writes each as a JSON line to out.
//
// When follow is false, it fetches the snapshot once and returns.
//
// When follow is true, it enters a bounded-backoff polling loop: it tracks a
// watermark (the count of events already printed) and prints only the events
// appended since the last poll, preventing duplicate output (the audit endpoint
// is a full snapshot with no cursor). The poll interval starts at
// a.eventPollStart, doubles on each idle poll (no new events), caps at
// a.eventPollMax, and resets to the start interval when new events arrive. The
// loop exits cleanly (nil) when ctx is cancelled.
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

	lastCount := len(events)
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
			if len(newEvents) > lastCount {
				if err := writeEventLines(out, newEvents[lastCount:]); err != nil {
					return err
				}
				lastCount = len(newEvents)
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
