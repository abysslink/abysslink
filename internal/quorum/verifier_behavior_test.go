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

package quorum

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/abysslink/abysslink/internal/approve"
)

// fakeClock is an injectable deterministic clock.
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func behaviorAct(bin string, args ...string) action {
	return action{name: bin, args: args, binary: bin}
}

func TestBehavior_RateWindowEscalates(t *testing.T) {
	clock := newFakeClock()
	v := newBehaviorVerifier(0, 0, 0, clock.now, nil) // shipped defaults: 10 ops / 300s

	// Nine destructive ops inside the window: still under the cap.
	for range 9 {
		v.record("rm", []string{"-f", "x"})
		clock.advance(time.Second)
	}
	vote := v.check(context.Background(), behaviorAct("rm", "-f", "y"))
	assert.NotEqual(t, codeRateWindow, vote.Code, "9 prior destructive ops must not trip a 10-op cap")

	// The tenth prior op trips the cap for the next destructive action.
	v.record("rm", []string{"-f", "x"})
	vote = v.check(context.Background(), behaviorAct("rm", "-f", "y"))
	assert.Equal(t, VerdictEscalate, vote.Verdict)
	assert.Equal(t, codeRateWindow, vote.Code)
	assert.Equal(t, approve.TierSensitive, vote.Tier)

	// A non-destructive action is not rate-gated.
	vote = v.check(context.Background(), behaviorAct("ls"))
	assert.NotEqual(t, codeRateWindow, vote.Code)

	// Outside the window the history ages out.
	clock.advance(400 * time.Second)
	vote = v.check(context.Background(), behaviorAct("rm", "-f", "y"))
	assert.NotEqual(t, codeRateWindow, vote.Code, "events beyond the window must age out")
}

func TestBehavior_TightenedRateConfigHonored(t *testing.T) {
	clock := newFakeClock()
	v := newBehaviorVerifier(0, 3, 600, clock.now, nil) // tightened: 3 ops / 600s

	for range 3 {
		v.record("rm", []string{"-f", "x"})
		clock.advance(time.Second)
	}
	vote := v.check(context.Background(), behaviorAct("rm", "-f", "y"))
	assert.Equal(t, codeRateWindow, vote.Code, "a tightened cap must trip earlier than the default")
}

func TestBehavior_VelocityEscalates(t *testing.T) {
	clock := newFakeClock()
	v := newBehaviorVerifier(0, 0, 0, clock.now, nil)

	// Many benign execs inside one velocity window — the compiled global cap.
	for range velocityMaxOps {
		v.record("ls", []string{"-la"})
		clock.advance(time.Second)
	}
	vote := v.check(context.Background(), behaviorAct("ls"))
	assert.Equal(t, VerdictEscalate, vote.Verdict)
	assert.Equal(t, codeVelocity, vote.Code,
		"many small individually-benign actions summing past the cap must escalate")
}

func TestBehavior_DryRunFirst(t *testing.T) {
	t.Run("cold history fails closed", func(t *testing.T) {
		clock := newFakeClock()
		v := newBehaviorVerifier(0, 0, 0, clock.now, nil)
		vote := v.check(context.Background(), behaviorAct("terraform", "apply"))
		assert.Equal(t, VerdictEscalate, vote.Verdict,
			"an apply-shaped action after a restart (cold ring) must ask the human")
		assert.Equal(t, codeDryRunFirst, vote.Code)
	})

	t.Run("prior dry-run satisfies the precondition", func(t *testing.T) {
		clock := newFakeClock()
		v := newBehaviorVerifier(0, 0, 0, clock.now, nil)
		v.record("terraform", []string{"plan"})
		clock.advance(30 * time.Second)
		vote := v.check(context.Background(), behaviorAct("terraform", "apply"))
		assert.NotEqual(t, codeDryRunFirst, vote.Code)
	})

	t.Run("git push without prior --dry-run escalates", func(t *testing.T) {
		clock := newFakeClock()
		v := newBehaviorVerifier(0, 0, 0, clock.now, nil)
		vote := v.check(context.Background(), behaviorAct("git", "push", "origin", "main"))
		assert.Equal(t, codeDryRunFirst, vote.Code)

		v.record("git", []string{"push", "--dry-run", "origin", "main"})
		vote = v.check(context.Background(), behaviorAct("git", "push", "origin", "main"))
		assert.NotEqual(t, codeDryRunFirst, vote.Code)
	})

	t.Run("stale dry-run outside the window does not satisfy", func(t *testing.T) {
		clock := newFakeClock()
		v := newBehaviorVerifier(0, 0, 0, clock.now, nil)
		v.record("terraform", []string{"plan"})
		clock.advance(10 * time.Minute) // beyond the 300s window
		vote := v.check(context.Background(), behaviorAct("terraform", "apply"))
		assert.Equal(t, codeDryRunFirst, vote.Code)
	})
}

func TestBehavior_SpendThreshold(t *testing.T) {
	clock := newFakeClock()

	t.Run("nil spend func is inert", func(t *testing.T) {
		v := newBehaviorVerifier(0, 0, 0, clock.now, nil)
		vote := v.check(context.Background(), behaviorAct("ls"))
		assert.NotEqual(t, codeSpendThreshold, vote.Code)
	})

	t.Run("at threshold escalates Critical", func(t *testing.T) {
		v := newBehaviorVerifier(0, 0, 0, clock.now, func() float64 { return 50 })
		vote := v.check(context.Background(), behaviorAct("ls"))
		assert.Equal(t, VerdictEscalate, vote.Verdict)
		assert.Equal(t, codeSpendThreshold, vote.Code)
		assert.Equal(t, approve.TierCritical, vote.Tier)
	})

	t.Run("tightened threshold trips earlier", func(t *testing.T) {
		v := newBehaviorVerifier(10, 0, 0, clock.now, func() float64 { return 12 })
		vote := v.check(context.Background(), behaviorAct("ls"))
		assert.Equal(t, codeSpendThreshold, vote.Code)
	})

	t.Run("under threshold does not trip", func(t *testing.T) {
		v := newBehaviorVerifier(0, 0, 0, clock.now, func() float64 { return 49.99 })
		vote := v.check(context.Background(), behaviorAct("ls"))
		assert.NotEqual(t, codeSpendThreshold, vote.Code)
	})
}

func TestBehavior_RingIsBounded(t *testing.T) {
	clock := newFakeClock()
	v := newBehaviorVerifier(0, 0, 0, clock.now, nil)
	for range behaviorRingCap * 2 {
		v.record("ls", nil)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	assert.LessOrEqual(t, len(v.ring), behaviorRingCap, "the history ring must stay bounded")
}
