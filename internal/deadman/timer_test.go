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

package deadman

import (
	"context"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a manually-advanced clock for deterministic deadline crossing.
// Now() reads the current fake time under a lock; Advance moves it forward.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{t: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTimerHarness builds a temp registry + audit writer + contact path and
// returns the pieces a timer test needs: opts (minus Interval/Now/Tick which
// the test sets), a signal recorder, the audit log path, and the contact path.
func newTimerHarness(t *testing.T) (*Registry, AuditAppender, AuditUpdater, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "armed-runs.json")
	logPath := filepath.Join(dir, "audit.log")
	contactPath := filepath.Join(dir, "deadman-contact.json")
	aud := audit.New(logPath)
	return New(statePath, aud), aud, aud, contactPath
}

// mustStartTimer starts the timer and registers a DETERMINISTIC join at cleanup:
// it cancels ctx and blocks on the done channel StartTimer returns, so the
// goroutine has fully exited before t.TempDir removal — no registry/audit write
// can race the teardown. Registered after the harness's t.TempDir cleanup, so it
// runs first (LIFO). Replaces the previous fixed-sleep drain, which was flaky
// under full-suite CPU load.
func mustStartTimer(ctx context.Context, t *testing.T, cancel context.CancelFunc, opts TimerOpts) {
	t.Helper()
	done, err := StartTimer(ctx, opts)
	require.NoError(t, err)
	t.Cleanup(func() { cancel(); <-done })
}

// TestTimerFiresLockdownAfterInterval asserts the timer fires Lockdown exactly
// once after the no-contact interval elapses with no heartbeat — and NOT before.
func TestTimerFiresLockdownAfterInterval(t *testing.T) {
	reg, appender, updater, contactPath := newTimerHarness(t)
	require.NoError(t, reg.Register(ArmedRun{PGID: 4242, ClosureHash: "x", ArmedAt: time.Now().UTC()}))

	start := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)

	// Seed a heartbeat at start so the persisted contact is "start".
	require.NoError(t, Heartbeat(context.Background(), contactPath, updater, clk.Now))

	var mu sync.Mutex
	var sigs []sigCall
	signalFn := func(pgid int, sig syscall.Signal) error {
		mu.Lock()
		sigs = append(sigs, sigCall{pgid, sig})
		mu.Unlock()
		return nil
	}
	sigCount := func() int { mu.Lock(); defer mu.Unlock(); return len(sigs) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	interval := time.Hour
	mustStartTimer(ctx, t, cancel, TimerOpts{
		Registry:    reg,
		ContactPath: contactPath,
		Interval:    interval,
		SignalFn:    signalFn,
		Audit:       appender,
		KillGrace:   time.Millisecond, // keep the disarm ladder fast in tests
		Tick:        5 * time.Millisecond,
		Now:         clk.Now,
	})

	// Before the interval elapses: never fires.
	clk.Advance(30 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, sigCount(), "must not fire before the interval elapses")

	// Cross the deadline: fires (SIGTERM + SIGKILL = 2 signals for one pgid).
	clk.Advance(31 * time.Minute)
	require.Eventually(t, func() bool { return sigCount() >= 2 }, 2*time.Second, 5*time.Millisecond,
		"lockdown must fire once the no-contact interval elapses")

	// Latched: does not re-fire on subsequent ticks without a heartbeat.
	clk.Advance(2 * time.Hour)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 2, sigCount(), "lockdown must fire EXACTLY once (latched until a fresh heartbeat)")
}

// TestHeartbeatResetsDeadline asserts a heartbeat pushes the deadline out so no
// lockdown fires when contact stays within the interval.
func TestHeartbeatResetsDeadline(t *testing.T) {
	reg, appender, updater, contactPath := newTimerHarness(t)
	require.NoError(t, reg.Register(ArmedRun{PGID: 777, ClosureHash: "y", ArmedAt: time.Now().UTC()}))

	start := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)
	require.NoError(t, Heartbeat(context.Background(), contactPath, updater, clk.Now))

	var fired int
	var mu sync.Mutex
	signalFn := func(int, syscall.Signal) error { mu.Lock(); fired++; mu.Unlock(); return nil }
	firedN := func() int { mu.Lock(); defer mu.Unlock(); return fired }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mustStartTimer(ctx, t, cancel, TimerOpts{
		Registry:    reg,
		ContactPath: contactPath,
		Interval:    time.Hour,
		SignalFn:    signalFn,
		Audit:       appender,
		KillGrace:   time.Millisecond,
		Tick:        5 * time.Millisecond,
		Now:         clk.Now,
	})

	// Advance 50m, heartbeat (resets), advance 50m more (100m total but only 50m
	// since the heartbeat): must NOT fire.
	clk.Advance(50 * time.Minute)
	time.Sleep(30 * time.Millisecond)
	require.NoError(t, Heartbeat(context.Background(), contactPath, updater, clk.Now))
	clk.Advance(50 * time.Minute)
	time.Sleep(80 * time.Millisecond)

	assert.Equal(t, 0, firedN(), "a heartbeat within the interval must reset the deadline (no lockdown)")
}

// TestDeadlineSurvivesRestart asserts a NEW timer reading the persisted
// last-contact does NOT reset the clock: the remaining time is computed from the
// persisted contact, so a restart shortly before the deadline still fires
// promptly after it.
func TestDeadlineSurvivesRestart(t *testing.T) {
	reg, appender, updater, contactPath := newTimerHarness(t)
	require.NoError(t, reg.Register(ArmedRun{PGID: 909, ClosureHash: "z", ArmedAt: time.Now().UTC()}))

	start := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)
	// Heartbeat at start, then "59 minutes pass" while a previous daemon ran.
	require.NoError(t, Heartbeat(context.Background(), contactPath, updater, clk.Now))
	clk.Advance(59 * time.Minute)

	// Simulate a daemon RESTART: a fresh StartTimer over the SAME persisted
	// contact. If it reset the clock, it would now need a full hour; instead it
	// must fire ~1 minute later (the remaining time from the persisted contact).
	var fired int
	var mu sync.Mutex
	signalFn := func(int, syscall.Signal) error { mu.Lock(); fired++; mu.Unlock(); return nil }
	firedN := func() int { mu.Lock(); defer mu.Unlock(); return fired }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mustStartTimer(ctx, t, cancel, TimerOpts{
		Registry:    reg,
		ContactPath: contactPath,
		Interval:    time.Hour,
		SignalFn:    signalFn,
		Audit:       appender,
		KillGrace:   time.Millisecond,
		Tick:        5 * time.Millisecond,
		Now:         clk.Now,
	})

	// Advance the remaining 2 minutes (past the 1h deadline from persisted
	// contact). A clock-resetting timer would NOT fire here.
	clk.Advance(2 * time.Minute)
	require.Eventually(t, func() bool { return firedN() >= 2 }, 2*time.Second, 5*time.Millisecond,
		"restart must compute remaining time from the persisted contact, not reset the clock")
}

// TestTimerFiresOnFreshEnableAfterInterval is the CR-02 regression: a freshly
// ENABLED switch (contact seeded at enable via SeedContact, NO subsequent
// heartbeat) must FIRE lockdown after the no-contact interval elapses — and must
// NOT fire before it (the legitimate T-32-25 false-trigger guard is preserved).
//
// This FAILS against the pre-fix timer: without a seeded contact, LastContact
// synthesized "now" on every tick so elapsed-since-contact stayed ~0 forever and
// the timer never fired (the fail-OPEN bug the old TestTimerNeverFiresFreshEnable
// enshrined). After seeding the contact at enable, the clock counts from enable
// and the deadline is crossed. It also confirms ctx cancellation exits the
// goroutine.
func TestTimerFiresOnFreshEnableAfterInterval(t *testing.T) {
	reg, appender, updater, contactPath := newTimerHarness(t)
	require.NoError(t, reg.Register(ArmedRun{PGID: 555, ClosureHash: "f", ArmedAt: time.Now().UTC()}))

	start := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	clk := newFakeClock(start)

	// Enable = first contact: seed contact=now (the fix). This is the only
	// "contact"; no heartbeat follows, mirroring an operator who enables and walks
	// away.
	require.NoError(t, SeedContact(context.Background(), contactPath, updater, clk.Now))

	var mu sync.Mutex
	var sigs []sigCall
	signalFn := func(pgid int, sig syscall.Signal) error {
		mu.Lock()
		sigs = append(sigs, sigCall{pgid, sig})
		mu.Unlock()
		return nil
	}
	sigCount := func() int { mu.Lock(); defer mu.Unlock(); return len(sigs) }

	ctx, cancel := context.WithCancel(context.Background())

	interval := time.Hour
	mustStartTimer(ctx, t, cancel, TimerOpts{
		Registry:    reg,
		ContactPath: contactPath,
		Interval:    interval,
		SignalFn:    signalFn,
		Audit:       appender,
		KillGrace:   time.Millisecond,
		Tick:        5 * time.Millisecond,
		Now:         clk.Now,
	})

	// Before the interval elapses: never fires (T-32-25 false-trigger guard).
	clk.Advance(30 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, sigCount(), "a freshly-enabled switch must NOT fire before the interval elapses")

	// Cross the deadline with NO heartbeat: lockdown MUST fire (SIGTERM + SIGKILL).
	clk.Advance(31 * time.Minute)
	require.Eventually(t, func() bool { return sigCount() >= 2 }, 2*time.Second, 5*time.Millisecond,
		"a fresh enable left silent past the interval MUST fire lockdown (CR-02 fail-open fix)")

	cancel()
	// After cancellation, advancing past a (hypothetical) deadline must not fire more.
	time.Sleep(30 * time.Millisecond)
	before := sigCount()
	time.Sleep(30 * time.Millisecond)
	assert.Equal(t, before, sigCount(), "goroutine must exit on ctx cancellation")
}

// TestSeedContact_Idempotent asserts SeedContact writes contact=now when no
// contact file exists (found=true afterward), and is a NO-OP when a contact
// already exists — a redundant seed (enable twice, or a daemon restart after
// enable) must never reset an in-flight deadline (T-32-24 restart-safety).
func TestSeedContact_Idempotent(t *testing.T) {
	_, _, updater, contactPath := newTimerHarness(t)

	// No contact yet: found=false.
	_, found0, err0 := LastContact(contactPath, time.Now)
	require.NoError(t, err0)
	assert.False(t, found0, "no contact should exist before seeding")

	// First seed writes contact=seedTime.
	seedTime := time.Date(2026, 6, 20, 8, 0, 0, 0, time.UTC)
	require.NoError(t, SeedContact(context.Background(), contactPath, updater, func() time.Time { return seedTime }))

	got1, found1, err1 := LastContact(contactPath, time.Now)
	require.NoError(t, err1)
	assert.True(t, found1, "after seeding, a contact must be persisted")
	assert.Equal(t, seedTime.UTC(), got1)

	// Second seed at a LATER time must be a no-op (preserve the in-flight deadline).
	laterTime := seedTime.Add(2 * time.Hour)
	require.NoError(t, SeedContact(context.Background(), contactPath, updater, func() time.Time { return laterTime }))

	got2, found2, err2 := LastContact(contactPath, time.Now)
	require.NoError(t, err2)
	assert.True(t, found2)
	assert.Equal(t, seedTime.UTC(), got2, "a second seed must NOT reset the persisted contact (idempotent restart-safety)")
}

// TestStartTimerRejectsBadOpts asserts StartTimer validates its required opts.
func TestStartTimerRejectsBadOpts(t *testing.T) {
	ctx := context.Background()
	_, errBadInterval := StartTimer(ctx, TimerOpts{ContactPath: "x", Interval: 0})
	require.Error(t, errBadInterval, "interval must be > 0")
	_, errEmptyPath := StartTimer(ctx, TimerOpts{ContactPath: "", Interval: time.Hour})
	require.Error(t, errEmptyPath, "contact path must be non-empty")
}

// TestHeartbeatPersistsThroughAudit asserts a heartbeat writes a readable
// contact timestamp and that LastContact reads it back (round-trip), and that a
// missing file reports found=false.
func TestHeartbeatPersistsThroughAudit(t *testing.T) {
	_, _, updater, contactPath := newTimerHarness(t)

	// Missing file: found=false, returns now.
	now := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	got, found, err := LastContact(contactPath, func() time.Time { return now })
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, now, got)

	// After a heartbeat: found=true, returns the heartbeat time.
	hbTime := time.Date(2026, 6, 20, 10, 30, 0, 0, time.UTC)
	require.NoError(t, Heartbeat(context.Background(), contactPath, updater, func() time.Time { return hbTime }))
	got2, found2, err := LastContact(contactPath, func() time.Time { return now })
	require.NoError(t, err)
	assert.True(t, found2)
	assert.Equal(t, hbTime.UTC(), got2)
}
