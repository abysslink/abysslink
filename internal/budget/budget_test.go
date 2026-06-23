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

// Package budget_test is the external test package for internal/budget.
// See budget.go for KILL-01..05 and D-05/D-06 constraint references.
package budget_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/budget"
)

// --------------------------------------------------------------------------
// Helpers / fakes
// --------------------------------------------------------------------------

// fakeNotify records all SendAgentStopped calls.
type fakeNotify struct {
	mu      sync.Mutex
	reasons []string
}

func (f *fakeNotify) SendAgentStopped(_ context.Context, reason string) error {
	f.mu.Lock()
	f.reasons = append(f.reasons, reason)
	f.mu.Unlock()
	return nil
}

func (f *fakeNotify) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.reasons))
	copy(out, f.reasons)
	return out
}

// fakeAudit records Append calls.
type fakeAudit struct {
	mu      sync.Mutex
	entries []auditEntry
}

type auditEntry struct {
	op      string
	target  string
	content []byte
	dryRun  bool
}

func (f *fakeAudit) Append(op, target string, content []byte, dryRun bool) error {
	f.mu.Lock()
	f.entries = append(f.entries, auditEntry{op: op, target: target, content: content, dryRun: dryRun})
	f.mu.Unlock()
	return nil
}

func (f *fakeAudit) appended() []auditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]auditEntry, len(f.entries))
	copy(out, f.entries)
	return out
}

// fakeSig records signals sent to a fake pgid.
type fakeSig struct {
	mu   sync.Mutex
	sent []syscall.Signal
}

func (f *fakeSig) Kill(pgid int, sig syscall.Signal) error {
	f.mu.Lock()
	f.sent = append(f.sent, sig)
	f.mu.Unlock()
	return nil
}

func (f *fakeSig) signals() []syscall.Signal {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]syscall.Signal, len(f.sent))
	copy(out, f.sent)
	return out
}

// fakeGated holds the observer registered via SetObserver.
type fakeGated struct {
	mu  sync.Mutex
	obs func([32]byte)
}

func (g *fakeGated) SetObserver(fn func([32]byte)) {
	g.mu.Lock()
	g.obs = fn
	g.mu.Unlock()
}

func (g *fakeGated) push(h [32]byte) {
	g.mu.Lock()
	fn := g.obs
	g.mu.Unlock()
	if fn != nil {
		fn(h)
	}
}

// --------------------------------------------------------------------------
// TestLoopDetector_Push (KILL-01, D-03)
// --------------------------------------------------------------------------

func TestLoopDetector_Push(t *testing.T) {
	// Access loopDetector via the exported Watcher test-seam helper:
	// We need to test loopDetector.push() behavior via a Watcher with
	// a fakeGated that we push hashes through.

	t.Run("7_of_8_identical_not_tripped", func(t *testing.T) {
		// Push 7 identical hashes into a window of 20 with tripN=8 → not tripped.
		// We test this via fakeGated + observer tap + checking that notify
		// is NOT called after 7 pushes.
		notif := &fakeNotify{}
		aud := &fakeAudit{}
		fgated := &fakeGated{}
		sig := &fakeSig{}
		reg := approve.NewRegistry(nil)

		cfg := budget.Config{
			WallClock:  0, // disable wall-clock timer
			LoopN:      8,
			LoopWindow: 20,
			Ladder:     false,
			KillGrace:  5 * time.Second,
		}

		w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)
		w.SetSignalFn(sig.Kill)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		// Start Watch in background.
		h := [32]byte{1}
		watchDone := make(chan error, 1)
		go func() {
			watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
		}()

		// Push 7 identical hashes.
		for i := 0; i < 7; i++ {
			fgated.push(h)
		}

		// Let Watch run briefly then cancel.
		time.Sleep(50 * time.Millisecond)
		cancel()
		<-watchDone

		// Notify must NOT have been called.
		assert.Empty(t, notif.called(), "expected no notify after 7 identical hashes")
	})

	t.Run("8th_identical_trips", func(t *testing.T) {
		notif := &fakeNotify{}
		aud := &fakeAudit{}
		fgated := &fakeGated{}
		sig := &fakeSig{}
		reg := approve.NewRegistry(nil)

		cfg := budget.Config{
			WallClock:  0,
			LoopN:      8,
			LoopWindow: 20,
			Ladder:     false,
			KillGrace:  5 * time.Second,
		}

		w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)
		w.SetSignalFn(sig.Kill)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		h := [32]byte{2}
		watchDone := make(chan error, 1)
		go func() {
			watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
		}()

		// Push 8 identical hashes — 8th should trip.
		for i := 0; i < 8; i++ {
			fgated.push(h)
		}

		// Wait for notify to be called.
		require.Eventually(t, func() bool {
			return len(notif.called()) >= 1
		}, 400*time.Millisecond, 5*time.Millisecond, "expected notify after 8 identical hashes")

		reasons := notif.called()
		assert.Contains(t, reasons[0], "loop", "reason should contain 'loop'")

		cancel()
		<-watchDone
	})

	t.Run("saturated_window_still_tripped", func(t *testing.T) {
		notif := &fakeNotify{}
		aud := &fakeAudit{}
		fgated := &fakeGated{}
		sig := &fakeSig{}
		reg := approve.NewRegistry(nil)

		cfg := budget.Config{
			WallClock:  0,
			LoopN:      8,
			LoopWindow: 20,
			Ladder:     false,
			KillGrace:  5 * time.Second,
		}

		w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)
		w.SetSignalFn(sig.Kill)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		h := [32]byte{3}
		watchDone := make(chan error, 1)
		go func() {
			watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
		}()

		// Push 20 identical hashes (saturated window).
		for i := 0; i < 20; i++ {
			fgated.push(h)
		}

		// Should still notify after window saturation.
		require.Eventually(t, func() bool {
			return len(notif.called()) >= 1
		}, 400*time.Millisecond, 5*time.Millisecond, "expected notify on saturated window")

		cancel()
		<-watchDone
	})

	t.Run("different_hash_trips_separately", func(t *testing.T) {
		// Hash A repeated 5 times, then hash B repeated 8 → trips on B, not A.
		notif := &fakeNotify{}
		aud := &fakeAudit{}
		fgated := &fakeGated{}
		sig := &fakeSig{}
		reg := approve.NewRegistry(nil)

		cfg := budget.Config{
			WallClock:  0,
			LoopN:      8,
			LoopWindow: 20,
			Ladder:     false,
			KillGrace:  5 * time.Second,
		}

		w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)
		w.SetSignalFn(sig.Kill)

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		hashA := [32]byte{0xAA}
		hashB := [32]byte{0xBB}

		watchDone := make(chan error, 1)
		go func() {
			watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
		}()

		// Push A 5 times (below threshold).
		for i := 0; i < 5; i++ {
			fgated.push(hashA)
		}

		// At this point, still no trip (A has only 5).
		time.Sleep(20 * time.Millisecond)
		assert.Empty(t, notif.called(), "expected no notify after 5 of hash A")

		// Now push B 8 times — should trip.
		for i := 0; i < 8; i++ {
			fgated.push(hashB)
		}

		require.Eventually(t, func() bool {
			return len(notif.called()) >= 1
		}, 400*time.Millisecond, 5*time.Millisecond, "expected notify after 8 of hash B")

		reasons := notif.called()
		assert.Contains(t, reasons[0], "loop", "reason should contain 'loop'")

		cancel()
		<-watchDone
	})
}

// --------------------------------------------------------------------------
// TestWatcher_WallClock_Shadow (KILL-01, D-05)
// --------------------------------------------------------------------------

func TestWatcher_WallClock_Shadow(t *testing.T) {
	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	sig := &fakeSig{}
	reg := approve.NewRegistry(nil)

	// Use a fake clock that advances to 31 minutes.
	start := time.Now()
	var nowMu sync.Mutex
	fakeTime := start
	fakeClock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return fakeTime
	}

	cfg := budget.Config{
		WallClock:  30 * time.Minute,
		LoopN:      8,
		LoopWindow: 20,
		Ladder:     false,
		KillGrace:  5 * time.Second,
	}

	w := budget.NewWatcher(cfg, reg, aud, notif, fgated, fakeClock)
	w.SetSignalFn(sig.Kill)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	watchDone := make(chan error, 1)
	go func() {
		watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
	}()

	// Advance fake clock to 31 minutes.
	nowMu.Lock()
	fakeTime = start.Add(31 * time.Minute)
	nowMu.Unlock()

	// Wait for notify with reason "wall_clock".
	require.Eventually(t, func() bool {
		return len(notif.called()) >= 1
	}, 1500*time.Millisecond, 10*time.Millisecond, "expected wall-clock notify")

	reasons := notif.called()
	assert.Equal(t, "wall_clock", reasons[0], "reason should be wall_clock")

	// Shadow mode: SIGSTOP must NOT have been sent.
	sigs := sig.signals()
	for _, s := range sigs {
		assert.NotEqual(t, syscall.SIGSTOP, s, "shadow mode must not send SIGSTOP")
	}

	cancel()
	<-watchDone
}

// --------------------------------------------------------------------------
// TestWatcher_LoopDetect_Shadow (KILL-01, D-05)
// --------------------------------------------------------------------------

func TestWatcher_LoopDetect_Shadow(t *testing.T) {
	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	sig := &fakeSig{}
	reg := approve.NewRegistry(nil)

	cfg := budget.Config{
		WallClock:  0, // disable wall-clock
		LoopN:      8,
		LoopWindow: 20,
		Ladder:     false,
		KillGrace:  5 * time.Second,
	}

	w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)
	w.SetSignalFn(sig.Kill)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	h := [32]byte{0xDE, 0xAD}
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
	}()

	// Push 8 identical hashes via the registered observer.
	for i := 0; i < 8; i++ {
		fgated.push(h)
	}

	require.Eventually(t, func() bool {
		return len(notif.called()) >= 1
	}, 400*time.Millisecond, 5*time.Millisecond, "expected loop notify")

	reasons := notif.called()
	assert.Contains(t, reasons[0], "loop", "reason should contain 'loop'")

	// Shadow mode: no SIGSTOP.
	sigs := sig.signals()
	for _, s := range sigs {
		assert.NotEqual(t, syscall.SIGSTOP, s, "shadow mode must not send SIGSTOP")
	}

	cancel()
	<-watchDone
}

// --------------------------------------------------------------------------
// TestWatcher_TokenTiers_Disabled (KILL-01, D-04)
// --------------------------------------------------------------------------

func TestWatcher_TokenTiers_Disabled(t *testing.T) {
	// Config with no TokenTiers → token observation is disabled.
	// TotalTokens must never be called. Trivially passes since we have no
	// tokenParser wired — this test simply verifies the watcher doesn't crash.
	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	reg := approve.NewRegistry(nil)

	cfg := budget.Config{
		WallClock:  0,
		LoopN:      8,
		LoopWindow: 20,
		Ladder:     false,
		KillGrace:  5 * time.Second,
	}

	w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
	// context.DeadlineExceeded is expected.
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		"expected context error, got: %v", err)
}

// --------------------------------------------------------------------------
// TestBudget_NoClaude (structural coupling test)
// --------------------------------------------------------------------------

// TestBudget_NoClaude enforces the D-01a constraint: budget is a generic watcher
// and must NEVER import internal/modules/claudecode. Uses go/parser (stdlib) to
// scan non-test source files — same technique as TestGate_NoClaude (gate/gate_test.go:384).
func TestBudget_NoClaude(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, parser.ImportsOnly|parser.ParseComments)
		require.NoError(t, perr, "failed to parse %s", name)
		for _, imp := range f.Imports {
			path := imp.Path.Value
			assert.NotContains(t, path, "claudecode",
				"%s must not import claudecode (D-01a: budget is a generic watcher)", name)
		}
		checked++
	}
	assert.Positive(t, checked, "expected at least one non-test source file to check")
}

// --------------------------------------------------------------------------
// Task 2: Ladder mode tests (KILL-02, KILL-05)
// --------------------------------------------------------------------------

// TestWatcher_LadderMode_ApproveResume: trip threshold → SIGSTOP sent →
// phone Approve tap → SIGCONT sent, no kill.
func TestWatcher_LadderMode_ApproveResume(t *testing.T) {
	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	sig := &fakeSig{}
	reg := approve.NewRegistry(nil)

	cfg := budget.Config{
		WallClock:  0,
		LoopN:      8,
		LoopWindow: 20,
		Ladder:     true,
		KillGrace:  100 * time.Millisecond, // short grace for test
	}

	hmacKey := []byte("test-hmac-key-for-approve-32byte!!")

	w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)
	w.SetSignalFn(sig.Kill)
	w.SetHMACKey(hmacKey)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	h := [32]byte{0xCA, 0xFE}
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
	}()

	// Push 8 identical hashes to trip.
	for i := 0; i < 8; i++ {
		fgated.push(h)
	}

	// Wait for SIGSTOP to be sent.
	require.Eventually(t, func() bool {
		for _, s := range sig.signals() {
			if s == syscall.SIGSTOP {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected SIGSTOP after ladder trip")

	// Simulate phone Approve tap: resolve the pending request as approved.
	// The watcher opens a request via reg.OpenWithDenySig. We need to find the
	// request ID via the watcher's LastRequestID helper.
	// The request opens asynchronously after SIGSTOP, so poll rather than
	// reading once (single-shot read raced on loaded CI).
	var reqID string
	require.Eventually(t, func() bool {
		reqID = w.LastRequestID()
		return reqID != ""
	}, 2*time.Second, 10*time.Millisecond, "expected a pending request ID after SIGSTOP")
	ok := reg.Resolve(reqID, approve.StateApproved)
	require.True(t, ok, "expected resolve to succeed")

	// Wait for SIGCONT.
	require.Eventually(t, func() bool {
		for _, s := range sig.signals() {
			if s == syscall.SIGCONT {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected SIGCONT after Approve tap")

	// No SIGTERM or SIGKILL should have been sent.
	for _, s := range sig.signals() {
		assert.NotEqual(t, syscall.SIGTERM, s, "Approve should not trigger SIGTERM")
		assert.NotEqual(t, syscall.SIGKILL, s, "Approve should not trigger SIGKILL")
	}

	cancel()
	<-watchDone
}

// TestWatcher_LadderMode_NilRegistry_FailsOpen (T-31-21, defense-in-depth):
// a Watcher constructed with ladder:true but a nil *approve.Registry must FAIL
// OPEN at the first threshold trip — send SIGCONT and return WITHOUT a SIGSTOP
// and WITHOUT a nil-pointer panic. The agent must never be left frozen.
func TestWatcher_LadderMode_NilRegistry_FailsOpen(t *testing.T) {
	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	sig := &fakeSig{}

	cfg := budget.Config{
		WallClock:  0,
		LoopN:      8,
		LoopWindow: 20,
		Ladder:     true, // ladder enabled...
		KillGrace:  100 * time.Millisecond,
	}

	// ...but NO registry wired (the shipped-bug condition). NewWatcher must not
	// be given SetHMACKey either — this mirrors a mis-wired production path.
	w := budget.NewWatcher(cfg, nil /*reg*/, aud, notif, fgated, nil)
	w.SetSignalFn(sig.Kill)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	h := [32]byte{0xDE, 0xAD}
	watchDone := make(chan error, 1)
	go func() {
		// Watch must not panic even though w.reg is nil and ladder trips.
		watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
	}()

	// Trip the loop.
	for i := 0; i < 8; i++ {
		fgated.push(h)
	}

	// SIGCONT must be observed (fail open).
	require.Eventually(t, func() bool {
		for _, s := range sig.signals() {
			if s == syscall.SIGCONT {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected SIGCONT (fail open) when registry is nil")

	// SIGSTOP must NOT have been sent — the agent must never be frozen.
	for _, s := range sig.signals() {
		assert.NotEqual(t, syscall.SIGSTOP, s, "nil-registry fail-open must NOT send SIGSTOP")
		assert.NotEqual(t, syscall.SIGTERM, s, "nil-registry fail-open must NOT send SIGTERM")
		assert.NotEqual(t, syscall.SIGKILL, s, "nil-registry fail-open must NOT send SIGKILL")
	}

	cancel()
	<-watchDone
}

// TestWatcher_NoAnswerRenotify (D-06): approve context expires → stay frozen +
// re-notify, no SIGCONT/SIGTERM/SIGKILL.
func TestWatcher_NoAnswerRenotify(t *testing.T) {
	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	sig := &fakeSig{}
	reg := approve.NewRegistry(nil)

	cfg := budget.Config{
		WallClock:       0,
		LoopN:           8,
		LoopWindow:      20,
		Ladder:          true,
		KillGrace:       100 * time.Millisecond,
		ApprovalTimeout: 150 * time.Millisecond, // short timeout to force re-notify quickly
	}

	hmacKey := []byte("test-hmac-key-for-approve-32byte!!")

	w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)
	w.SetSignalFn(sig.Kill)
	w.SetHMACKey(hmacKey)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	h := [32]byte{0xBE, 0xEF}
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
	}()

	// Trip the loop detector.
	for i := 0; i < 8; i++ {
		fgated.push(h)
	}

	// Wait for SIGSTOP.
	require.Eventually(t, func() bool {
		for _, s := range sig.signals() {
			if s == syscall.SIGSTOP {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected SIGSTOP")

	// Wait for re-notify (second notification after timeout).
	require.Eventually(t, func() bool {
		return len(notif.called()) >= 2
	}, 2*time.Second, 10*time.Millisecond, "expected re-notify after approve timeout (D-06)")

	// SIGCONT must NOT have been sent (process stays frozen).
	sigs := sig.signals()
	for _, s := range sigs {
		assert.NotEqual(t, syscall.SIGCONT, s, "D-06: no-answer must not send SIGCONT")
		assert.NotEqual(t, syscall.SIGTERM, s, "D-06: no-answer must not send SIGTERM")
		assert.NotEqual(t, syscall.SIGKILL, s, "D-06: no-answer must not send SIGKILL")
	}

	cancel()
	// After cancel, watcher must send SIGCONT (safety net).
	<-watchDone
}

// TestWatcher_LadderMode_DenyKill (KILL-02): phone Deny → SIGTERM then SIGKILL.
func TestWatcher_LadderMode_DenyKill(t *testing.T) {
	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	sig := &fakeSig{}
	reg := approve.NewRegistry(nil)

	cfg := budget.Config{
		WallClock:       0,
		LoopN:           8,
		LoopWindow:      20,
		Ladder:          true,
		KillGrace:       50 * time.Millisecond, // very short grace for test
		ApprovalTimeout: 5 * time.Second,       // long timeout so we can control resolve
	}

	hmacKey := []byte("test-hmac-key-for-approve-32byte!!")

	w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)
	w.SetSignalFn(sig.Kill)
	w.SetHMACKey(hmacKey)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- w.Watch(ctx, 9999, "/tmp/nonexistent.cast", "", "")
	}()

	// Trip.
	for i := 0; i < 8; i++ {
		fgated.push(h)
	}

	// Wait for SIGSTOP.
	require.Eventually(t, func() bool {
		for _, s := range sig.signals() {
			if s == syscall.SIGSTOP {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected SIGSTOP")

	// Simulate phone Deny tap.
	// The request opens asynchronously after SIGSTOP, so poll rather than
	// reading once (single-shot read raced on loaded CI).
	var reqID string
	require.Eventually(t, func() bool {
		reqID = w.LastRequestID()
		return reqID != ""
	}, 2*time.Second, 10*time.Millisecond, "expected a pending request ID")
	ok := reg.Resolve(reqID, approve.StateDenied)
	require.True(t, ok, "expected resolve to succeed")

	// Wait for SIGTERM then SIGKILL (in order).
	require.Eventually(t, func() bool {
		sigs := sig.signals()
		hasTERM, hasKILL := false, false
		for _, s := range sigs {
			if s == syscall.SIGTERM {
				hasTERM = true
			}
			if s == syscall.SIGKILL {
				hasKILL = true
			}
		}
		return hasTERM && hasKILL
	}, 2*time.Second, 10*time.Millisecond, "expected SIGTERM then SIGKILL after Deny")

	// Verify order: SIGTERM before SIGKILL.
	sigs := sig.signals()
	termIdx, killIdx := -1, -1
	for i, s := range sigs {
		if s == syscall.SIGTERM && termIdx < 0 {
			termIdx = i
		}
		if s == syscall.SIGKILL && killIdx < 0 {
			killIdx = i
		}
	}
	assert.Greater(t, killIdx, termIdx, "SIGTERM must precede SIGKILL")

	cancel()
	<-watchDone
}

// TestWatcher_CastAuditBind (KILL-05): audit.Append called with op="arm-run:end"
// and non-nil castBytes after Watch returns.
func TestWatcher_CastAuditBind(t *testing.T) {
	// Create a real temporary cast file.
	f, err := os.CreateTemp("", "test-*.cast")
	require.NoError(t, err)
	castPath := f.Name()
	defer func() { _ = os.Remove(castPath) }()
	castContent := []byte(`{"version":2,"width":220,"height":50}` + "\n" + `[0.1,"o","hello"]`)
	_, err = f.Write(castContent)
	require.NoError(t, err)
	_ = f.Close()

	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	reg := approve.NewRegistry(nil)

	cfg := budget.Config{
		WallClock:  0,
		LoopN:      8,
		LoopWindow: 20,
		Ladder:     false,
		KillGrace:  5 * time.Second,
	}

	w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = w.Watch(ctx, 9999, castPath, "", "")

	// audit.Append must have been called with op="arm-run:end".
	entries := aud.appended()
	require.Len(t, entries, 1, "expected exactly one audit entry")
	assert.Equal(t, "arm-run:end", entries[0].op)
	assert.Equal(t, castPath, entries[0].target)
	assert.NotNil(t, entries[0].content, "castBytes must not be nil")
	assert.NotEmpty(t, entries[0].content, "castBytes must not be empty")

	// Verify the content passed is the actual cast bytes.
	expectedSum := sha256.Sum256(castContent)
	actualSum := sha256.Sum256(entries[0].content)
	assert.Equal(t, expectedSum, actualSum, "audit content hash should match cast file sha256")
}

// TestWatcher_CastAuditBind_MissingFile (KILL-05): castPath does not exist →
// Append called with sentinel bytes, no panic.
func TestWatcher_CastAuditBind_MissingFile(t *testing.T) {
	notif := &fakeNotify{}
	aud := &fakeAudit{}
	fgated := &fakeGated{}
	reg := approve.NewRegistry(nil)

	cfg := budget.Config{
		WallClock:  0,
		LoopN:      8,
		LoopWindow: 20,
		Ladder:     false,
		KillGrace:  5 * time.Second,
	}

	w := budget.NewWatcher(cfg, reg, aud, notif, fgated, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	missingPath := "/tmp/does-not-exist-abysslink-test-budget.cast"
	_ = w.Watch(ctx, 9999, missingPath, "", "")

	entries := aud.appended()
	require.Len(t, entries, 1, "expected exactly one audit entry even on missing file")
	assert.Equal(t, "arm-run:end", entries[0].op)
	// Sentinel bytes must NOT be nil (Pitfall 2: nil would produce well-known empty hash).
	assert.NotNil(t, entries[0].content)
	assert.NotEmpty(t, entries[0].content)
	// Sentinel must contain "cast-read-error:".
	assert.Contains(t, string(entries[0].content), "cast-read-error:",
		"sentinel bytes must contain cast-read-error: prefix")
}

// --------------------------------------------------------------------------
// Helpers for structural test
// --------------------------------------------------------------------------

var _ = fmt.Sprintf // satisfy import
