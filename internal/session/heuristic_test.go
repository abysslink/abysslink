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

package session

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// ---- test plumbing ----

// fakeClock is the injected heuristic clock (RESEARCH Pitfall 9): tests
// advance it explicitly, so no heuristic test ever really sleeps.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1700000000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// countHandler counts slog records at Warn and above so tests can assert
// warn-once semantics (D-01 floor clamp) and drop warnings (T-27-11).
type countHandler struct {
	mu    sync.Mutex
	warns int
	msgs  []string
}

func (h *countHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countHandler) Handle(_ context.Context, rec slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if rec.Level >= slog.LevelWarn {
		h.warns++
		h.msgs = append(h.msgs, rec.Message)
	}
	return nil
}

func (h *countHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *countHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *countHandler) warnCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.warns
}

func (h *countHandler) warnMsgs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.msgs))
	copy(out, h.msgs)
	return out
}

// captureWarns swaps the default slog logger for a counting handler for the
// duration of the test.
func captureWarns(t *testing.T) *countHandler {
	t.Helper()
	h := &countHandler{}
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })
	return h
}

// tickCalls builds the scripted MockRunner calls for ONE heuristic poll tick:
// the list-panes poll followed by one capture-pane result per eligible pane
// (eligible panes are visited in numeric pane-ID order, so FIFO scripting is
// deterministic).
func tickCalls(panesOut string, captures ...string) []shell.Call {
	calls := []shell.Call{{Result: shell.Result{Stdout: panesOut}}}
	for _, c := range captures {
		calls = append(calls, shell.Call{Result: shell.Result{Stdout: c}})
	}
	return calls
}

// joinCalls flattens per-tick call groups into one scripted sequence.
func joinCalls(groups ...[]shell.Call) []shell.Call {
	var all []shell.Call
	for _, g := range groups {
		all = append(all, g...)
	}
	return all
}

// onlyPane returns the single pane of a single-session single-window snapshot.
func onlyPane(t *testing.T, r *Registry) PaneState {
	t.Helper()
	snap := r.Snapshot()
	require.Len(t, snap.Sessions, 1)
	require.Len(t, snap.Sessions[0].Windows, 1)
	require.Len(t, snap.Sessions[0].Windows[0].Panes, 1)
	return snap.Sessions[0].Windows[0].Panes[0]
}

// Standard one-pane list-panes output (claude in $1/@1/%1, attached 1).
func onePaneLine() string {
	return paneLine("$1", "@1", "%1", "0", "1", "1", "claude", "work", "editor") + "\n"
}

// Pane contents for the heuristic to look at.
const (
	promptTailContent = "$ make deploy\nbuilding the thing\ncontinue? \n"
	busyTailContent   = "compiling foo.c\nlinking bar\nbuilding target 4 of 9\n"
)

// newHeuristicRegistry wires a registry over scripted calls with an injected
// fake clock.
func newHeuristicRegistry(cfg *config.Config, calls ...shell.Call) (*Registry, *fakeClock, *shell.MockRunner) {
	m := shell.NewMockRunner(calls...)
	r := New(m, cfg)
	clk := newFakeClock()
	r.now = clk.now
	return r, clk, m
}

// ---- D-01..D-07 behavior ----

// TestHeuristicSetOnIdlePrompt: a pane whose capture output stops changing
// for >= the idle threshold and whose last non-blank line is "continue? "
// becomes needs_input (BACK-04).
func TestHeuristicSetOnIdlePrompt(t *testing.T) {
	line := onePaneLine()
	r, clk, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(line, promptTailContent),
		tickCalls(line, promptTailContent),
	)...)
	ctx := context.Background()

	r.pollTick(ctx)
	assert.False(t, onlyPane(t, r).NeedsInput, "first observation only baselines the content hash")

	clk.advance(30 * time.Second)
	r.pollTick(ctx)
	p := onlyPane(t, r)
	assert.True(t, p.NeedsInput, "idle past threshold at a prompt-shaped tail must set needs_input")
	assert.Equal(t, clk.now(), p.NeedsInputSince, "NeedsInputSince must come from the injected clock")
}

// TestHeuristicNonPromptTailStaysFalse: identical idle pattern but a busy,
// non-prompt tail — needs_input must stay false.
func TestHeuristicNonPromptTailStaysFalse(t *testing.T) {
	line := onePaneLine()
	r, clk, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(line, busyTailContent),
		tickCalls(line, busyTailContent),
	)...)
	ctx := context.Background()

	r.pollTick(ctx)
	clk.advance(30 * time.Second)
	r.pollTick(ctx)
	assert.False(t, onlyPane(t, r).NeedsInput, "a non-prompt tail must never set needs_input")
}

// TestHeuristicThreeLineBoundary: D-03 — the prompt marker on the
// third-from-last non-blank line (boxed prompt) IS detected; a prompt-shaped
// line four non-blank lines up is NOT.
func TestHeuristicThreeLineBoundary(t *testing.T) {
	line := onePaneLine()
	// Prompt marker is third-from-last non-blank; trailing blank lines must
	// not count toward the window.
	boxed := "Continue? (y/n)\n| filler one |\n| filler two |\n\n\n"
	// Prompt marker is FOUR non-blank lines up: out of the D-03 window.
	deep := "Continue? (y/n)\nfiller one\nfiller two\nfiller three\n"

	rBoxed, clkB, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(line, boxed), tickCalls(line, boxed))...)
	ctx := context.Background()
	rBoxed.pollTick(ctx)
	clkB.advance(30 * time.Second)
	rBoxed.pollTick(ctx)
	assert.True(t, onlyPane(t, rBoxed).NeedsInput, "prompt on line 3-from-last must be detected (D-03)")

	rDeep, clkD, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(line, deep), tickCalls(line, deep))...)
	rDeep.pollTick(ctx)
	clkD.advance(30 * time.Second)
	rDeep.pollTick(ctx)
	assert.False(t, onlyPane(t, rDeep).NeedsInput, "prompt 4 lines up must NOT be detected (D-03 window is 3)")

	// The same boundary at the helper level, both ways.
	assert.True(t, promptShaped(lastNonBlankLines(boxed, 3), nil))
	assert.False(t, promptShaped(lastNonBlankLines(deep, 3), nil))
}

// TestSentinelSetContents pins the built-in D-02 sentinel set: single-char
// prompt tails, interactive phrases (case-insensitive), and clear negatives.
func TestSentinelSetContents(t *testing.T) {
	positives := []string{
		"$", "user@host ~ $", "%", ">", "#", "?", ":", "❯", "» ",
		"Proceed (y/n)", "proceed (Y/N)", "Delete file [y/n]",
		"Are you sure (yes/no)", "Password:", "password: ", "Continue?",
	}
	for _, s := range positives {
		assert.True(t, promptShaped([]string{s}, nil), "expected prompt-shaped: %q", s)
	}

	negatives := []string{
		"building target 4 of 9", "done.", "| box |", "all tests passed", "",
	}
	for _, s := range negatives {
		assert.False(t, promptShaped([]string{s}, nil), "expected NOT prompt-shaped: %q", s)
	}
}

// TestSentinelPromptRegexExtension: a config prompt_regex catches a line the
// built-in set misses (D-02 extension point), and the sentinel set still
// applies alongside it.
func TestSentinelPromptRegexExtension(t *testing.T) {
	cfg := config.Defaults()
	cfg.SessionRegistry.PromptRegex = "AWAITING INPUT$"
	line := onePaneLine()
	awaiting := "doing things\nstill going\nAWAITING INPUT\n"

	r, clk, _ := newHeuristicRegistry(cfg, joinCalls(
		tickCalls(line, awaiting), tickCalls(line, awaiting))...)
	ctx := context.Background()
	r.pollTick(ctx)
	clk.advance(30 * time.Second)
	r.pollTick(ctx)
	assert.True(t, onlyPane(t, r).NeedsInput, "prompt_regex must extend the sentinel set (D-02)")

	// Built-in sentinels still apply with a prompt_regex configured.
	r2, clk2, _ := newHeuristicRegistry(cfg, joinCalls(
		tickCalls(line, promptTailContent), tickCalls(line, promptTailContent))...)
	r2.pollTick(ctx)
	clk2.advance(30 * time.Second)
	r2.pollTick(ctx)
	assert.True(t, onlyPane(t, r2).NeedsInput, "built-in sentinels must still apply alongside prompt_regex")
}

// TestHeuristicClearOnOutput: new output (hash change) clears needs_input AND
// resets the idle window — the pane must idle a full threshold again before
// re-setting.
func TestHeuristicClearOnOutput(t *testing.T) {
	line := onePaneLine()
	fresh := "fresh output after the clear\ncontinue? \n" // changed AND prompt-shaped
	r, clk, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(line, promptTailContent),
		tickCalls(line, promptTailContent),
		tickCalls(line, fresh),
		tickCalls(line, fresh),
		tickCalls(line, fresh),
	)...)
	ctx := context.Background()

	r.pollTick(ctx)
	clk.advance(30 * time.Second)
	r.pollTick(ctx)
	require.True(t, onlyPane(t, r).NeedsInput)

	// Tick 3: content changed — clear + idleSince reset.
	r.pollTick(ctx)
	p := onlyPane(t, r)
	assert.False(t, p.NeedsInput, "new output must clear needs_input (D-04)")
	assert.True(t, p.NeedsInputSince.IsZero(), "clear must zero NeedsInputSince")

	// Tick 4 at +29s: still under the (reset) threshold — must stay false.
	clk.advance(29 * time.Second)
	r.pollTick(ctx)
	assert.False(t, onlyPane(t, r).NeedsInput, "idle window must restart at the clearing output")

	// Tick 5 at +30s total since the change: sets again.
	clk.advance(1 * time.Second)
	r.pollTick(ctx)
	assert.True(t, onlyPane(t, r).NeedsInput)
}

// TestIdleFloorClamp: D-01 — idle_secs 5 clamps to the 10s floor with exactly
// one warning; 12 passes through; zero means the compiled-in 30s default.
func TestIdleFloorClamp(t *testing.T) {
	h := captureWarns(t)

	cfg5 := config.Defaults()
	cfg5.SessionRegistry.IdleSecs = 5
	r5 := New(shell.NewMockRunner(), cfg5)
	assert.Equal(t, 10*time.Second, r5.idleThreshold(), "idle_secs 5 must clamp to the 10s floor")
	assert.Equal(t, 10*time.Second, r5.idleThreshold())
	require.Equal(t, 1, h.warnCount(), "floor clamp must warn exactly once (D-01)")
	assert.Contains(t, h.warnMsgs()[0], "idle_secs")

	cfg12 := config.Defaults()
	cfg12.SessionRegistry.IdleSecs = 12
	r12 := New(shell.NewMockRunner(), cfg12)
	assert.Equal(t, 12*time.Second, r12.idleThreshold(), "idle_secs 12 must pass through")

	cfg0 := config.Defaults()
	r0 := New(shell.NewMockRunner(), cfg0)
	assert.Equal(t, 30*time.Second, r0.idleThreshold(), "zero idle_secs means the 30s default")

	assert.Equal(t, 1, h.warnCount(), "pass-through and default must not warn")
}

// TestHeuristicAlternateScreenExempt: D-06 — a pane with alternate_on is
// never captured and never set, even idle.
func TestHeuristicAlternateScreenExempt(t *testing.T) {
	altLine := paneLine("$1", "@1", "%1", "1", "1", "1", "vim", "work", "editor") + "\n"
	// No capture-pane results are scripted: the exempt pane must be skipped.
	r, clk, m := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(altLine), tickCalls(altLine))...)
	ctx := context.Background()

	r.pollTick(ctx)
	clk.advance(30 * time.Second)
	r.pollTick(ctx)

	assert.False(t, onlyPane(t, r).NeedsInput, "alternate-screen panes are exempt (D-06)")
	for _, argv := range m.RunCalls() {
		if len(argv) > 1 {
			assert.NotEqual(t, "capture-pane", argv[1], "exempt panes must never be captured")
		}
	}
}

// TestHeuristicIgnoreList: D-07 — panes in an ignore_sessions session are
// never captured and never set.
func TestHeuristicIgnoreList(t *testing.T) {
	cfg := config.Defaults()
	cfg.SessionRegistry.IgnoreSessions = []string{"logs"}
	logsLine := paneLine("$1", "@1", "%1", "0", "1", "1", "tail", "logs", "stream") + "\n"
	r, clk, m := newHeuristicRegistry(cfg, joinCalls(
		tickCalls(logsLine), tickCalls(logsLine))...)
	ctx := context.Background()

	r.pollTick(ctx)
	clk.advance(30 * time.Second)
	r.pollTick(ctx)

	assert.False(t, onlyPane(t, r).NeedsInput, "ignore_sessions panes are exempt (D-07)")
	for _, argv := range m.RunCalls() {
		if len(argv) > 1 {
			assert.NotEqual(t, "capture-pane", argv[1], "ignored sessions must never be captured")
		}
	}
}

// ---- D-05 adaptive cadence ----

// TestCadenceAdaptive: pollTick schedules the next tick at 5s when any pane's
// content changed this tick, 15s when all idle — no real sleeping anywhere.
func TestCadenceAdaptive(t *testing.T) {
	line := onePaneLine()
	r, clk, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(line, promptTailContent),
		tickCalls(line, promptTailContent),
	)...)
	ctx := context.Background()

	d1 := r.pollTick(ctx)
	assert.Equal(t, 5*time.Second, d1, "a changed pane must schedule the active 5s cadence (D-05)")

	clk.advance(time.Second)
	d2 := r.pollTick(ctx)
	assert.Equal(t, 15*time.Second, d2, "all-idle must back off to the 15s cadence (D-05)")
}

// heurSleepRecorder records the heuristic loop's cadence waits without
// sleeping and cancels the loop after cancelAfter records.
type heurSleepRecorder struct {
	mu          sync.Mutex
	durations   []time.Duration
	cancelAfter int
	cancel      context.CancelFunc
}

func (s *heurSleepRecorder) sleep(_ context.Context, d time.Duration) {
	s.mu.Lock()
	s.durations = append(s.durations, d)
	n := len(s.durations)
	s.mu.Unlock()
	if n >= s.cancelAfter {
		s.cancel()
	}
}

func (s *heurSleepRecorder) recorded() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]time.Duration, len(s.durations))
	copy(out, s.durations)
	return out
}

// ---- transition emission (plan 27-06 Task 2) ----

// drainEvents empties the Events channel without blocking.
func drainEvents(r *Registry) []Transition {
	var out []Transition
	for {
		select {
		case tr := <-r.Events():
			out = append(out, tr)
		default:
			return out
		}
	}
}

// TestTransitionEdgeSemantics: emission is edge-triggered, never
// level-triggered — three consecutive idle+prompt ticks emit exactly ONE
// TransitionNeedsInput, the clearing tick exactly ONE TransitionCleared, and
// every Transition carries the full identity set.
func TestTransitionEdgeSemantics(t *testing.T) {
	line := onePaneLine()
	fresh := "new output after the answer\n$ \n"
	r, clk, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(line, promptTailContent), // tick 1: baseline
		tickCalls(line, promptTailContent), // tick 2: idle past threshold -> set
		tickCalls(line, promptTailContent), // tick 3: still set -> NO emission
		tickCalls(line, promptTailContent), // tick 4: still set -> NO emission
		tickCalls(line, fresh),             // tick 5: output change -> clear
	)...)
	r.bumpEpoch() // transitions must carry the live epoch
	ctx := context.Background()

	r.pollTick(ctx)
	clk.advance(30 * time.Second)
	r.pollTick(ctx)
	clk.advance(5 * time.Second)
	r.pollTick(ctx)
	clk.advance(5 * time.Second)
	r.pollTick(ctx)

	events := drainEvents(r)
	require.Len(t, events, 1, "three consecutive idle+prompt ticks must emit exactly ONE NeedsInput")
	ni := events[0]
	assert.Equal(t, TransitionNeedsInput, ni.Type)
	assert.Equal(t, "$1", ni.SessionID)
	assert.Equal(t, "@1", ni.WindowID)
	assert.Equal(t, "%1", ni.PaneID)
	assert.Equal(t, uint64(1), ni.Epoch)
	assert.Equal(t, "claude", ni.Consumer)
	assert.Equal(t, "work", ni.SessionName)
	assert.Equal(t, "editor", ni.WindowName)

	r.pollTick(ctx) // tick 5: the clear
	events = drainEvents(r)
	require.Len(t, events, 1, "the clearing tick must emit exactly ONE Cleared")
	cl := events[0]
	assert.Equal(t, TransitionCleared, cl.Type)
	assert.Equal(t, "%1", cl.PaneID)
	assert.Equal(t, uint64(1), cl.Epoch)
	assert.Equal(t, "claude", cl.Consumer)
	assert.Equal(t, "work", cl.SessionName)
	assert.Equal(t, "editor", cl.WindowName)
}

// TestAttachClearOnPollTick: D-04 — a poll where the session's attached
// count increased clears needs_input and emits Cleared with NO output change,
// and the idle window restarts so the next tick does not instantly re-set.
func TestAttachClearOnPollTick(t *testing.T) {
	attached1 := onePaneLine()
	attached2 := paneLine("$1", "@1", "%1", "0", "1", "2", "claude", "work", "editor") + "\n"
	r, clk, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(attached1, promptTailContent), // tick 1: baseline
		tickCalls(attached1, promptTailContent), // tick 2: set
		tickCalls(attached2, promptTailContent), // tick 3: attach 1->2, SAME content
		tickCalls(attached2, promptTailContent), // tick 4: +29s, window restarted
	)...)
	r.bumpEpoch()
	ctx := context.Background()

	r.pollTick(ctx)
	clk.advance(30 * time.Second)
	r.pollTick(ctx)
	events := drainEvents(r)
	require.Len(t, events, 1)
	require.Equal(t, TransitionNeedsInput, events[0].Type)

	// Tick 3: the attached count increases with the pane content unchanged.
	r.pollTick(ctx)
	events = drainEvents(r)
	require.Len(t, events, 1, "attach increase must emit exactly one Cleared (D-04)")
	assert.Equal(t, TransitionCleared, events[0].Type)
	assert.Equal(t, "%1", events[0].PaneID)
	p := onlyPane(t, r)
	assert.False(t, p.NeedsInput, "client attach must clear needs_input without any output change")
	assert.True(t, p.NeedsInputSince.IsZero())

	// Tick 4 at +29s after the clear: idle window restarted -> must NOT
	// re-set (and so must not emit).
	clk.advance(29 * time.Second)
	r.pollTick(ctx)
	assert.False(t, onlyPane(t, r).NeedsInput, "attach-clear must restart the idle window")
	assert.Empty(t, drainEvents(r))
}

// TestTransitionChannelBoundDrop: with a full Events channel, emission drops
// with a warning and never blocks the caller (T-27-11) — and the state
// mutation still lands.
func TestTransitionChannelBoundDrop(t *testing.T) {
	h := captureWarns(t)
	r := newTestRegistry()
	r.syncPanes([]string{paneLine("$1", "@1", "%1", "0", "1", "1", "claude", "work", "editor")})
	for i := 0; i < eventsChanDepth; i++ {
		r.emit(Transition{Type: TransitionCleared, PaneID: "%9"})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.setNeedsInput("%1")
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("setNeedsInput blocked on a full Events channel")
	}

	assert.Len(t, r.events, eventsChanDepth, "the dropped transition must not grow the channel")
	assert.GreaterOrEqual(t, h.warnCount(), 1, "the drop must be logged, never silent")
	assert.True(t, onlyPane(t, r).NeedsInput, "the state mutation must land even when the emission drops")
}

// TestCadenceRunLoopSchedules: runHeuristic waits BEFORE each tick using the
// cadence the previous tick selected (initial wait = active cadence).
func TestCadenceRunLoopSchedules(t *testing.T) {
	line := onePaneLine()
	r, _, _ := newHeuristicRegistry(config.Defaults(), joinCalls(
		tickCalls(line, promptTailContent),
		tickCalls(line, promptTailContent),
	)...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &heurSleepRecorder{cancelAfter: 3, cancel: cancel}
	r.heurSleep = rec.sleep

	done := make(chan struct{})
	go func() { defer close(done); r.runHeuristic(ctx) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runHeuristic did not exit after ctx cancel")
	}

	want := []time.Duration{5 * time.Second, 5 * time.Second, 15 * time.Second}
	assert.Equal(t, want, rec.recorded(),
		"initial wait at active cadence; changed tick keeps 5s; idle tick backs off to 15s")
}
