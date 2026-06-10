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

package daemon

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/notifyv2"
)

// captureNotifier records every SendNote for assertions; setting err makes
// SendNote fail (retry-queue tests).
type captureNotifier struct {
	mu    sync.Mutex
	notes []notifyv2.RenderedNote
	err   error
}

func (c *captureNotifier) Send(_ context.Context, _, _ string) error { return nil }

func (c *captureNotifier) SendNote(_ context.Context, n notifyv2.RenderedNote) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.notes = append(c.notes, n)
	return nil
}

func (c *captureNotifier) setErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *captureNotifier) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.notes)
}

func (c *captureNotifier) all() []notifyv2.RenderedNote {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]notifyv2.RenderedNote, len(c.notes))
	copy(out, c.notes)
	return out
}

// fakeClock is the injected clock for dispatcher tests — zero real sleeps
// (RESEARCH Pitfall 9).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// newTestDispatcher wires a dispatcher to a captureNotifier and a fakeClock.
func newTestDispatcher(t *testing.T) (*dispatcher, *captureNotifier, *fakeClock) {
	t.Helper()
	n := &captureNotifier{}
	d := newDispatcher(n, nil)
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	d.now = clk.Now
	d.lastRefill = clk.Now()
	return d, n, clk
}

// dispatchMsg builds a valid v2 message for dispatcher tests.
func dispatchMsg(kind notifyv2.Kind, pane string, epoch uint64) notifyv2.Message {
	return notifyv2.Message{
		V:        2,
		MsgID:    notifyv2.NewMsgID(),
		Kind:     kind,
		Host:     "rig-1",
		Session:  notifyv2.SessionRef{Session: "$1", Window: "@2", Pane: pane, Epoch: epoch},
		Consumer: "claudecode",
		Title:    "needs input",
	}
}

// TestDispatch_ValidateGate verifies the single policy-side gate: an invalid
// message is returned as an error and nothing is delivered.
func TestDispatch_ValidateGate(t *testing.T) {
	d, n, _ := newTestDispatcher(t)
	bad := dispatchMsg(notifyv2.KindNeedsInput, "%3", 1)
	bad.MsgID = "not-a-ulid"
	err := d.dispatch(context.Background(), bad, originExplicit, notifyv2.RenderOpts{})
	require.Error(t, err)
	assert.Equal(t, 0, n.count(), "an invalid message must never reach the notifier")
}

// TestDispatch_CooldownSuppressesHeuristicRepeats (D-08): a second
// heuristic-originated dispatch for the same (epoch, pane, kind) within the
// window is suppressed (success, not error); a different kind for the same
// pane is a separate key and delivers.
func TestDispatch_CooldownSuppressesHeuristicRepeats(t *testing.T) {
	d, n, _ := newTestDispatcher(t)
	ctx := context.Background()

	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	assert.Equal(t, 1, n.count(), "first heuristic dispatch must deliver")

	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	assert.Equal(t, 1, n.count(), "repeat within the cooldown window must be suppressed")

	suppressed, _ := d.paneStats(1, "%3")
	assert.Equal(t, 1, suppressed, "suppression must be counted (D-15)")

	done := dispatchMsg(notifyv2.KindCommandDone, "%3", 1)
	done.Title = "done"
	require.NoError(t, d.dispatch(ctx, done, originHeuristic, notifyv2.RenderOpts{}))
	assert.Equal(t, 2, n.count(), "a different kind for the same pane is a separate cooldown key")
}

// TestDispatch_EpochChangeClearsSuppression (RESEARCH Pitfall 5): the epoch is
// part of the cooldown key, so a tmux restart (new epoch) delivers immediately.
func TestDispatch_EpochChangeClearsSuppression(t *testing.T) {
	d, n, _ := newTestDispatcher(t)
	ctx := context.Background()

	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	require.Equal(t, 1, n.count(), "second dispatch at epoch 1 suppressed")

	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 2), originHeuristic, notifyv2.RenderOpts{}))
	assert.Equal(t, 2, n.count(), "same pane+kind at epoch 2 must deliver immediately")
}

// TestDispatch_ApprovalRequestNeverSuppressed (D-09): approval_request repeats
// within the window are never cooldown-suppressed.
func TestDispatch_ApprovalRequestNeverSuppressed(t *testing.T) {
	d, n, _ := newTestDispatcher(t)
	ctx := context.Background()

	for range 3 {
		m := dispatchMsg(notifyv2.KindApprovalRequest, "%3", 1)
		m.Title = "approval required"
		require.NoError(t, d.dispatch(ctx, m, originHeuristic, notifyv2.RenderOpts{}))
	}
	assert.Equal(t, 3, n.count(), "approval_request must never be suppressed (D-09)")
}

// TestDispatch_ExplicitBypassesCooldownButConsumesTokens (D-10): explicit POST
// asserts skip the cooldown check but still draw from the global ceiling.
func TestDispatch_ExplicitBypassesCooldownButConsumesTokens(t *testing.T) {
	d, n, _ := newTestDispatcher(t)
	ctx := context.Background()

	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	assert.Equal(t, 2, n.count(), "explicit assert must bypass the heuristic cooldown")

	d.mu.Lock()
	tokens := d.tokens
	d.mu.Unlock()
	assert.InDelta(t, bucketCapacity-2, tokens, 0.001, "explicit dispatches must still consume ceiling tokens")
}

// TestDispatch_CeilingMetaNotificationOncePerEpisode (D-11/D-12): the dispatch
// over capacity is dropped with exactly one ceiling-exempt meta-notification;
// further drops in the same episode add none; after a refill and a successful
// send, a new flood episode produces a new meta-notification.
func TestDispatch_CeilingMetaNotificationOncePerEpisode(t *testing.T) {
	d, n, clk := newTestDispatcher(t)
	ctx := context.Background()

	require.Equal(t, 30.0, bucketCapacity, "D-11 target: ~30 per 5 minutes")

	// Drain the bucket: 30 explicit dispatches all deliver.
	for i := range int(bucketCapacity) {
		_ = i
		require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	}
	require.Equal(t, 30, n.count())

	// 31st: dropped + exactly one meta-notification.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	require.Equal(t, 31, n.count(), "ceiling trip must send the ceiling-exempt meta-notification")
	assert.Contains(t, n.all()[30].Title, "notification flood, suppressing")

	// More over-ceiling dispatches in the same episode: no second meta.
	for range 3 {
		require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	}
	assert.Equal(t, 31, n.count(), "one meta-notification per flood episode (D-12)")

	// Refill one token, send successfully → episode resets.
	clk.Advance(bucketRefillEvery)
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	require.Equal(t, 32, n.count(), "a refilled token must deliver normally")

	// Bucket empty again → new episode, new meta-notification.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	require.Equal(t, 33, n.count(), "a new flood episode must produce a new meta-notification")
	flood := 0
	for _, note := range n.all() {
		if strings.Contains(note.Title, "notification flood, suppressing") {
			flood++
		}
	}
	assert.Equal(t, 2, flood, "exactly one meta-notification per episode across both episodes")
}

// TestDispatch_RetryQueueDeliversAfterFailure (D-28): a failed SendNote is
// queued and delivered on a later retry tick once the backend recovers.
func TestDispatch_RetryQueueDeliversAfterFailure(t *testing.T) {
	d, n, clk := newTestDispatcher(t)
	ctx := context.Background()

	n.setErr(errors.New("ntfy unreachable"))
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}),
		"delivery failure must not surface as a dispatch error — it enters the retry queue")
	require.Equal(t, 0, n.count())
	d.mu.Lock()
	queued := len(d.retry)
	d.mu.Unlock()
	require.Equal(t, 1, queued)

	n.setErr(nil)
	clk.Advance(d.retryBase + time.Second)
	d.processRetries(ctx)
	assert.Equal(t, 1, n.count(), "a retry tick after the backend recovers must deliver the queued note")
	d.mu.Lock()
	left := len(d.retry)
	d.mu.Unlock()
	assert.Equal(t, 0, left)
}

// TestDispatch_RetryQueueOverflowDropsOldest (D-28): the queue is bounded at
// retryDepth; overflow drops the oldest entry.
func TestDispatch_RetryQueueOverflowDropsOldest(t *testing.T) {
	d, n, _ := newTestDispatcher(t)
	ctx := context.Background()
	// Plenty of tokens: bump capacity is fixed, so refill between batches.
	d.tokens = float64(retryDepth + 10)

	n.setErr(errors.New("ntfy unreachable"))
	for i := range retryDepth + 1 {
		m := dispatchMsg(notifyv2.KindNeedsInput, "%3", uint64(i+1)) //nolint:gosec // gosec: test loop index, never negative
		require.NoError(t, d.dispatch(ctx, m, originExplicit, notifyv2.RenderOpts{}))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	assert.Len(t, d.retry, retryDepth, "queue must stay bounded at depth %d", retryDepth)
	// Anchored: a bare Contains("epoch 2") would also match epochs 20-29
	// (IN-06), false-passing a regression that drops more than one entry.
	assert.Regexp(t, `epoch 2$`, d.retry[0].note.Body, "the OLDEST entry (epoch 1) must have been dropped")
	assert.NotRegexp(t, `epoch 1$`, d.retry[0].note.Body)
}

// TestDispatch_RetryQueueDropsExpired (D-28): entries older than the max age
// are dropped, not retried forever.
func TestDispatch_RetryQueueDropsExpired(t *testing.T) {
	d, n, clk := newTestDispatcher(t)
	ctx := context.Background()

	n.setErr(errors.New("ntfy unreachable"))
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	n.setErr(nil)

	clk.Advance(retryMaxAge + time.Minute)
	d.processRetries(ctx)
	assert.Equal(t, 0, n.count(), "an expired entry must be dropped, never delivered late")
	d.mu.Lock()
	left := len(d.retry)
	d.mu.Unlock()
	assert.Equal(t, 0, left)
}

// TestDispatch_RunDeliversRetries: the run loop (real ticker at a short test
// retryBase) drains the retry queue and exits on ctx cancellation.
func TestDispatch_RunDeliversRetries(t *testing.T) {
	d, n, clk := newTestDispatcher(t)
	d.retryBase = time.Millisecond

	n.setErr(errors.New("ntfy unreachable"))
	require.NoError(t, d.dispatch(context.Background(), dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	n.setErr(nil)
	clk.Advance(time.Second) // entry is due

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.run(ctx)

	require.Eventually(t, func() bool { return n.count() == 1 },
		100*time.Millisecond, 2*time.Millisecond, "run loop must deliver the due retry entry")
}

// TestDispatch_PaneStats (D-15): suppressed count and latest cooldown-until
// for a pane with active suppression; zero values otherwise.
func TestDispatch_PaneStats(t *testing.T) {
	d, _, clk := newTestDispatcher(t)
	ctx := context.Background()

	armed := clk.Now()
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))

	suppressed, until := d.paneStats(1, "%3")
	assert.Equal(t, 2, suppressed)
	assert.Equal(t, armed.Add(d.cooldownDur), until, "cooldown_until must reflect the armed window")

	suppressed, until = d.paneStats(1, "%9")
	assert.Equal(t, 0, suppressed, "a pane with no suppression reports zero")
	assert.True(t, until.IsZero(), "a pane with no suppression reports a zero cooldown_until")
}

// TestDispatch_FreshStateIsEmpty (D-13): all policy state is memory-only by
// construction — a fresh dispatcher starts empty.
func TestDispatch_FreshStateIsEmpty(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	suppressed, until := d.paneStats(1, "%3")
	assert.Equal(t, 0, suppressed)
	assert.True(t, until.IsZero())
	d.mu.Lock()
	defer d.mu.Unlock()
	assert.Empty(t, d.retry)
	assert.InDelta(t, bucketCapacity, d.tokens, 0.001, "the bucket starts full")
}

// TestDispatch_ClickURLDefault (D-16): an empty RenderOpts.Click defaults to
// the dispatcher's server-side composed ssh:// deep link; a caller-resolved
// Click passes through untouched.
func TestDispatch_ClickURLDefault(t *testing.T) {
	d, n, _ := newTestDispatcher(t)
	d.clickURL = "ssh://mo@rig-1"
	ctx := context.Background()

	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit, notifyv2.RenderOpts{}))
	require.Equal(t, 1, n.count())
	assert.Equal(t, "ssh://mo@rig-1", n.all()[0].Click)

	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originExplicit,
		notifyv2.RenderOpts{Click: "ssh://other@rig-2"}))
	assert.Equal(t, "ssh://other@rig-2", n.all()[1].Click, "a caller-resolved Click must pass through")
}

// TestDispatch_PruneExpiredCooldown (WR-04): after the cooldown window
// expires, the next dispatch triggers pruneLocked which deletes the expired
// keys from both cooldown and suppressed maps.
func TestDispatch_PruneExpiredCooldown(t *testing.T) {
	d, _, clk := newTestDispatcher(t)
	ctx := context.Background()

	expiredKey := cooldownKey{epoch: 1, pane: "%3", kind: notifyv2.KindNeedsInput}

	// First dispatch: creates a cooldown entry.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	// Second dispatch within window: suppressed, increments suppressed counter.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))

	d.mu.Lock()
	assert.Len(t, d.cooldown, 1, "one cooldown entry must exist after first dispatch")
	assert.Len(t, d.suppressed, 1, "one suppressed entry must exist after second dispatch")
	d.mu.Unlock()

	// Advance clock past the cooldown window.
	clk.Advance(d.cooldownDur + time.Second)

	// Any new dispatch triggers pruneLocked, which deletes expired entries.
	// Note: this dispatch itself creates a new cooldown entry for %9, so we
	// assert the OLD key is gone, not that the map is empty.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindCommandDone, "%9", 1), originHeuristic, notifyv2.RenderOpts{}))

	d.mu.Lock()
	_, hasExpired := d.cooldown[expiredKey]
	_, hasExpiredSup := d.suppressed[expiredKey]
	d.mu.Unlock()
	assert.False(t, hasExpired, "expired cooldown key must be pruned")
	assert.False(t, hasExpiredSup, "suppressed entry must be pruned when its cooldown expires")
}

// TestDispatch_PruneDeadEpochEntries (WR-04): when a new epoch is seen, all
// entries from prior epochs are deleted from both maps — even if their until
// timestamp is still in the future (tmux restarted: old panes are dead).
func TestDispatch_PruneDeadEpochEntries(t *testing.T) {
	d, _, clk := newTestDispatcher(t)
	ctx := context.Background()

	// Epoch 1: create a cooldown + suppressed entry.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))

	d.mu.Lock()
	assert.Len(t, d.cooldown, 1, "one epoch-1 cooldown entry")
	assert.Len(t, d.suppressed, 1, "one epoch-1 suppressed entry")
	d.mu.Unlock()

	// The cooldown is NOT expired yet (advance only a fraction of the window).
	clk.Advance(10 * time.Second)

	// Epoch 2 dispatch: triggers pruneLocked which deletes epoch-1 entries.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%7", 2), originHeuristic, notifyv2.RenderOpts{}))

	d.mu.Lock()
	defer d.mu.Unlock()
	// Epoch-1 key must be gone even though its until is still in the future.
	for k := range d.cooldown {
		assert.Equal(t, uint64(2), k.epoch, "only epoch-2 keys must remain in cooldown")
	}
	for k := range d.suppressed {
		assert.Equal(t, uint64(2), k.epoch, "only epoch-2 keys must remain in suppressed")
	}
}

// TestDispatch_PaneStatsSkipsExpiredCooldown (D-15 honesty): paneStats must
// return zero suppressed_count and a zero cooldown_until for a pane whose
// cooldown window has expired — even when no dispatch has triggered pruning.
func TestDispatch_PaneStatsSkipsExpiredCooldown(t *testing.T) {
	d, _, clk := newTestDispatcher(t)
	ctx := context.Background()

	// Create a cooldown + suppressed entry.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))

	// Advance past the cooldown window WITHOUT triggering another dispatch.
	clk.Advance(d.cooldownDur + time.Second)

	// paneStats must skip the expired entry: honest reporting requires that
	// past-cooldown entries are not counted (D-15 cooldown_until honesty).
	suppressed, until := d.paneStats(1, "%3")
	assert.Equal(t, 0, suppressed, "paneStats must return 0 suppressed for an expired cooldown")
	assert.True(t, until.IsZero(), "paneStats must return zero cooldown_until for an expired cooldown")
}

// TestNewDispatcher_CooldownConfig: session_registry.cooldown_secs overrides
// the compiled-in 300s default (zero means default).
func TestNewDispatcher_CooldownConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.SessionRegistry.CooldownSecs = 60
	d := newDispatcher(&captureNotifier{}, cfg)
	assert.Equal(t, 60*time.Second, d.cooldownDur)

	d = newDispatcher(&captureNotifier{}, nil)
	assert.Equal(t, defaultCooldown, d.cooldownDur, "nil config must fall back to the 300s default")
}

// TestDispatch_ExplicitEpochCannotPoisonMaxEpoch (WR-01): Session.Epoch on an
// explicit POST is client-controlled and unbounded; it must never advance
// maxEpoch, or one forged huge value would make pruneLocked delete every real
// cooldown key on every dispatch — permanently disabling D-08 suppression and
// zeroing D-15 stats until daemon restart.
func TestDispatch_ExplicitEpochCannotPoisonMaxEpoch(t *testing.T) {
	d, n, _ := newTestDispatcher(t)
	ctx := context.Background()

	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	require.Equal(t, 1, n.count())

	forged := dispatchMsg(notifyv2.KindNeedsInput, "%9", math.MaxUint64)
	require.NoError(t, d.dispatch(ctx, forged, originExplicit, notifyv2.RenderOpts{}))
	require.Equal(t, 2, n.count(), "explicit asserts always deliver (D-10)")

	// The heuristic repeat at the REAL epoch must still be suppressed: the
	// forged explicit epoch must not have pruned its live cooldown key.
	require.NoError(t, d.dispatch(ctx, dispatchMsg(notifyv2.KindNeedsInput, "%3", 1), originHeuristic, notifyv2.RenderOpts{}))
	assert.Equal(t, 2, n.count(), "cooldown must survive a forged explicit epoch (WR-01)")

	suppressed, _ := d.paneStats(1, "%3")
	assert.Equal(t, 1, suppressed, "D-15 stats must survive a forged explicit epoch")
	d.mu.Lock()
	assert.Equal(t, uint64(1), d.maxEpoch, "maxEpoch advances only from heuristic dispatches")
	d.mu.Unlock()
}

// TestDispatch_RequeueRespectsDepthAndDropsTrueOldest (WR-02/D-28): failed
// retries re-enter the queue inside the depth bound in one locked section,
// and overflow drops the entry with the earliest firstTried — re-appends put
// old entries at the back of the slice, so index 0 is not the oldest.
func TestDispatch_RequeueRespectsDepthAndDropsTrueOldest(t *testing.T) {
	d, n, clk := newTestDispatcher(t)
	ctx := context.Background()
	n.setErr(errors.New("ntfy unreachable"))

	// Fill the queue to capacity in REVERSED age order: index 0 newest
	// (firstTried latest), the true oldest at the end.
	base := clk.Now()
	d.mu.Lock()
	for i := range retryDepth {
		d.retry = append(d.retry, retryEntry{
			note:       notifyv2.RenderedNote{Title: "queued"},
			attempts:   1,
			firstTried: base.Add(time.Duration(retryDepth-i) * time.Second),
			nextTry:    base,
		})
	}
	d.mu.Unlock()

	// All entries are due and all sends fail: the re-queue must come back at
	// exactly retryDepth, never beyond it.
	d.processRetries(ctx)
	d.mu.Lock()
	require.Len(t, d.retry, retryDepth, "re-queue must respect the D-28 depth bound")
	d.mu.Unlock()

	// Overflow now: the drop must remove the earliest firstTried (base+1s),
	// not whatever happens to sit at index 0.
	clk.Advance(time.Hour)
	d.enqueueRetry(notifyv2.RenderedNote{Title: "newest"})
	d.mu.Lock()
	defer d.mu.Unlock()
	require.Len(t, d.retry, retryDepth)
	oldest := d.retry[0].firstTried
	for _, e := range d.retry {
		if e.firstTried.Before(oldest) {
			oldest = e.firstTried
		}
	}
	assert.Equal(t, base.Add(2*time.Second), oldest,
		"the TRUE oldest entry (earliest firstTried) must be dropped, not index 0")
}
