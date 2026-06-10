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
	"log/slog"
	"os/user"
	"sync"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/notifyv2"
)

// Dispatch policy constants (D-08, D-11, D-28). All state is memory-only and
// resets on daemon restart (D-13).
const (
	// defaultCooldown is the per-(epoch,pane,kind) re-notify suppression
	// window (D-08); session_registry.cooldown_secs overrides it.
	defaultCooldown = 5 * time.Minute
	// bucketCapacity / bucketRefillEvery implement the D-11 global flood
	// ceiling: a 30-token bucket refilling 1 token per 10s sustains the
	// ~30-per-5-minutes target while allowing a full-capacity initial burst.
	bucketCapacity    = 30.0
	bucketRefillEvery = 10 * time.Second
	// Bounded in-memory retry queue (D-28): depth 32 drop-oldest, base
	// interval 5s doubling per attempt to a 60s cap, entries dropped after
	// 5 minutes or 6 attempts.
	retryDepth       = 32
	retryBaseDefault = 5 * time.Second
	retryMaxBackoff  = 60 * time.Second
	retryMaxAge      = 5 * time.Minute
	retryMaxAttempts = 6
)

// cooldownKey identifies a suppression bucket. The tmux server epoch is part
// of the key (RESEARCH Pitfall 5) so a tmux restart naturally clears
// suppression without any flush logic.
type cooldownKey struct {
	epoch uint64
	pane  string
	kind  notifyv2.Kind
}

// dispatchOrigin distinguishes explicit POST asserts from heuristic-originated
// dispatches: explicit asserts bypass the cooldown but still consume ceiling
// tokens (D-10).
type dispatchOrigin int

const (
	originExplicit dispatchOrigin = iota
	originHeuristic
)

// cooldownRef ties a queued retry entry back to the cooldown window its
// dispatch armed. The cooldown is armed BEFORE delivery succeeds; if every
// retry exhausts, the window must be released (releaseCooldownLocked) or
// heuristic repeats stay suppressed for the full — possibly user-configured,
// hours-long — window with nothing ever delivered (silent notification loss).
type cooldownRef struct {
	armed bool
	key   cooldownKey
	until time.Time // the exact window armed; release only if still current
}

// retryEntry is one queued re-delivery attempt (D-28).
type retryEntry struct {
	note       notifyv2.RenderedNote
	attempts   int
	firstTried time.Time
	nextTry    time.Time
	// cooldown is the window the originating dispatch armed (zero when the
	// dispatch armed none); released when this entry is finally dropped.
	cooldown cooldownRef
}

// dispatcher enforces the v2 delivery policy: per-(epoch,pane,kind) cooldown
// (D-08), approval_request exemption (D-09), explicit-assert bypass (D-10),
// token-bucket flood ceiling with one meta-notification per episode
// (D-11/D-12), and a bounded in-memory retry queue (D-28). All state lives in
// memory only (D-13) — never on disk.
type dispatcher struct {
	notifier Notifier
	now      func() time.Time // injected clock (RESEARCH Pitfall 9)

	clickURL    string
	hostname    string
	cooldownDur time.Duration
	retryBase   time.Duration

	mu            sync.Mutex
	cooldown      map[cooldownKey]time.Time // suppression-until per key
	suppressed    map[cooldownKey]int       // D-15 suppression counters
	maxEpoch      uint64                    // highest epoch seen; used by pruneLocked to delete dead-epoch keys
	tokens        float64
	lastRefill    time.Time
	floodNotified bool
	retry         []retryEntry
}

// newDispatcher returns a dispatcher delivering via n. cfg may be nil (tests,
// degraded startup); the compiled-in defaults then apply.
func newDispatcher(n Notifier, cfg *config.Config) *dispatcher {
	cooldown := defaultCooldown
	if cfg != nil && cfg.SessionRegistry.CooldownSecs > 0 {
		cooldown = time.Duration(cfg.SessionRegistry.CooldownSecs) * time.Second
	}
	host := notifyv2.ShortHostname()
	return &dispatcher{
		notifier:    n,
		now:         time.Now,
		clickURL:    composeClickURL(host),
		hostname:    host,
		cooldownDur: cooldown,
		retryBase:   retryBaseDefault,
		cooldown:    make(map[cooldownKey]time.Time),
		suppressed:  make(map[cooldownKey]int),
		tokens:      bucketCapacity,
		lastRefill:  time.Now(),
	}
}

// composeClickURL builds the server-side ssh:// deep link (D-16 —
// Blink/Termius/ConnectBot register the ssh scheme). An unresolvable user
// omits the user@ part; an unresolvable hostname yields no click URL at all.
func composeClickURL(host string) string {
	if host == "" {
		return ""
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "ssh://" + u.Username + "@" + host
	}
	return "ssh://" + host
}

// pruneLocked removes expired and dead-epoch entries from the cooldown and
// suppressed maps (WR-04 fix). Caller must hold d.mu.
//
// Two pruning rules (D-13: state is memory-only, never persisted):
//  1. Expired: any key whose until is not after now is deleted — the window
//     is over, reporting it would violate D-15 honesty.
//  2. Dead epoch: any key whose epoch is below d.maxEpoch is deleted — the
//     tmux server restarted and that epoch's panes no longer exist (RESEARCH
//     Pitfall 5). This complements the epoch-keyed design: new dispatches for
//     the new epoch use different keys, so dead-epoch keys never self-expire.
//
// After deleting expired/dead-epoch cooldown entries, any suppressed key that
// no longer has a live cooldown entry is also deleted: suppressed counters only
// accumulate under a live cooldown, so an absent cooldown key means the window
// is over and the count is stale.
func (d *dispatcher) pruneLocked(now time.Time) {
	for k, until := range d.cooldown {
		if !until.After(now) || k.epoch < d.maxEpoch {
			delete(d.cooldown, k)
		}
	}
	// Remove orphaned suppressed counters (no live cooldown entry).
	for k := range d.suppressed {
		if _, live := d.cooldown[k]; !live {
			delete(d.suppressed, k)
		}
	}
}

// dispatch applies the policy chain to msg and delivers the rendered note.
// Suppression and ceiling drops are success (nil), not errors — the only
// error path is the single policy-side Validate gate.
func (d *dispatcher) dispatch(ctx context.Context, msg notifyv2.Message, origin dispatchOrigin, opts notifyv2.RenderOpts) error {
	// (1) Validate — the single policy-side gate.
	if err := msg.Validate(); err != nil {
		return err
	}

	d.mu.Lock()
	now := d.now()
	// Track the highest epoch seen; pruneLocked uses this to delete dead-epoch
	// keys (RESEARCH Pitfall 5 — tmux restart clears old suppression state).
	// Only heuristic/bridge dispatches may advance maxEpoch — the registry is
	// the sole authority on tmux server generations; POST bodies are not. A
	// client-controlled epoch advancing maxEpoch would let one forged huge
	// value disable cooldown suppression daemon-wide until restart (WR-01).
	if origin == originHeuristic && msg.Session.Epoch > d.maxEpoch {
		d.maxEpoch = msg.Session.Epoch
	}
	d.pruneLocked(now)
	key := cooldownKey{epoch: msg.Session.Epoch, pane: msg.Session.Pane, kind: msg.Kind}

	// (2) Cooldown: only heuristic-originated, never approval_request
	// (D-08, D-09, D-10).
	cooldownApplies := origin == originHeuristic && msg.Kind != notifyv2.KindApprovalRequest
	if cooldownApplies {
		if until, ok := d.cooldown[key]; ok && now.Before(until) {
			d.suppressed[key]++
			d.mu.Unlock()
			slog.Debug("daemon: v2 dispatch suppressed by cooldown",
				"kind", msg.Kind, "pane", msg.Session.Pane, "epoch", msg.Session.Epoch)
			return nil // suppression is success, not error
		}
	}

	// (3) Global flood ceiling (D-11/D-12).
	d.refillLocked(now)
	if d.tokens < 1 {
		firstDrop := !d.floodNotified
		d.floodNotified = true
		d.mu.Unlock()
		// NET-11 voice: log it and recover, never silently ignore.
		slog.Warn("daemon: v2 notification dropped — flood ceiling reached",
			"kind", msg.Kind, "pane", msg.Session.Pane, "epoch", msg.Session.Epoch)
		if firstDrop {
			d.sendFloodMeta(ctx)
		}
		return nil
	}
	d.tokens--
	var cd cooldownRef
	if cooldownApplies {
		until := now.Add(d.cooldownDur)
		d.cooldown[key] = until
		// Remember the armed window: if delivery fails and every retry
		// exhausts, the drop releases it so repeats are not silently lost.
		cd = cooldownRef{armed: true, key: key, until: until}
	}
	d.mu.Unlock()

	// (4) Render: the click URL defaults to the server-side ssh:// deep link.
	if opts.Click == "" {
		opts.Click = d.clickURL
	}
	note := notifyv2.Render(msg, opts)

	// (5) Deliver; failures enter the bounded retry queue (D-28).
	if err := d.notifier.SendNote(ctx, note); err != nil {
		slog.Warn("daemon: v2 delivery failed; queued for retry", "err", err)
		d.enqueueRetry(note, cd)
		return nil
	}

	// A send succeeding with tokens available closes any flood episode, so
	// the next ceiling trip is a NEW episode with its own meta-notification
	// (D-12 new-episode detection).
	d.mu.Lock()
	d.floodNotified = false
	d.mu.Unlock()
	return nil
}

// refillLocked adds tokens for the elapsed time since lastRefill (1 token per
// bucketRefillEvery, capped at bucketCapacity). Caller holds d.mu.
func (d *dispatcher) refillLocked(now time.Time) {
	elapsed := now.Sub(d.lastRefill)
	if elapsed <= 0 {
		return
	}
	d.tokens += elapsed.Seconds() / bucketRefillEvery.Seconds()
	if d.tokens > bucketCapacity {
		d.tokens = bucketCapacity
	}
	d.lastRefill = now
}

// sendFloodMeta delivers the once-per-episode ceiling-exempt meta-notification
// (D-12): a runaway agent must never look like silence. The note is composed
// solely of the hostname and a fixed string — secret-free by construction.
func (d *dispatcher) sendFloodMeta(ctx context.Context) {
	title := "notification flood, suppressing"
	if d.hostname != "" {
		title = d.hostname + ": " + title
	}
	meta := notifyv2.RenderedNote{Title: title, Priority: "4", Tags: "warning"}
	if err := d.notifier.SendNote(ctx, meta); err != nil {
		slog.Warn("daemon: flood meta-notification delivery failed", "err", err)
	}
}

// enqueueRetry appends note to the bounded retry queue, dropping the oldest
// entry with a warning when the queue is full (D-28). cd is the cooldown
// window the originating dispatch armed (zero when none); it is released when
// the entry is finally dropped.
func (d *dispatcher) enqueueRetry(note notifyv2.RenderedNote, cd cooldownRef) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if len(d.retry) >= retryDepth {
		d.dropOldestLocked()
	}
	d.retry = append(d.retry, retryEntry{
		note:       note,
		attempts:   1,
		firstTried: now,
		nextTry:    now.Add(d.retryBase),
		cooldown:   cd,
	})
}

// releaseCooldownLocked deletes the cooldown window a finally-dropped retry
// entry armed — but only if the map still holds that exact window (a newer
// dispatch may have re-armed the key). Without the release, a delivery that
// failed every retry would keep heuristic repeats suppressed for the rest of
// the window: silent notification loss when cooldown_secs exceeds the 5-minute
// retry age. The suppressed counter goes with it — counting suppressions
// against a window that delivered nothing would violate D-15 honesty.
// Caller holds d.mu.
func (d *dispatcher) releaseCooldownLocked(e retryEntry) {
	if !e.cooldown.armed {
		return
	}
	if until, ok := d.cooldown[e.cooldown.key]; ok && until.Equal(e.cooldown.until) {
		delete(d.cooldown, e.cooldown.key)
		delete(d.suppressed, e.cooldown.key)
	}
}

// dropOldestLocked removes the entry with the earliest firstTried (D-28
// drop-oldest). Re-queued failures land at the back of the slice, so index 0
// is not necessarily the oldest — scan by firstTried. NET-11 voice: the drop
// is logged, never silent; metadata only, no note content in the log line.
// Caller holds d.mu and guarantees len(d.retry) > 0.
func (d *dispatcher) dropOldestLocked() {
	oldest := 0
	for i, e := range d.retry {
		if e.firstTried.Before(d.retry[oldest].firstTried) {
			oldest = i
		}
	}
	slog.Warn("daemon: retry queue full — dropping oldest entry",
		"depth", retryDepth, "dropped_age", d.now().Sub(d.retry[oldest].firstTried).String())
	// An overflow drop is final too: release the window it armed so repeats
	// for that (epoch,pane,kind) are not suppressed with nothing delivered.
	d.releaseCooldownLocked(d.retry[oldest])
	d.retry = append(d.retry[:oldest], d.retry[oldest+1:]...)
}

// run is the retry-queue loop: a real ticker at retryBase (tests shorten it)
// drives processRetries until ctx is cancelled. Started by Server.Run.
func (d *dispatcher) run(ctx context.Context) {
	ticker := time.NewTicker(d.retryBase)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.processRetries(ctx)
		}
	}
}

// processRetries attempts due retry entries once (one run-loop tick). Entries
// older than retryMaxAge or past retryMaxAttempts are dropped with a warning;
// a failed attempt re-queues with doubled backoff capped at retryMaxBackoff.
func (d *dispatcher) processRetries(ctx context.Context) {
	d.mu.Lock()
	now := d.now()
	var due, keep []retryEntry
	for _, e := range d.retry {
		switch {
		case now.Sub(e.firstTried) > retryMaxAge || e.attempts >= retryMaxAttempts:
			slog.Warn("daemon: retry entry dropped",
				"attempts", e.attempts, "age", now.Sub(e.firstTried).String())
			// Final drop: release the cooldown window the original dispatch
			// armed so the next heuristic repeat can deliver (no silent loss).
			d.releaseCooldownLocked(e)
		case !e.nextTry.After(now):
			due = append(due, e)
		default:
			keep = append(keep, e)
		}
	}
	d.retry = keep
	d.mu.Unlock()

	var failed []retryEntry
	for _, e := range due {
		if err := d.notifier.SendNote(ctx, e.note); err == nil {
			continue
		}
		e.attempts++
		// Double per attempt from the base (5s, 10s, 20s, 40s, 60s cap);
		// attempts is bounded by retryMaxAttempts so the shift cannot
		// overflow.
		backoff := d.retryBase << (e.attempts - 1)
		if backoff > retryMaxBackoff || backoff <= 0 {
			backoff = retryMaxBackoff
		}
		e.nextTry = d.now().Add(backoff)
		failed = append(failed, e)
	}
	if len(failed) == 0 {
		return
	}
	// Re-insert all failures in one locked section with the D-28 depth bound
	// re-enforced: concurrent enqueueRetry calls may have refilled the queue
	// while the sends ran unlocked, so per-entry unbounded appends could
	// exceed retryDepth (WR-02).
	d.mu.Lock()
	d.retry = append(d.retry, failed...)
	for len(d.retry) > retryDepth {
		d.dropOldestLocked()
	}
	d.mu.Unlock()
}

// paneStats reports the suppression count and latest cooldown-until across
// kinds for (epoch, pane) — the D-15 accessor consumed by /sessions (27-07).
// It calls pruneLocked first so /sessions reads are honest even when no
// dispatch traffic has occurred since the window expired (D-15 honesty).
// Past-cooldown entries are additionally skipped in the loop for defence in
// depth: a key that survives pruning (e.g. future maxEpoch advances) whose
// until has already passed must never inflate the reported cooldown_until.
func (d *dispatcher) paneStats(epoch uint64, pane string) (suppressed int, cooldownUntil time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.pruneLocked(now)
	for k, n := range d.suppressed {
		if k.epoch == epoch && k.pane == pane {
			suppressed += n
		}
	}
	for k, until := range d.cooldown {
		if k.epoch == epoch && k.pane == pane && until.After(now) && until.After(cooldownUntil) {
			cooldownUntil = until
		}
	}
	return suppressed, cooldownUntil
}
