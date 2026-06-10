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
	"os"
	"os/user"
	"strings"
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

// retryEntry is one queued re-delivery attempt (D-28).
type retryEntry struct {
	note       notifyv2.RenderedNote
	attempts   int
	firstTried time.Time
	nextTry    time.Time
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
	host := shortHostname()
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

// shortHostname returns the local hostname with any domain stripped at the
// first dot; "" when the hostname cannot be resolved.
func shortHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	return h
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
	if cooldownApplies {
		d.cooldown[key] = now.Add(d.cooldownDur)
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
		d.enqueueRetry(note)
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
// entry with a warning when the queue is full (D-28).
func (d *dispatcher) enqueueRetry(note notifyv2.RenderedNote) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if len(d.retry) >= retryDepth {
		// NET-11 voice: the drop is logged, never silent. Metadata only — no
		// note content in the log line.
		slog.Warn("daemon: retry queue full — dropping oldest entry",
			"depth", retryDepth, "dropped_age", now.Sub(d.retry[0].firstTried).String())
		d.retry = d.retry[1:]
	}
	d.retry = append(d.retry, retryEntry{
		note:       note,
		attempts:   1,
		firstTried: now,
		nextTry:    now.Add(d.retryBase),
	})
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
		case !e.nextTry.After(now):
			due = append(due, e)
		default:
			keep = append(keep, e)
		}
	}
	d.retry = keep
	d.mu.Unlock()

	for _, e := range due {
		if err := d.notifier.SendNote(ctx, e.note); err == nil {
			continue
		}
		e.attempts++
		// Double the base interval per attempt, capped at retryMaxBackoff
		// (attempts is bounded by retryMaxAttempts, so this loop is tiny).
		backoff := d.retryBase
		for i := 0; i < e.attempts && backoff < retryMaxBackoff; i++ {
			backoff *= 2
		}
		if backoff > retryMaxBackoff {
			backoff = retryMaxBackoff
		}
		e.nextTry = d.now().Add(backoff)
		d.mu.Lock()
		d.retry = append(d.retry, e)
		d.mu.Unlock()
	}
}

// paneStats reports the suppression count and latest cooldown-until across
// kinds for (epoch, pane) — the D-15 accessor consumed by /sessions (27-07).
func (d *dispatcher) paneStats(epoch uint64, pane string) (suppressed int, cooldownUntil time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, n := range d.suppressed {
		if k.epoch == epoch && k.pane == pane {
			suppressed += n
		}
	}
	for k, until := range d.cooldown {
		if k.epoch == epoch && k.pane == pane && until.After(cooldownUntil) {
			cooldownUntil = until
		}
	}
	return suppressed, cooldownUntil
}
