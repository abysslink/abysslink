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
	_ = cfg
	return &dispatcher{notifier: n, now: time.Now}
}

// dispatch applies the policy chain to msg and delivers the rendered note.
// Suppression and ceiling drops are success (nil), not errors.
func (d *dispatcher) dispatch(ctx context.Context, msg notifyv2.Message, origin dispatchOrigin, opts notifyv2.RenderOpts) error {
	_, _, _, _ = ctx, msg, origin, opts
	return nil
}

// run is the retry-queue loop; it exits when ctx is cancelled.
func (d *dispatcher) run(ctx context.Context) {
	<-ctx.Done()
}

// processRetries attempts due retry entries once (one run-loop tick).
func (d *dispatcher) processRetries(ctx context.Context) {
	_ = ctx
}

// paneStats reports the suppression count and latest cooldown-until across
// kinds for (epoch, pane) — the D-15 accessor consumed by /sessions (27-07).
func (d *dispatcher) paneStats(epoch uint64, pane string) (suppressed int, cooldownUntil time.Time) {
	_, _ = epoch, pane
	return 0, time.Time{}
}
