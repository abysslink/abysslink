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
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/shell"
)

const (
	// backoffBase is the initial reconnect delay; it is restored after
	// every successful attach.
	backoffBase = time.Second
	// backoffMax caps the exponential respawn backoff so a dead tmux can
	// never turn the supervisor into a hot loop (T-27-11).
	backoffMax = 30 * time.Second
	// debounceWindow coalesces bursts of structural notifications into a
	// single list-panes re-poll: tmux emits several events for one user
	// action (e.g. window-add + layout-change), and one poll reads the
	// whole truth anyway.
	debounceWindow = 250 * time.Millisecond
)

// Run is the registry supervisor loop (D-34: the registry owns reconnect;
// RunStream is one process lifetime). Each cycle: version gate, attach via
// the plain runner's RunStream with the structural no-output client flag,
// await the %begin protocol greeting (the PROVEN-attach gate — CR-01/D-26),
// epoch bump + immediate full poll, then consume control-mode notifications
// (which only ever schedule debounced re-polls) until the stream ends. Every
// failure mode degrades to an honest status string and a capped backoff —
// the daemon is never hostage to tmux (D-26/D-27/D-34). Run returns nil
// after ctx is cancelled, leaving no goroutines behind.
//
// An attach is PROVEN only when the tmux control-mode %begin greeting is
// observed on the stream (awaitAttach true). A started-then-exited attach
// (tmux installed, no server running — the dominant failure mode at boot under
// config.Defaults() since SessionRegistry.Enabled is true) does NOT reach the
// success bookkeeping: backoff is kept, StatusUnavailable is set, and neither
// the epoch nor the needs_input state is touched. This prevents the fabricated
// StatusOK, sleepless hot loop, and per-spin RestartLost flood documented in
// CR-01. See D-26 (honest degraded status) and D-29 (RestartLost iff lost).
func (r *Registry) Run(ctx context.Context) error {
	backoff := backoffBase
	// baselined is the watch.go idiom distinguishing "no baseline yet" (the
	// first-ever attach: nothing can have been lost) from "a previous epoch
	// existed" (a restart that may have killed needs_input panes — D-29).
	baselined := false
	for ctx.Err() == nil {
		if !r.versionGate(ctx) {
			r.sleep(ctx, backoff)
			backoff = min(backoff*2, backoffMax)
			continue
		}

		// The -f client-flags argument is the concrete reason for the
		// >= 3.2 gate; no-output suppresses %output entirely, so pane
		// content structurally never enters the protocol (BACK-03,
		// T-27-10) — it is not parsed-and-dropped.
		stream, err := r.plain.RunStream(ctx, "tmux", "-CC", "-u", "attach-session", "-f", "no-output")
		if err != nil {
			// RunStream errors only when the process cannot start (e.g.
			// tmux binary missing/not-executable). Started-then-exited
			// attaches (no server running) do NOT error here — they are
			// caught by the greeting gate below (CR-01).
			r.setStatus(StatusUnavailable)
			r.sleep(ctx, backoff)
			backoff = min(backoff*2, backoffMax)
			continue
		}

		// Per attach cycle the parser is created here and shared between
		// awaitAttach (which consumes lines up to and including %begin)
		// and consume (which continues from the established block state).
		// This ensures the %begin inBlock flag is visible to consume's
		// subsequent %end feed — they see the same state machine.
		p := &parser{}

		// PROVEN-attach gate (CR-01/D-26/D-34): an attach is only
		// considered successful when the tmux control-mode protocol
		// greeting (%begin) is observed on the stream. A client that
		// starts and exits before the greeting — the state of every rig at
		// boot with no tmux server running — takes the failure path: keep
		// backoff, set StatusUnavailable, never touch epoch or pane state.
		if !r.awaitAttach(ctx, stream, p) {
			exitErr := stream.Close()
			slog.Warn("session: attach exited before greeting — no server?", "err", exitErr)
			r.setStatus(StatusUnavailable)
			r.sleep(ctx, backoff)
			backoff = min(backoff*2, backoffMax)
			continue
		}

		// Attach is PROVEN: the greeting was observed. Only now reset
		// backoff and perform success bookkeeping.
		backoff = backoffBase
		// D-29: capture the pre-disconnect needs_input set BEFORE the epoch
		// bump — these panes died with the old server and keep their
		// last-known identity and OLD epoch on the emitted transitions.
		lost := r.lostNeedsInput()
		r.bumpEpoch()
		r.setStatus(StatusOK)
		r.pollPanes(ctx)
		// D-29: the re-snapshot itself is silent — the phone is notified
		// iff panes were needs_input at restart time (someone was waiting
		// on a now-dead pane). Never always, never never. The first-ever
		// attach has no baseline and emits nothing.
		if baselined {
			for _, t := range lost {
				r.emit(t)
			}
		}
		baselined = true

		// Heuristic poll loop: one goroutine per live attach, stopped (and
		// WAITED for) on detach/ctx so heuristic state has exactly one
		// writer at any time (D-05 cadence lives inside runHeuristic).
		hctx, hcancel := context.WithCancel(ctx)
		hdone := make(chan struct{})
		go func() {
			defer close(hdone)
			r.runHeuristic(hctx)
		}()

		r.consume(ctx, stream, p)
		hcancel()
		<-hdone
		if cerr := stream.Close(); cerr != nil {
			slog.Debug("session: control stream closed", "err", cerr)
		}
	}
	return nil
}

// awaitAttach reads lines from the stream until the %begin greeting is
// observed (eventBlockBegin) — proof that the tmux control-mode attach
// succeeded and the server is live (CR-01/D-26). Returns true when the
// greeting is seen; false when the channel closes before the greeting (the
// process exited without a server — the dominant boot-time failure mode) or
// ctx is cancelled. Truncated lines are debug-logged per consume's convention.
// No extra timeout is applied: channel close (process exit) and ctx cancel
// (daemon shutdown) are the only exits — D-34/T-27-06.
func (r *Registry) awaitAttach(ctx context.Context, stream *shell.Stream, p *parser) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case ln, ok := <-stream.Lines():
			if !ok {
				return false // process exited before greeting
			}
			if ln.Truncated {
				slog.Debug("session: over-cap control-mode line truncated (await greeting)")
			}
			ev := p.feed(ln.Text)
			if ev.kind == eventBlockBegin {
				return true // %begin received — attach proven
			}
		}
	}
}

// lostNeedsInput snapshots the panes that are needs_input right now as
// TransitionRestartLost transitions carrying their last-known identity and
// the CURRENT (about-to-die) epoch — Run calls it before the re-attach epoch
// bump (D-29). Returned in numeric pane-ID order for deterministic emission.
func (r *Registry) lostNeedsInput() []Transition {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Transition
	for _, p := range r.panes {
		if p.needsInput {
			out = append(out, transitionFrom(TransitionRestartLost, p, r.epoch))
		}
	}
	sort.Slice(out, func(i, j int) bool { return idNum(out[i].PaneID) < idNum(out[j].PaneID) })
	return out
}

// versionGate runs `tmux -V` and enforces the >= 3.2 floor BEFORE any attach
// (Pitfall 3, D-27). It re-runs every supervisor cycle, so a user can
// upgrade tmux without restarting the daemon. Returns true when attach may
// proceed; on false the caller backs off and re-checks.
func (r *Registry) versionGate(ctx context.Context) bool {
	res, err := r.plain.Run(ctx, "tmux", "-V")
	if err != nil || res.ExitCode != 0 {
		r.setStatus(StatusUnavailable) // D-26: degrade, never die
		return false
	}
	out := strings.TrimSpace(res.Stdout)
	major, minor, perr := parseTmuxVersion(out)
	if perr != nil {
		slog.Warn("session: cannot parse tmux version", "output", out, "err", perr)
		r.setStatus(StatusUnavailable)
		return false
	}
	if major < 3 || (major == 3 && minor < 2) {
		r.setStatus(fmt.Sprintf(StatusUnsupportedFmt, fmt.Sprintf("%d.%d", major, minor)))
		return false
	}
	if f := strings.Fields(out); len(f) >= 2 {
		r.setTmuxVersion(f[1])
	}
	return true
}

// pollPanes runs the full `list-panes -a` poll — the single source of truth
// for registry state (BACK-03). Control-mode events only ever schedule this
// poll; they never mutate state directly. A failed poll is logged and the
// previous state stands until the next trigger.
func (r *Registry) pollPanes(ctx context.Context) {
	res, err := r.plain.Run(ctx, "tmux", "list-panes", "-a", "-F", listPanesFormat)
	if err != nil || res.ExitCode != 0 {
		slog.Warn("session: list-panes poll failed", "err", err, "exit_code", res.ExitCode)
		return
	}
	r.syncPanes(strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n"))
}

// consume drains the control-mode line channel, feeding each line to the
// protocol parser p (created in Run and already advanced past the %begin
// greeting by awaitAttach — sharing the parser preserves the inBlock state
// so the %end that closes the greeting block is classified correctly).
// Structural notifications schedule a debounced re-poll on THIS goroutine
// (single writer); %exit or channel close returns, handing reconnect back to
// Run. The stdin writer exists on the stream for protocol generality (D-33)
// but this phase sends no control-mode commands — list-panes rides separate
// Runner.Run calls (Pattern 2).
func (r *Registry) consume(ctx context.Context, stream *shell.Stream, p *parser) {
	var debounce *time.Timer
	var debounceC <-chan time.Time
	defer func() {
		if debounce != nil {
			debounce.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-debounceC:
			debounceC = nil
			r.pollPanes(ctx)
		case ln, ok := <-stream.Lines():
			if !ok {
				return // process exited / stdout EOF: supervisor re-attaches
			}
			if ln.Truncated {
				slog.Debug("session: over-cap control-mode line truncated")
			}
			ev := p.feed(ln.Text)
			if ev.kind != eventNotification {
				continue
			}
			if ev.name == notifExit {
				return // stream is ending: loop back to the version gate
			}
			if !structuralNotifications[ev.name] {
				slog.Debug("session: non-structural notification skipped", "name", ev.name)
				continue
			}
			if debounceC == nil {
				debounce = time.NewTimer(debounceWindow)
				debounceC = debounce.C
			}
			// A poll is already pending: the burst coalesces into it.
		}
	}
}
