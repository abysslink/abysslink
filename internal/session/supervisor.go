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
// epoch bump + immediate full poll, then consume control-mode notifications
// (which only ever schedule debounced re-polls) until the stream ends. Every
// failure mode degrades to an honest status string and a capped backoff —
// the daemon is never hostage to tmux (D-26/D-27). Run returns nil after ctx
// is cancelled, leaving no goroutines behind.
func (r *Registry) Run(ctx context.Context) error {
	backoff := backoffBase
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
			// Attach failure modes (no server, no sessions, ...) are
			// treated uniformly and never string-matched for control
			// flow (Pitfall 3).
			r.setStatus(StatusUnavailable)
			r.sleep(ctx, backoff)
			backoff = min(backoff*2, backoffMax)
			continue
		}

		backoff = backoffBase
		r.bumpEpoch()
		r.setStatus(StatusOK)
		// TODO(plan 27-06, D-29): at this re-attach point, emit
		// TransitionRestartLost for panes that were needs_input when the
		// previous epoch died. The re-snapshot itself stays silent at
		// this layer.
		r.pollPanes(ctx)
		r.consume(ctx, stream)
		if cerr := stream.Close(); cerr != nil {
			slog.Debug("session: control stream closed", "err", cerr)
		}
	}
	return nil
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
// protocol parser. Structural notifications schedule a debounced re-poll on
// THIS goroutine (single writer); %exit or channel close returns, handing
// reconnect back to Run. The stdin writer exists on the stream for protocol
// generality (D-33) but this phase sends no control-mode commands —
// list-panes rides separate Runner.Run calls (Pattern 2).
func (r *Registry) consume(ctx context.Context, stream *shell.Stream) {
	p := &parser{}
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
