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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// Status strings exposed on Snapshot.Status (and later GET /sessions).
const (
	// StatusOK means the control-mode attach is live and the state tree is
	// being maintained from list-panes polls.
	StatusOK = "ok"
	// StatusUnavailable is the degraded status when tmux is missing, no
	// server is running, or attach fails — the daemon is never hostage to
	// tmux (D-26).
	StatusUnavailable = "tmux: unavailable"
	// StatusUnsupportedFmt formats the refusal status for tmux < 3.2
	// (D-27); the %s receives the detected "major.minor" version. The 3.2
	// floor exists because the -f client-flags argument on attach-session
	// (used for the structural no-output attach) only landed in tmux 3.2.
	StatusUnsupportedFmt = "tmux: unsupported (%s, need >= 3.2)"
)

// eventsChanDepth bounds the Events transition channel (T-27-11). When the
// channel is full the transition is dropped with a warning — the poll loop
// must never block on a slow consumer.
const eventsChanDepth = 64

// listPanesFormat is the tmux -F format string for the full-state poll:
// machine fields (IDs, flags, counters) FIRST, free-text display names LAST,
// so SplitN parsing can never let a hostile name shift a routing field
// (T-27-09). Field order: session_id, window_id, pane_id, alternate_on,
// pane_active, session_attached, pane_current_command, session_name,
// window_name.
const listPanesFormat = "#{session_id}\t#{window_id}\t#{pane_id}\t#{alternate_on}\t#{pane_active}\t#{session_attached}\t#{pane_current_command}\t#{session_name}\t#{window_name}"

// listPanesFields is the field count of listPanesFormat (the SplitN limit:
// the trailing window_name absorbs stray separators inside names).
const listPanesFields = 9

// Routing-ID validation (T-27-09/T-27-13): the three tmux ID shapes. A line
// whose IDs fail these is skipped — IDs are later used as -t targets, so
// nothing un-validated may enter the state tree.
var (
	sessionIDRe = regexp.MustCompile(`^\$\d+$`)
	windowIDRe  = regexp.MustCompile(`^@\d+$`)
	paneIDRe    = regexp.MustCompile(`^%\d+$`)
)

// TransitionType classifies a registry Transition.
type TransitionType int

// Transition types published on the Events channel. Emission lands in plan
// 27-06 (the needs_input heuristic); the types are defined now so the
// channel contract is stable for plans 27-06/27-07.
const (
	// TransitionNeedsInput fires when a pane newly needs input.
	TransitionNeedsInput TransitionType = iota
	// TransitionCleared fires when a needs_input pane produces new output
	// or a client attaches (D-04).
	TransitionCleared
	// TransitionRestartLost fires when a tmux restart killed panes that
	// were needs_input at restart time (D-29).
	TransitionRestartLost
)

// Transition is one registry state change delivered on Events. IDs route;
// the name fields are display-only metadata for notification rendering.
type Transition struct {
	Type        TransitionType
	SessionID   string
	WindowID    string
	PaneID      string
	Epoch       uint64
	Consumer    string
	SessionName string
	WindowName  string
}

// Snapshot is a deep copy of the registry state at one instant.
type Snapshot struct {
	Epoch       uint64
	Status      string
	TmuxVersion string
	Sessions    []SessionState
}

// SessionState is one tmux session in a Snapshot.
//
//nolint:revive // revive: SessionState is the published plan-27-03 channel/snapshot contract name consumed by plans 27-06/27-07; session.State is reserved for the SPEC §3.2 pane-state enum
type SessionState struct {
	ID       string
	Name     string
	Attached int
	Windows  []WindowState
}

// WindowState is one tmux window in a Snapshot.
type WindowState struct {
	ID    string
	Name  string
	Panes []PaneState
}

// PaneState is one tmux pane in a Snapshot. NeedsInput/NeedsInputSince are
// populated by the idle-prompt heuristic (plan 27-06).
type PaneState struct {
	ID              string
	Active          bool
	AlternateOn     bool
	Consumer        string
	NeedsInput      bool
	NeedsInputSince time.Time
}

// paneRecord is the internal mutable state for one pane, keyed by pane ID in
// the registry's state tree.
type paneRecord struct {
	sessionID   string
	windowID    string
	paneID      string
	sessionName string
	windowName  string
	attached    int
	active      bool
	alternateOn bool
	consumer    string

	// Heuristic fields (written by the plan-27-06 poll-tick engine):
	// preserved across syncs within the same epoch, cleared by an epoch
	// bump (Pitfall 5). lastHash/idleSince are the watchPane content-hash
	// idle state; they live on the record (under r.mu) so the D-04
	// attach-clear in syncPanes can restart the idle window of a
	// just-cleared pane.
	needsInput      bool
	needsInputSince time.Time
	lastHash        string
	idleSince       time.Time
	epoch           uint64
}

// Registry is the daemon-side tmux session registry (BACK-03). It is a
// library: the daemon hosts it (plan 27-07) by running Run in a goroutine
// and reading Snapshot/Events.
type Registry struct {
	// plain is the UNGATED runner (D-40): registry plumbing is
	// daemon-internal and structurally bypasses the GatedRunner.
	plain shell.Runner
	cfg   *config.Config

	// sleep is the backoff sleeper, injected so tests never really wait
	// (RESEARCH Pitfall 9). Defaults to ctxSleep.
	sleep func(ctx context.Context, d time.Duration)

	// now is the injected heuristic clock (RESEARCH Pitfall 9); defaults to
	// time.Now. NeedsInputSince and idle-window arithmetic come from it.
	now func() time.Time
	// heurSleep paces the heuristic poll loop. It is DELIBERATELY separate
	// from sleep: cadence waits must never pollute supervisor backoff test
	// recorders. Defaults to ctxSleep.
	heurSleep func(ctx context.Context, d time.Duration)
	// promptRe is the compiled optional session_registry.prompt_regex
	// (D-02 extension point); nil means built-in sentinels only.
	promptRe *regexp.Regexp
	// floorWarnOnce dedups the D-01 idle-floor clamp warning.
	floorWarnOnce sync.Once

	mu          sync.Mutex
	epoch       uint64
	status      string
	tmuxVersion string
	panes       map[string]*paneRecord

	events chan Transition
}

// New constructs a Registry over the PLAIN (ungated) runner — the parameter
// is deliberately named plain: registry plumbing must structurally bypass the
// GatedRunner (D-40; the gate lands in plan 27-04). cfg supplies the
// session_registry knobs (zero values mean compiled-in defaults).
func New(plain shell.Runner, cfg *config.Config) *Registry {
	r := &Registry{
		plain:     plain,
		cfg:       cfg,
		sleep:     ctxSleep,
		now:       time.Now,
		heurSleep: ctxSleep,
		status:    StatusUnavailable, // honest initial state: nothing attached yet
		panes:     make(map[string]*paneRecord),
		events:    make(chan Transition, eventsChanDepth),
	}
	if cfg != nil && cfg.SessionRegistry.PromptRegex != "" {
		// Validated with regexp.Compile at config load (T-27-12); a failure
		// here (unvalidated cfg) degrades to sentinels-only, never a panic.
		re, err := regexp.Compile(cfg.SessionRegistry.PromptRegex)
		if err != nil {
			slog.Warn("session: prompt_regex does not compile; using built-in sentinels only", "err", err)
		} else {
			r.promptRe = re
		}
	}
	return r
}

// Events returns the bounded transition channel. Transitions are dropped
// (with a warning) rather than ever blocking the registry's poll loop
// (T-27-11). Emission begins with plan 27-06.
func (r *Registry) Events() <-chan Transition { return r.events }

// emit delivers t on the bounded Events channel, dropping with a warning
// when the consumer is slow (T-27-11). Emission is wired by plan 27-06; the
// helper fixes the drop semantics now so the channel contract is stable.
func (r *Registry) emit(t Transition) {
	select {
	case r.events <- t:
	default:
		slog.Warn("session: events channel full; transition dropped",
			"type", int(t.Type), "pane", t.PaneID, "epoch", t.Epoch)
	}
}

// transitionFrom builds a Transition from a pane record's full identity set.
// IDs route; names/consumer are display metadata. Pane CONTENT never enters a
// Transition (T-27-23) — the heuristic reduces it to a hash and a boolean.
func transitionFrom(tt TransitionType, p *paneRecord, epoch uint64) Transition {
	return Transition{
		Type:        tt,
		SessionID:   p.sessionID,
		WindowID:    p.windowID,
		PaneID:      p.paneID,
		Epoch:       epoch,
		Consumer:    p.consumer,
		SessionName: p.sessionName,
		WindowName:  p.windowName,
	}
}

// setNeedsInput marks a pane needs_input, stamping NeedsInputSince from the
// injected clock. Emission is edge-triggered: only the false→true edge emits
// TransitionNeedsInput — repeated idle+prompt ticks are no-ops, never
// level-triggered spam (and a hostile prompt-flapper is bounded by the edge
// requirement plus the downstream 27-05 cooldown, T-27-24).
func (r *Registry) setNeedsInput(paneID string) {
	r.mu.Lock()
	p, ok := r.panes[paneID]
	if !ok || p.needsInput {
		r.mu.Unlock()
		return
	}
	p.needsInput = true
	p.needsInputSince = r.now()
	t := transitionFrom(TransitionNeedsInput, p, r.epoch)
	r.mu.Unlock()
	r.emit(t)
}

// clearNeedsInput clears a pane's needs_input state, recording why (output /
// attach). Only the true→false edge emits TransitionCleared.
func (r *Registry) clearNeedsInput(paneID, reason string) {
	r.mu.Lock()
	p, ok := r.panes[paneID]
	if !ok || !p.needsInput {
		r.mu.Unlock()
		return
	}
	p.needsInput = false
	p.needsInputSince = time.Time{}
	t := transitionFrom(TransitionCleared, p, r.epoch)
	r.mu.Unlock()
	slog.Debug("session: needs_input cleared", "pane", paneID, "reason", reason)
	r.emit(t)
}

// Snapshot returns a deep copy of the registry state: sessions, windows, and
// panes ordered by numeric ID. Mutating the returned value never affects
// registry state.
func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()

	snap := Snapshot{
		Epoch:       r.epoch,
		Status:      r.status,
		TmuxVersion: r.tmuxVersion,
	}

	type winKey struct{ session, window string }
	sessions := make(map[string]*SessionState)
	windows := make(map[winKey]*WindowState)

	for _, p := range r.panes {
		if _, ok := sessions[p.sessionID]; !ok {
			sessions[p.sessionID] = &SessionState{ID: p.sessionID, Name: p.sessionName, Attached: p.attached}
		}
		wk := winKey{p.sessionID, p.windowID}
		w, ok := windows[wk]
		if !ok {
			w = &WindowState{ID: p.windowID, Name: p.windowName}
			windows[wk] = w
		}
		w.Panes = append(w.Panes, PaneState{
			ID:              p.paneID,
			Active:          p.active,
			AlternateOn:     p.alternateOn,
			Consumer:        p.consumer,
			NeedsInput:      p.needsInput,
			NeedsInputSince: p.needsInputSince,
		})
	}

	for wk, w := range windows {
		sort.Slice(w.Panes, func(i, j int) bool { return idNum(w.Panes[i].ID) < idNum(w.Panes[j].ID) })
		s := sessions[wk.session]
		s.Windows = append(s.Windows, *w)
	}
	for _, s := range sessions {
		sort.Slice(s.Windows, func(i, j int) bool { return idNum(s.Windows[i].ID) < idNum(s.Windows[j].ID) })
		snap.Sessions = append(snap.Sessions, *s)
	}
	sort.Slice(snap.Sessions, func(i, j int) bool { return idNum(snap.Sessions[i].ID) < idNum(snap.Sessions[j].ID) })
	return snap
}

// syncPanes replaces the state tree from a full `list-panes -a` output — the
// poll is the single source of truth (BACK-03). Heuristic fields
// (needs_input and its timestamp, content hash, idle window) are preserved
// for panes whose ID persists within the same epoch; after an epoch bump a
// recycled pane ID is a different pane and starts clean (Pitfall 5).
// Malformed lines are skipped with a debug log, never fatally (T-27-09).
//
// D-04 attach-clear: a session whose attached count INCREASED since the
// previous same-epoch poll clears needs_input for all its panes — a client
// attaching means eyes on the session. Each clear restarts the pane's idle
// window so the next heuristic tick does not instantly re-set a pane that is
// still sitting at the same prompt. Cleared transitions are emitted after the
// lock is released (emit never blocks regardless, T-27-11).
func (r *Registry) syncPanes(lines []string) {
	var cleared []Transition

	r.mu.Lock()
	// Previous per-session attached counts, same epoch only — counts from a
	// dead server must never seed the comparison.
	prevAttached := make(map[string]int)
	for _, p := range r.panes {
		if p.epoch == r.epoch {
			prevAttached[p.sessionID] = p.attached
		}
	}

	next := make(map[string]*paneRecord, len(lines))
	for _, line := range lines {
		rec, ok := parsePaneLine(line)
		if !ok {
			continue
		}
		if prev, exists := r.panes[rec.paneID]; exists && prev.epoch == r.epoch {
			rec.needsInput = prev.needsInput
			rec.needsInputSince = prev.needsInputSince
			rec.lastHash = prev.lastHash
			rec.idleSince = prev.idleSince
		}
		rec.epoch = r.epoch
		next[rec.paneID] = &rec
	}
	r.panes = next

	for _, rec := range next {
		prev, seen := prevAttached[rec.sessionID]
		if !seen || rec.attached <= prev || !rec.needsInput {
			continue
		}
		rec.needsInput = false
		rec.needsInputSince = time.Time{}
		rec.idleSince = r.now()
		cleared = append(cleared, transitionFrom(TransitionCleared, rec, r.epoch))
	}
	r.mu.Unlock()

	sort.Slice(cleared, func(i, j int) bool { return idNum(cleared[i].PaneID) < idNum(cleared[j].PaneID) })
	for _, t := range cleared {
		slog.Debug("session: needs_input cleared by client attach", "pane", t.PaneID)
		r.emit(t)
	}
}

// parsePaneLine parses one listPanesFormat line. Machine fields come first
// and are regex-validated; free-text names come LAST and are captured via
// SplitN so a separator inside a name can only corrupt display fields, never
// routing IDs (T-27-09). Returns false (with a debug log) for malformed
// lines — hostile pane content must never take the poll down.
func parsePaneLine(line string) (paneRecord, bool) {
	fields := strings.SplitN(line, "\t", listPanesFields)
	if len(fields) != listPanesFields {
		slog.Debug("session: malformed list-panes line skipped", "fields", len(fields))
		return paneRecord{}, false
	}
	if !sessionIDRe.MatchString(fields[0]) || !windowIDRe.MatchString(fields[1]) || !paneIDRe.MatchString(fields[2]) {
		slog.Debug("session: list-panes line with invalid IDs skipped",
			"session_id", fields[0], "window_id", fields[1], "pane_id", fields[2])
		return paneRecord{}, false
	}
	attached, err := strconv.Atoi(fields[5])
	if err != nil {
		attached = 0
	}
	return paneRecord{
		sessionID:   fields[0],
		windowID:    fields[1],
		paneID:      fields[2],
		alternateOn: fields[3] == "1",
		active:      fields[4] == "1",
		attached:    attached,
		consumer:    normalizeConsumer(fields[6]),
		sessionName: fields[7],
		windowName:  fields[8],
	}, true
}

// normalizeConsumer maps shell processes to the canonical "shell" (D-23) and
// constrains everything else to lowercase [a-z0-9_-], max 32 chars, so a
// daemon-built Message.Consumer always passes the D-25 wire regex. Empty
// after filtering yields "" (consumer unknown).
func normalizeConsumer(cmd string) string {
	switch cmd {
	case "zsh", "bash", "fish", "sh":
		return "shell"
	}
	var b strings.Builder
	for _, c := range strings.ToLower(cmd) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			b.WriteByte(byte(c))
		}
		if b.Len() == 32 {
			break
		}
	}
	return b.String()
}

// bumpEpoch starts a new registry epoch — every (re)attach is a new epoch,
// so per-pane state and downstream cooldown keys can never leak across a
// tmux restart (Pitfall 5).
func (r *Registry) bumpEpoch() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.epoch++
}

// setStatus records the registry's honest health string (D-26/D-27: explicit
// degraded states, never fabricated success).
func (r *Registry) setStatus(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = s
}

// setTmuxVersion records the detected tmux version token (e.g. "3.6b") for
// Snapshot/GET /sessions display.
func (r *Registry) setTmuxVersion(v string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tmuxVersion = v
}

// ctxSleep sleeps for d or until ctx is cancelled, whichever comes first.
// It is the default Registry.sleep; tests inject a recorder instead so no
// test ever really waits (RESEARCH Pitfall 9).
func ctxSleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// idNum extracts the numeric part of a tmux ID ("$12" → 12) for stable
// Snapshot ordering. IDs reaching this point already passed their shape
// regex, so the parse cannot fail in practice; 0 is a harmless fallback.
func idNum(id string) int {
	if len(id) < 2 {
		return 0
	}
	n, err := strconv.Atoi(id[1:])
	if err != nil {
		return 0
	}
	return n
}
