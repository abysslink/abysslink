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
	"crypto/sha256"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"
)

// needs_input heuristic defaults (D-01/D-05). The watchPane idiom: a YAML
// override > 0 wins, otherwise the compiled-in constant applies.
const (
	// defaultIdleThreshold is the no-output window before a prompt-shaped
	// pane is considered needs_input (D-01 default).
	defaultIdleThreshold = 30 * time.Second
	// idleThresholdFloor is the hard lower bound on idle_secs: values below
	// it are clamped up with one warning (D-01 — settable down to the
	// floor, never below; an immutable default in the original-guide
	// sense).
	idleThresholdFloor = 10 * time.Second
	// defaultPollActive is the capture-pane cadence while any pane's
	// content changed within the last tick (D-05).
	defaultPollActive = 5 * time.Second
	// defaultPollIdle is the backed-off cadence when all panes are idle
	// (D-05). Detection lag stays well under the 30s idle threshold.
	defaultPollIdle = 15 * time.Second
	// promptScanLines is the D-03 detection window: the LAST 3 non-blank
	// lines of capture-pane output are scanned (catches boxed/multi-line
	// prompts; supersedes SPEC §3.3's last-line rule).
	promptScanLines = 3
)

// builtinSentinels is the compiled D-02 prompt-shape set, applied to each of
// the last promptScanLines non-blank lines after trailing-whitespace strip: a
// line ending in one of the single-char prompt tails, or ending
// (case-insensitively) in one of the interactive phrases. The exact contents
// are Claude's-discretion under D-02 — the approach (sentinel set + optional
// prompt_regex extension) is the locked part, not every character.
//
//nolint:gochecknoglobals // gochecknoglobals: immutable compiled lookup table (D-02)
var builtinSentinels = []*regexp.Regexp{
	regexp.MustCompile("[$%>#?:❯»]$"),
	regexp.MustCompile(`(?i)\((?:y/n|yes/no)\)$`),
	regexp.MustCompile(`(?i)\[y/n\]$`),
	regexp.MustCompile(`(?i)password:$`),
	regexp.MustCompile(`(?i)continue\?$`),
}

// lastNonBlankLines returns the last n non-blank lines of s in their original
// order — the generalization of watchPane's lastNonEmptyLine to the D-03
// window.
func lastNonBlankLines(s string, n int) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, n)
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			out = append(out, lines[i])
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// promptShaped reports whether any of lines (trailing whitespace stripped)
// matches the built-in sentinel set or the optional compiled config
// prompt_regex (D-02/D-03). Only the boolean ever leaves the heuristic — pane
// text never enters a Transition (T-27-23).
func promptShaped(lines []string, extra *regexp.Regexp) bool {
	for _, ln := range lines {
		s := strings.TrimRight(ln, " \t")
		if s == "" {
			continue
		}
		for _, re := range builtinSentinels {
			if re.MatchString(s) {
				return true
			}
		}
		if extra != nil && extra.MatchString(s) {
			return true
		}
	}
	return false
}

// idleThreshold returns the configured needs_input idle window, clamped to
// the 10s floor with a single warning (D-01). Zero config means the 30s
// default.
func (r *Registry) idleThreshold() time.Duration {
	if r.cfg != nil && r.cfg.SessionRegistry.IdleSecs > 0 {
		d := time.Duration(r.cfg.SessionRegistry.IdleSecs) * time.Second
		if d < idleThresholdFloor {
			r.floorWarnOnce.Do(func() {
				slog.Warn("session: session_registry.idle_secs below the floor; clamping",
					"configured_secs", r.cfg.SessionRegistry.IdleSecs,
					"floor_secs", int(idleThresholdFloor/time.Second))
			})
			return idleThresholdFloor
		}
		return d
	}
	return defaultIdleThreshold
}

// pollActiveInterval returns the D-05 active cadence (config override > 0,
// else 5s).
func (r *Registry) pollActiveInterval() time.Duration {
	if r.cfg != nil && r.cfg.SessionRegistry.PollActiveSecs > 0 {
		return time.Duration(r.cfg.SessionRegistry.PollActiveSecs) * time.Second
	}
	return defaultPollActive
}

// pollIdleInterval returns the D-05 all-idle cadence (config override > 0,
// else 15s).
func (r *Registry) pollIdleInterval() time.Duration {
	if r.cfg != nil && r.cfg.SessionRegistry.PollIdleSecs > 0 {
		return time.Duration(r.cfg.SessionRegistry.PollIdleSecs) * time.Second
	}
	return defaultPollIdle
}

// runHeuristic drives pollTick on the adaptive D-05 cadence. It is started by
// Run after each successful attach and stopped on detach/ctx — Run waits for
// it to exit before re-attaching, so at most ONE heuristic goroutine ever
// exists (single-writer discipline: only pollTick mutates heuristic state).
// The wait comes FIRST: the supervisor already ran a full poll at attach
// time, so the first capture pass is due one cadence later.
func (r *Registry) runHeuristic(ctx context.Context) {
	next := r.pollActiveInterval()
	for {
		r.heurSleep(ctx, next)
		if ctx.Err() != nil {
			return
		}
		next = r.pollTick(ctx)
	}
}

// pollTick runs one full heuristic cycle: the list-panes sync (the plan-27-03
// poll — single source of truth), then a capture-pane evaluation per eligible
// pane. It returns the next tick's cadence: 5s when any pane's content
// changed this tick, 15s when everything is idle (D-05).
func (r *Registry) pollTick(ctx context.Context) time.Duration {
	r.pollPanes(ctx)
	anyChanged := false
	for _, id := range r.heuristicCandidates() {
		if r.evalPane(ctx, id) {
			anyChanged = true
		}
	}
	if anyChanged {
		return r.pollActiveInterval()
	}
	return r.pollIdleInterval()
}

// heuristicCandidates returns the pane IDs eligible for the heuristic, in
// numeric ID order (deterministic capture order). Alternate-screen panes
// (vim/htop — D-06) and panes in ignore_sessions sessions (D-07) are exempt:
// they are never captured, never set. Hooks can still assert needs_input for
// them via POST /notify.
func (r *Registry) heuristicCandidates() []string {
	ignored := make(map[string]bool)
	if r.cfg != nil {
		for _, s := range r.cfg.SessionRegistry.IgnoreSessions {
			ignored[s] = true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.panes))
	for id, p := range r.panes {
		if p.alternateOn { // D-06
			continue
		}
		if ignored[p.sessionName] { // D-07
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return idNum(ids[i]) < idNum(ids[j]) })
	return ids
}

// evalPane captures one pane and applies the watchPane content-hash idiom:
// changed hash → record + reset the idle window + clear needs_input (D-04);
// unchanged past the idle threshold with a prompt-shaped tail (D-02/D-03) →
// set needs_input. It reports whether the pane's content changed (the D-05
// cadence input). Capture errors skip the pane and never crash or tighten the
// loop (watchPane stance, T-27-25); output is bounded by the Runner's 16 MiB
// cap and the pane ID was regex-validated at sync before any -t use
// (T-27-26).
func (r *Registry) evalPane(ctx context.Context, paneID string) bool {
	res, err := r.plain.Run(ctx, "tmux", "capture-pane", "-t", paneID, "-p")
	if err != nil || res.ExitCode != 0 {
		return false
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(res.Stdout)))
	now := r.now()

	r.mu.Lock()
	p, ok := r.panes[paneID]
	if !ok {
		// The pane vanished between the sync and this capture.
		r.mu.Unlock()
		return false
	}
	if p.lastHash != sum {
		p.lastHash = sum
		p.idleSince = now
		r.mu.Unlock()
		r.clearNeedsInput(paneID, "output") // D-04: new output clears
		return true
	}
	idleFor := now.Sub(p.idleSince)
	r.mu.Unlock()

	if idleFor >= r.idleThreshold() && promptShaped(lastNonBlankLines(res.Stdout, promptScanLines), r.promptRe) {
		r.setNeedsInput(paneID)
	}
	return false
}
