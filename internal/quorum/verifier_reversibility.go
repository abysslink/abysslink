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

package quorum

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/shell"
)

// verifierReversibilityName is V4's canonical name.
const verifierReversibilityName = "V4 reversibility"

// V4 rule codes.
const (
	codeNoUndoProtected = "no-undo-protected"
	codeNoUndo          = "no-undo"
	codeUndoAvailable   = "undo-available"
)

// v4MutatingBinaries is V4's OWN mutating-binaries trigger list (independent
// of V2's write-verb table by declaration; overlap is at the threat level).
var v4MutatingBinaries = map[string]bool{
	"rm": true, "rmdir": true, "shred": true, "dd": true, "truncate": true,
	"mv": true, "rsync": true, "srm": true, "unlink": true,
}

// v4MaxStatArgs caps the stat sweep at the first N existing-path args.
const v4MaxStatArgs = 8

// v4CacheTTL is the per-directory probe cache TTL.
const v4CacheTTL = 10 * time.Second

// dirProbe is one cached per-directory world-state probe result.
type dirProbe struct {
	at        time.Time
	inGitTree bool
	dirty     bool
	unpushed  bool
	err       bool
}

// reversibilityVerifier is V4: a reversibility/blast-radius probe grounded in
// filesystem and VCS world state, not command text. Its own extraction
// os.Stat's each arg (ground truth, not a parse); read-only git probes run
// via the injected shell.Runner — never os/exec, never a mutation.
//
// INDEPENDENCE: if V1 and V2 are both blind to an obfuscated command but an
// argument stats to a real file with no safety net, V4 escalates anyway.
// Failure modes (stale cache, not-yet-existing targets) are disjoint from
// string/parse failures.
type reversibilityVerifier struct {
	runner            shell.Runner // nil ⇒ probes impossible ⇒ ABSTAIN when triggered
	protectedPrefixes []protectedPath
	now               func() time.Time
	// homeGrounded is false when os.UserHomeDir failed at construction: the
	// home-based protected scopes are then MISSING, so a mutating action whose
	// target could be under one of them fails closed (ABSTAIN) rather than
	// silently allowing.
	homeGrounded bool

	mu    sync.Mutex
	cache map[string]dirProbe
}

// newReversibilityVerifier builds V4. runner may be nil (fail closed: a
// triggered check without a probe path ABSTAINs, which the lattice escalates).
func newReversibilityVerifier(runner shell.Runner, extraPaths []string, now func() time.Time) *reversibilityVerifier {
	if now == nil {
		now = time.Now
	}
	paths, homeGrounded := buildProtectedPaths(extraPaths)
	return &reversibilityVerifier{
		runner:            runner,
		protectedPrefixes: paths,
		now:               now,
		homeGrounded:      homeGrounded,
		cache:             make(map[string]dirProbe),
	}
}

func (v *reversibilityVerifier) name() string { return verifierReversibilityName }

func (v *reversibilityVerifier) check(ctx context.Context, act action) Vote {
	paths := v.existingPathArgs(act.args)

	mutating := v4MutatingBinaries[act.binary]
	protectedHit := ""
	for _, p := range paths {
		if label, ok := v.protectedLabel(p); ok {
			protectedHit = label
			break
		}
	}
	// FAIL-CLOSED: a mutating action against an existing target when the home
	// directory was unresolvable at construction — the home-based protected
	// scopes (~/.ssh, keychain, keyring) were never in the set, so a protected
	// target could be silently missed. ABSTAIN (⇒ lattice escalates) instead of
	// ALLOW/undervaluing the blast radius.
	if !v.homeGrounded && mutating && protectedHit == "" && len(paths) > 0 {
		return Vote{
			Verifier: verifierReversibilityName,
			Verdict:  VerdictAbstain,
			Tier:     approve.TierSensitive,
			Reason:   "home directory unresolved — reversibility check ungrounded",
		}
	}
	if !mutating && protectedHit == "" {
		// Not triggered: no mutating binary and no protected path-arg.
		return Vote{Verifier: verifierReversibilityName, Verdict: VerdictAllow, Confidence: ConfidenceHigh}
	}
	if len(paths) == 0 {
		// Mutating binary but nothing exists to destroy — no blast radius.
		return Vote{Verifier: verifierReversibilityName, Verdict: VerdictAllow, Confidence: ConfidenceHigh}
	}

	worst := Vote{Verifier: verifierReversibilityName, Verdict: VerdictAllow, Confidence: ConfidenceHigh, Code: codeUndoAvailable, Reason: "undo available"}
	for _, p := range paths {
		vote := v.checkPath(ctx, p)
		if voteMoreRestrictive(vote, worst) {
			worst = vote
		}
	}
	return worst
}

// checkPath probes one existing target path for an undo mechanism.
func (v *reversibilityVerifier) checkPath(ctx context.Context, p string) Vote {
	probe := v.probeDir(ctx, filepath.Dir(p))
	if probe.err {
		return Vote{
			Verifier: verifierReversibilityName,
			Verdict:  VerdictAbstain,
			Tier:     approve.TierSensitive,
			Err:      VoteErrProbe,
			Reason:   "world-state probe failed",
		}
	}

	undo := probe.inGitTree && !probe.dirty && !probe.unpushed
	if undo {
		return Vote{
			Verifier:   verifierReversibilityName,
			Verdict:    VerdictAllow,
			Confidence: ConfidenceHigh,
			Code:       codeUndoAvailable,
			Reason:     "undo available (clean, pushed work tree)",
		}
	}

	reason := "no undo"
	switch {
	case !probe.inGitTree:
		reason = "no undo — target not under version control"
	case probe.dirty:
		reason = "no undo — dirty or untracked work tree"
	case probe.unpushed:
		reason = "no undo — unpushed commits"
	}

	if label, ok := v.protectedLabel(p); ok {
		return Vote{
			Verifier:   verifierReversibilityName,
			Verdict:    VerdictEscalate,
			Confidence: ConfidenceHigh,
			Tier:       approve.TierCritical,
			Code:       codeNoUndoProtected,
			Reason:     reason + " (protected: " + label + ")",
		}
	}
	return Vote{
		Verifier:   verifierReversibilityName,
		Verdict:    VerdictEscalate,
		Confidence: ConfidenceHigh,
		Tier:       approve.TierSensitive,
		Code:       codeNoUndo,
		Reason:     reason,
	}
}

// probeDir runs the read-only git probes for dir, with a 10s TTL cache.
func (v *reversibilityVerifier) probeDir(ctx context.Context, dir string) dirProbe {
	v.mu.Lock()
	if cached, ok := v.cache[dir]; ok && v.now().Sub(cached.at) < v4CacheTTL {
		v.mu.Unlock()
		return cached
	}
	v.mu.Unlock()

	probe := v.runProbes(ctx, dir)
	probe.at = v.now()

	v.mu.Lock()
	v.cache[dir] = probe
	v.mu.Unlock()
	return probe
}

// runProbes executes the three read-only git probes via the injected Runner.
func (v *reversibilityVerifier) runProbes(ctx context.Context, dir string) dirProbe {
	if v.runner == nil {
		return dirProbe{err: true}
	}

	// Probe 1: inside a git work tree?
	res, err := v.runner.Run(ctx, "git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return dirProbe{err: true}
	}
	if !res.Ok() || strings.TrimSpace(res.Stdout) != "true" {
		return dirProbe{inGitTree: false}
	}

	// Probe 2: dirty / untracked?
	res, err = v.runner.Run(ctx, "git", "-C", dir, "status", "--porcelain")
	if err != nil {
		return dirProbe{err: true}
	}
	if !res.Ok() {
		return dirProbe{err: true}
	}
	dirty := strings.TrimSpace(res.Stdout) != ""

	// Probe 3: unpushed commits? A missing upstream is not an error — it
	// means nothing is backed up remotely, so treat it as unpushed.
	res, err = v.runner.Run(ctx, "git", "-C", dir, "rev-list", "--count", "@{upstream}..HEAD")
	if err != nil {
		return dirProbe{err: true}
	}
	unpushed := !res.Ok() || strings.TrimSpace(res.Stdout) != "0"

	return dirProbe{inGitTree: true, dirty: dirty, unpushed: unpushed}
}

// existingPathArgs stats each non-flag arg and returns those that exist,
// capped at v4MaxStatArgs (ground truth — never a parse).
func (v *reversibilityVerifier) existingPathArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || a == "" {
			continue
		}
		p := a
		if strings.HasPrefix(p, "of=") || strings.HasPrefix(p, "if=") {
			p = p[3:]
		}
		p = expandTilde(p)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		out = append(out, abs)
		if len(out) >= v4MaxStatArgs {
			break
		}
	}
	return out
}

// protectedLabel returns the protected-prefix LABEL for p, if any (labels are
// the only path-shaped strings allowed in reasons — hygiene).
func (v *reversibilityVerifier) protectedLabel(p string) (string, bool) {
	for _, pp := range v.protectedPrefixes {
		if pathUnder(p, pp.prefix) {
			return pp.label, true
		}
	}
	return "", false
}
