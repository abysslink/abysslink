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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/abysslink/abysslink/internal/approve"
)

// verifierBehaviorName is V3's canonical name.
const verifierBehaviorName = "V3 behavior"

// V3 rule codes.
const (
	codeRateWindow     = "rate-window"
	codeVelocity       = "velocity"
	codeDryRunFirst    = "dry-run-first"
	codeSpendThreshold = "spend-threshold"
)

// Compiled V3 defaults and caps. The YAML knobs are tighten-only against
// these (validateQuorum rejects anything looser at config load).
const (
	// DefaultSpendThresholdUSD is the shipped spend-threshold ceiling; YAML
	// may only lower it (0 means this default).
	DefaultSpendThresholdUSD = 50.0
	// DefaultRateMaxOps is the shipped destructive-op cap per window; YAML
	// may only lower it.
	DefaultRateMaxOps = 10
	// DefaultRateWindowSeconds is the shipped rate window; YAML may only
	// lengthen it (a longer window is tighter).
	DefaultRateWindowSeconds = 300
	// MaxRateWindowSeconds caps the rate window so that
	// time.Duration(seconds)*time.Second cannot overflow int64 (~9.2e9s) and
	// silently produce a NEGATIVE window that DISABLES the destructive-op rate
	// cap. ~100 years is far beyond any legitimate need while leaving a wide
	// overflow margin; config load rejects anything larger, and
	// newBehaviorVerifier clamps defensively for direct construction.
	MaxRateWindowSeconds = 100 * 365 * 24 * 3600 // 3_153_600_000s

	// velocityMaxOps / velocityWindow are the COMPILED global exec-velocity
	// cap. Not configurable: no YAML key exists (Funnel-omission pattern).
	velocityMaxOps = 30
	velocityWindow = 60 * time.Second

	// behaviorRingCap bounds the in-memory exec-history ring.
	behaviorRingCap = 512
)

// v3DestructiveBinaries is V3's own destructive-binary membership table (it
// reads only the binary basename plus a fixed dry-run-flag table — no parse).
var v3DestructiveBinaries = map[string]bool{
	"rm": true, "dd": true, "shred": true, "truncate": true, "mv": true,
	"rsync": true, "terraform": true, "kubectl": true, "srm": true,
}

// execEvent is one recorded exec observation.
type execEvent struct {
	at          time.Time
	binary      string
	dryRun      bool
	destructive bool
}

// behaviorVerifier is V3: behavioral/temporal signals over an in-memory ring
// of RecordExec events plus an optional injected spend signal. Memory-only by
// design (mirrors approve.Registry D-11): a daemon restart clears history and
// the dry-run-first precondition then fails CLOSED — the first apply-shaped
// op after a restart asks the human.
//
// INDEPENDENCE: the verdict is a function of history no other verifier sees.
// It catches many small individually-benign actions summing to catastrophe,
// which no per-action parser can.
type behaviorVerifier struct {
	mu   sync.Mutex
	ring []execEvent

	now        func() time.Time
	spend      func() float64 // nil ⇒ spend signal inert
	spendLimit float64
	rateMaxOps int
	rateWindow time.Duration
}

// newBehaviorVerifier builds V3 with resolved (tighten-only) thresholds.
func newBehaviorVerifier(spendLimit float64, rateMaxOps, rateWindowSeconds int, now func() time.Time, spend func() float64) *behaviorVerifier {
	if spendLimit <= 0 {
		spendLimit = DefaultSpendThresholdUSD
	}
	if rateMaxOps <= 0 {
		rateMaxOps = DefaultRateMaxOps
	}
	if rateWindowSeconds <= 0 {
		rateWindowSeconds = DefaultRateWindowSeconds
	}
	// Overflow guard: clamp to the safe ceiling so the duration multiplication
	// below can never wrap negative and disable the rate cap (config load also
	// rejects out-of-range values; this is the defense for direct construction).
	if rateWindowSeconds > MaxRateWindowSeconds {
		rateWindowSeconds = MaxRateWindowSeconds
	}
	if now == nil {
		now = time.Now
	}
	return &behaviorVerifier{
		now:        now,
		spend:      spend,
		spendLimit: spendLimit,
		rateMaxOps: rateMaxOps,
		rateWindow: time.Duration(rateWindowSeconds) * time.Second,
	}
}

func (v *behaviorVerifier) name() string { return verifierBehaviorName }

// record appends one exec observation to the ring (cheap, synchronous).
func (v *behaviorVerifier) record(name string, args []string) {
	bin := filepath.Base(name)
	ev := execEvent{
		at:          v.now(),
		binary:      bin,
		dryRun:      isDryRunShaped(bin, args),
		destructive: isDestructiveBinary(bin),
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.ring = append(v.ring, ev)
	if len(v.ring) > behaviorRingCap {
		v.ring = v.ring[len(v.ring)-behaviorRingCap:]
	}
}

func (v *behaviorVerifier) check(_ context.Context, act action) Vote {
	// Spend threshold — Critical (budget integration; nil func ⇒ inert).
	if v.spend != nil && v.spend() >= v.spendLimit {
		return behaviorEscalate(approve.TierCritical, codeSpendThreshold,
			"session spend reached the configured threshold")
	}

	now := v.now()
	v.mu.Lock()
	ring := make([]execEvent, len(v.ring))
	copy(ring, v.ring)
	v.mu.Unlock()

	if vote, hit := v.checkRateAndVelocity(ring, now, act); hit {
		return vote
	}
	if vote, hit := v.checkDryRunFirst(ring, now, act); hit {
		return vote
	}
	return Vote{Verifier: verifierBehaviorName, Verdict: VerdictAllow, Confidence: ConfidenceHigh}
}

// checkRateAndVelocity applies the destructive-op rate window (only when the
// current action is itself destructive-class: history is the signal, the
// current op the trigger) and the compiled global exec-velocity cap.
func (v *behaviorVerifier) checkRateAndVelocity(ring []execEvent, now time.Time, act action) (Vote, bool) {
	if isDestructiveBinary(act.binary) {
		n := 0
		for _, ev := range ring {
			if ev.destructive && now.Sub(ev.at) <= v.rateWindow {
				n++
			}
		}
		if n >= v.rateMaxOps {
			return behaviorEscalate(approve.TierSensitive, codeRateWindow,
				"destructive-op rate exceeded the window cap"), true
		}
	}

	n := 0
	for _, ev := range ring {
		if now.Sub(ev.at) <= velocityWindow {
			n++
		}
	}
	if n >= velocityMaxOps {
		return behaviorEscalate(approve.TierSensitive, codeVelocity,
			"global exec velocity exceeded the compiled cap"), true
	}
	return Vote{}, false
}

// checkDryRunFirst applies the dry-run-first rule: an apply-shaped action
// with no matching prior dry-run record in the window. Cold history after a
// restart cannot confirm the precondition ⇒ fail closed (ESCALATE).
func (v *behaviorVerifier) checkDryRunFirst(ring []execEvent, now time.Time, act action) (Vote, bool) {
	if !isApplyShaped(act.binary, act.args) {
		return Vote{}, false
	}
	for _, ev := range ring {
		if ev.binary == act.binary && ev.dryRun && now.Sub(ev.at) <= v.rateWindow {
			return Vote{}, false // precondition confirmed
		}
	}
	return behaviorEscalate(approve.TierSensitive, codeDryRunFirst,
		"apply-shaped action with no prior dry-run in the window"), true
}

// behaviorEscalate builds one V3 escalation vote.
func behaviorEscalate(tier approve.TierLevel, code, reason string) Vote {
	return Vote{
		Verifier:   verifierBehaviorName,
		Verdict:    VerdictEscalate,
		Confidence: ConfidenceHigh,
		Tier:       tier,
		Code:       code,
		Reason:     reason,
	}
}

// isDestructiveBinary is V3's membership test (basename only; mkfs.* family
// matched by prefix).
func isDestructiveBinary(bin string) bool {
	return v3DestructiveBinaries[bin] || strings.HasPrefix(bin, "mkfs")
}

// applyShape describes one entry of the small per-binary apply/dry-run table.
// An action is apply-shaped when the binary matches, every requiredToken is
// present, and no dry-run flag is present.
type applyShape struct {
	binary        string
	requiredToken string // subcommand token that makes it apply-shaped ("" = any)
}

// applyShapes is the compiled apply-shaped action table.
var applyShapes = []applyShape{
	{"terraform", "apply"},
	{"git", "push"},
	{"rsync", ""},
	{"abysslink", ""},
}

// dryRunFlags is the fixed dry-run-flag table V3 reads from argv (no parse).
var dryRunFlags = map[string]bool{
	"-n": true, "--dry-run": true, "--check": true,
}

// isApplyShaped reports whether (bin, args) is an apply-shaped action per the
// compiled table: matching binary + required token, without a dry-run flag.
// abysslink is apply-shaped only with an explicit --apply (dry-run default).
func isApplyShaped(bin string, args []string) bool {
	for _, s := range applyShapes {
		if s.binary != bin {
			continue
		}
		if s.requiredToken != "" && !containsToken(args, s.requiredToken) {
			continue
		}
		if bin == "abysslink" {
			return containsToken(args, "--apply")
		}
		for _, a := range args {
			if dryRunFlags[a] {
				return false
			}
		}
		return true
	}
	return false
}

// isDryRunShaped reports whether a recorded exec counts as the dry-run
// precursor for its binary: an explicit dry-run flag, or the dry-run
// counterpart subcommand (terraform plan; abysslink without --apply).
func isDryRunShaped(bin string, args []string) bool {
	for _, a := range args {
		if dryRunFlags[a] {
			return true
		}
	}
	switch bin {
	case "terraform":
		return containsToken(args, "plan")
	case "abysslink":
		return !containsToken(args, "--apply")
	}
	return false
}
