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
	"fmt"
	"sort"
	"strings"

	"github.com/abysslink/abysslink/internal/approve"
)

// Verdict is one verifier's stance on a single action.
type Verdict int

const (
	// VerdictAllow votes to let the action proceed.
	VerdictAllow Verdict = iota
	// VerdictEscalate votes to route the action to human approval.
	VerdictEscalate
	// VerdictDeny is a veto: the action is refused with no approval path.
	VerdictDeny
	// VerdictAbstain means the verifier could not evaluate (probe error,
	// timeout, panic). Abstention fails CLOSED — it maps to ESCALATE in the
	// lattice, never to ALLOW.
	VerdictAbstain
)

// String renders the verdict for audit records and human summaries.
func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "ALLOW"
	case VerdictEscalate:
		return "ESCALATE"
	case VerdictDeny:
		return "DENY"
	case VerdictAbstain:
		return "ABSTAIN"
	default:
		return fmt.Sprintf("VERDICT(%d)", int(v))
	}
}

// Confidence qualifies an ALLOW vote. A Low-confidence ALLOW is treated as
// ESCALATE by the lattice — confidence only ever demotes toward restrictive,
// never promotes (selective-prediction / reject-option rule).
type Confidence int

const (
	// ConfidenceLow marks an uncertain vote (ambiguous parse, partial signal).
	ConfidenceLow Confidence = iota
	// ConfidenceHigh marks a confident vote.
	ConfidenceHigh
)

// String renders the confidence for audit records.
func (c Confidence) String() string {
	if c == ConfidenceHigh {
		return "high"
	}
	return "low"
}

// Outcome is the combined decision of the lattice: DENY(2) > ESCALATE(1) >
// ALLOW(0). Combination is the meet — most restrictive wins.
type Outcome int

const (
	// OutcomeAllow lets the exec proceed (audit-only, no prompt).
	OutcomeAllow Outcome = 0
	// OutcomeEscalate routes the exec to the existing approve flow.
	OutcomeEscalate Outcome = 1
	// OutcomeDeny refuses the exec with no approval path.
	OutcomeDeny Outcome = 2
)

// String renders the outcome for audit records.
func (o Outcome) String() string {
	switch o {
	case OutcomeAllow:
		return "allow"
	case OutcomeEscalate:
		return "escalate"
	case OutcomeDeny:
		return "deny"
	default:
		return fmt.Sprintf("outcome(%d)", int(o))
	}
}

// Vote error markers. Vote.Err carries ONLY one of these fixed codes — never
// free-form error text, which could embed argv fragments (D-38 hygiene).
const (
	// VoteErrPanic marks a verifier that panicked (recovered, fail closed).
	VoteErrPanic = "panic"
	// VoteErrTimeout marks a verifier that exceeded its per-verifier budget.
	VoteErrTimeout = "timeout"
	// VoteErrProbe marks a verifier whose world-state probe failed.
	VoteErrProbe = "probe-error"
)

// Vote is one verifier's verdict on one action.
type Vote struct {
	// Verifier is the canonical verifier name ("V1 syntactic", …).
	Verifier string
	// Verdict is the verifier's stance.
	Verdict Verdict
	// Confidence qualifies an ALLOW (Low ⇒ the lattice escalates).
	Confidence Confidence
	// Tier is the approval tier this vote demands when escalating.
	Tier approve.TierLevel
	// Code is the matched rule code (e.g. "force-push-protected"), empty when
	// no rule matched.
	Code string
	// Reason is a short human-readable reason. HYGIENE: it may name the
	// matched pattern and the matched protected-prefix label from the
	// compiled/config list — never a raw argument (D-38/T-27-14).
	Reason string
	// Err is a fixed failure marker (VoteErrPanic/VoteErrTimeout/VoteErrProbe)
	// or empty. Any non-empty Err makes the effective verdict ESCALATE.
	Err string
	// ElapsedMS is the verifier's wall-clock evaluation time.
	ElapsedMS int64
}

// Decision is the combined result of one quorum evaluation.
type Decision struct {
	// Outcome is the lattice-combined outcome.
	Outcome Outcome
	// Tier is the approval tier demanded when Outcome is ESCALATE.
	Tier approve.TierLevel
	// FloorRule names the stage-0 deny-floor rule that matched (empty when
	// the floor did not fire).
	FloorRule string
	// TripwireMarker identifies the canary marker that fired (label from the
	// compiled/config list, never the raw argv token).
	TripwireMarker string
	// Matched lists every rule code that matched across the vote vector.
	Matched []string
	// Votes is the full vote vector (empty on a stage-0 floor deny — the
	// verifiers never ran).
	Votes []Vote
	// VetoVerifier names the verifier whose DENY vetoed the action (empty
	// otherwise).
	VetoVerifier string
	// DecisionID is a random identifier linking the quorum-decision audit
	// entry to a later approve-decision entry.
	DecisionID string
	// Mode is "enforcing" or "shadow" (audit labeling only).
	Mode string
	// Binary is the resolved binary BASENAME — the one allowed cleartext
	// field (D-38).
	Binary string
	// Closure8 is the first 8 bytes (hex) of the execution-closure hash.
	Closure8 string
}

// meet combines two outcomes in the security lattice: most restrictive wins
// (implemented as max over DENY(2) > ESCALATE(1) > ALLOW(0)).
func meet(a, b Outcome) Outcome {
	if a > b {
		return a
	}
	return b
}

// effectiveOutcome maps a single vote to its effective lattice input per the
// §3 mapping: ABSTAIN → ESCALATE; error/timeout/panic → ESCALATE;
// ALLOW@Low → ESCALATE. Nothing in this mapping ever promotes toward ALLOW.
func effectiveOutcome(v Vote) Outcome {
	switch {
	case v.Verdict == VerdictDeny:
		return OutcomeDeny
	case v.Verdict == VerdictAbstain, v.Err != "":
		return OutcomeEscalate
	case v.Verdict == VerdictEscalate:
		return OutcomeEscalate
	case v.Confidence == ConfidenceLow:
		return OutcomeEscalate // ALLOW@Low fails closed
	default:
		return OutcomeAllow
	}
}

// combine folds the vote vector through the lattice and returns the combined
// outcome, the demanded tier, the matched rule codes, and the veto verifier
// (when a DENY vetoed). Rules (§3 decision table):
//
//   - any DENY ⇒ DENY (veto; row 1);
//   - ≥2 verifier failures (error/timeout/panic/abstain) ⇒ ESCALATE at
//     TierCritical (systemic failure; row 3);
//   - one failure ⇒ ESCALATE at max(TierSensitive, highest demanded; row 2);
//   - any ESCALATE (incl. ALLOW@Low remapped) ⇒ ESCALATE at the max demanded
//     tier, floored at TierSensitive (rows 4–5);
//   - unanimous ALLOW@High ⇒ ALLOW at TierBenign (row 6).
//
// There is no path from disagreement, low confidence, failure, or silence to
// ALLOW.
func combine(votes []Vote) (Outcome, approve.TierLevel, []string, string) {
	outcome := OutcomeAllow
	tier := approve.TierBenign
	veto := ""
	failures := 0
	var matched []string

	for _, v := range votes {
		if v.Code != "" {
			matched = append(matched, v.Code)
		}
		if v.Verdict == VerdictAbstain || v.Err != "" {
			failures++
		}
		eff := effectiveOutcome(v)
		outcome = meet(outcome, eff)
		if eff == OutcomeDeny && veto == "" {
			veto = v.Verifier
		}
		if eff == OutcomeEscalate {
			demanded := v.Tier
			if demanded < approve.TierSensitive {
				demanded = approve.TierSensitive
			}
			if demanded > tier {
				tier = demanded
			}
		}
	}

	if failures >= 2 {
		// Row 3: systemic verifier failure — Critical (TTY-only in v4).
		outcome = meet(outcome, OutcomeEscalate)
		tier = approve.TierCritical
	}
	if outcome == OutcomeAllow {
		tier = approve.TierBenign
	}
	return outcome, tier, matched, veto
}

// tierName renders an approve.TierLevel for audit records and summaries.
func tierName(t approve.TierLevel) string {
	switch t {
	case approve.TierBenign:
		return "benign"
	case approve.TierSensitive:
		return "sensitive"
	case approve.TierCritical:
		return "critical"
	default:
		return fmt.Sprintf("tier(%d)", int(t))
	}
}

// Title renders the human approval-prompt title: the top (most restrictive)
// reason, human-readable. HYGIENE: reasons name matched patterns and
// protected-prefix labels only — never raw argv (D-38/T-27-14).
func (d Decision) Title() string {
	if d.FloorRule != "" {
		return "Blocked: " + d.FloorRule
	}
	votes := d.sortedDissentFirst()
	for _, v := range votes {
		if effectiveOutcome(v) != OutcomeAllow && v.Reason != "" {
			return "Approval needed: " + v.Reason
		}
	}
	return "Approval needed: " + d.Binary
}

// Body renders the human approval-prompt body: binary basename, closure-hash
// prefix, matched rule codes, and the full vote summary with DISSENT FIRST —
// the human tiebreak reviews the strongest objection, never a consensus
// summary. It never carries raw argv, env, full paths, request IDs, or
// capability URLs.
func (d Decision) Body() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s · closure %s", d.Binary, d.Closure8)
	if len(d.Matched) > 0 {
		fmt.Fprintf(&b, " · rules: %s", strings.Join(d.Matched, ", "))
	}
	if summary := d.VoteSummary(); summary != "" {
		b.WriteString("\n")
		b.WriteString(summary)
	}
	return b.String()
}

// VoteSummary renders the dissent-first vote vector, e.g.:
//
//	V4 reversibility: ESCALATE(critical) no-undo — unpushed commits ·
//	V1 syntactic: ALLOW · …
func (d Decision) VoteSummary() string {
	votes := d.sortedDissentFirst()
	parts := make([]string, 0, len(votes))
	for _, v := range votes {
		parts = append(parts, formatVote(v))
	}
	return strings.Join(parts, " · ")
}

// formatVote renders one vote for the human summary.
func formatVote(v Vote) string {
	var b strings.Builder
	b.WriteString(v.Verifier)
	b.WriteString(": ")
	switch {
	case v.Err != "":
		fmt.Fprintf(&b, "ABSTAIN (%s)", v.Err)
	case v.Verdict == VerdictEscalate || v.Verdict == VerdictDeny:
		fmt.Fprintf(&b, "%s(%s)", v.Verdict, tierName(v.Tier))
		if v.Code != "" {
			b.WriteString(" " + v.Code)
		}
		if v.Reason != "" {
			b.WriteString(" — " + v.Reason)
		}
	case v.Verdict == VerdictAllow && v.Confidence == ConfidenceLow:
		b.WriteString("ALLOW(low)")
		if v.Code != "" {
			b.WriteString(" " + v.Code)
		}
	default:
		b.WriteString(v.Verdict.String())
	}
	return b.String()
}

// sortedDissentFirst returns the votes ordered most-restrictive-first (the
// MYCIN-style weighting fence: ordering/loudness inside the escalate bucket
// only — it never crosses the DENY floor and never converts a verdict).
func (d Decision) sortedDissentFirst() []Vote {
	out := make([]Vote, len(d.Votes))
	copy(out, d.Votes)
	sort.SliceStable(out, func(i, j int) bool {
		oi, oj := effectiveOutcome(out[i]), effectiveOutcome(out[j])
		if oi != oj {
			return oi > oj // more restrictive first
		}
		return out[i].Tier > out[j].Tier // then higher demanded tier first
	})
	return out
}
