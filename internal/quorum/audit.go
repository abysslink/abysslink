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
	"encoding/json"
	"log/slog"
	"time"
)

// AuditAppender appends one hash-only entry to the audit chain. *audit.Audit
// satisfies it (the daemon.AuditAppender / approve-decision receipt
// precedent): content is HASHED by the implementation (SHA-256 into the
// entry), never stored.
type AuditAppender interface {
	Append(op, target string, content []byte, dryRun bool) error
}

// Audit op codes.
const (
	opQuorumDecision = "quorum-decision"
	opQuorumTripwire = "quorum-tripwire" //nolint:gosec // G101: audit op-code identifier, not a credential
)

// decisionRecord is the canonical vote-vector JSON hashed into the audit
// entry for op=quorum-decision. HYGIENE (C-03/C-09, D-38/T-27-14): it carries
// reason codes and protected-prefix labels only — no raw argv, env, stdin,
// full paths, full request IDs, or capability URLs.
type decisionRecord struct {
	V            int          `json:"v"`
	TS           string       `json:"ts"`
	Mode         string       `json:"mode"`
	Outcome      string       `json:"outcome"`
	Tier         string       `json:"tier"`
	FloorRule    string       `json:"floor_rule,omitempty"`
	Binary       string       `json:"binary"`
	Closure8     string       `json:"closure8"`
	Matched      []string     `json:"matched"`
	Votes        []voteRecord `json:"votes"`
	VetoVerifier string       `json:"veto_verifier,omitempty"`
	DecisionID   string       `json:"decision_id"`
}

// voteRecord is one verifier's vote in the canonical vote vector.
type voteRecord struct {
	Verifier   string `json:"verifier"`
	Verdict    string `json:"verdict"`
	Confidence string `json:"confidence"`
	Tier       string `json:"tier"`
	Code       string `json:"code,omitempty"`
	ElapsedMS  int64  `json:"elapsed_ms"`
	Err        string `json:"err,omitempty"`
}

// tripwireRecord is the canonical JSON for op=quorum-tripwire.
type tripwireRecord struct {
	V          int    `json:"v"`
	TS         string `json:"ts"`
	MarkerID   string `json:"marker_id"`
	Binary     string `json:"binary"`
	Closure8   string `json:"closure8"`
	DecisionID string `json:"decision_id"`
}

// canonicalDecisionJSON serializes d into the canonical audit content.
func canonicalDecisionJSON(d Decision, ts time.Time) ([]byte, error) {
	rec := decisionRecord{
		V:            1,
		TS:           ts.UTC().Format(time.RFC3339),
		Mode:         d.Mode,
		Outcome:      d.Outcome.String(),
		Tier:         tierName(d.Tier),
		FloorRule:    d.FloorRule,
		Binary:       d.Binary,
		Closure8:     d.Closure8,
		Matched:      d.Matched,
		VetoVerifier: d.VetoVerifier,
		DecisionID:   d.DecisionID,
	}
	if rec.Matched == nil {
		rec.Matched = []string{}
	}
	rec.Votes = make([]voteRecord, 0, len(d.Votes))
	for _, v := range d.Votes {
		rec.Votes = append(rec.Votes, voteRecord{
			Verifier:   v.Verifier,
			Verdict:    v.Verdict.String(),
			Confidence: v.Confidence.String(),
			Tier:       tierName(v.Tier),
			Code:       v.Code,
			ElapsedMS:  v.ElapsedMS,
			Err:        v.Err,
		})
	}
	return json.Marshal(rec)
}

// emitDecision appends the quorum-decision audit entry and mirrors the same
// canonical JSON as one structured slog record (info in enforcing, debug in
// shadow) — the audit log stores only the hash, the slog mirror is the
// operator-forensics copy. Append failures degrade to a warning: the decision
// stands (an audit failure can make a decision LOUDER, never looser).
func (e *Engine) emitDecision(d Decision, ts time.Time) {
	content, err := canonicalDecisionJSON(d, ts)
	if err != nil {
		e.log.Warn("quorum: decision serialization failed", "err", err, "decision_id", d.DecisionID)
		return
	}
	if e.audit != nil {
		if aerr := e.audit.Append(opQuorumDecision, "exec:"+d.Closure8, content, false); aerr != nil {
			e.log.Warn("quorum: audit append failed", "err", aerr, "decision_id", d.DecisionID)
		}
	}
	level := slog.LevelDebug
	if d.Mode == modeEnforcing {
		level = slog.LevelInfo
	}
	e.log.Log(context.Background(), level, "quorum: decision",
		"record", string(content),
	)
}

// emitTripwire appends the quorum-tripwire audit entry and dispatches the
// alert notification. markerLabel is the marker LABEL, never the raw token.
func (e *Engine) emitTripwire(d Decision, markerLabel string, ts time.Time) {
	rec := tripwireRecord{
		V:          1,
		TS:         ts.UTC().Format(time.RFC3339),
		MarkerID:   markerLabel,
		Binary:     d.Binary,
		Closure8:   d.Closure8,
		DecisionID: d.DecisionID,
	}
	content, err := json.Marshal(rec)
	if err != nil {
		e.log.Warn("quorum: tripwire serialization failed", "err", err)
		return
	}
	if e.audit != nil {
		if aerr := e.audit.Append(opQuorumTripwire, "exec:"+d.Closure8, content, false); aerr != nil {
			e.log.Warn("quorum: tripwire audit append failed", "err", aerr, "decision_id", d.DecisionID)
		}
	}
	e.log.Warn("quorum: canary tripwire fired",
		"marker_id", markerLabel,
		"binary", d.Binary,
		"closure8", d.Closure8,
		"decision_id", d.DecisionID,
	)
}
