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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/approve"
)

// ---------------------------------------------------------------------------
// Test helpers shared across the quorum test files.
// ---------------------------------------------------------------------------

// stubVerifier is a scripted verifier for lattice tests.
type stubVerifier struct {
	vname    string
	vote     Vote
	panicNow bool
	sleep    time.Duration // hard sleep that IGNORES ctx (simulates a hung verifier)
}

func (s *stubVerifier) name() string { return s.vname }

func (s *stubVerifier) check(_ context.Context, _ action) Vote {
	if s.panicNow {
		panic("stub verifier panic")
	}
	if s.sleep > 0 {
		time.Sleep(s.sleep)
	}
	return s.vote
}

// fakeAppender captures audit Append calls for assertions.
type fakeAppender struct {
	mu      sync.Mutex
	entries []fakeEntry
	err     error
}

type fakeEntry struct {
	op      string
	target  string
	content []byte
}

func (f *fakeAppender) Append(op, target string, content []byte, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(content))
	copy(cp, content)
	f.entries = append(f.entries, fakeEntry{op: op, target: target, content: cp})
	return f.err
}

func (f *fakeAppender) all() []fakeEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeEntry, len(f.entries))
	copy(out, f.entries)
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// allowHigh builds a confident ALLOW vote for a named stub.
func allowHigh(name string) Vote {
	return Vote{Verifier: name, Verdict: VerdictAllow, Confidence: ConfidenceHigh}
}

// newStubEngine builds an engine whose four verifiers are replaced by stubs.
func newStubEngine(t *testing.T, stubs ...*stubVerifier) *Engine {
	t.Helper()
	e := New(Config{}, WithLogger(discardLogger()))
	vs := make([]verifier, 0, len(stubs))
	for _, s := range stubs {
		vs = append(vs, s)
	}
	e.verifiers = vs
	return e
}

// fourStubs builds four stub verifiers with the given votes.
func fourStubs(votes [4]Vote) []*stubVerifier {
	names := []string{"S1", "S2", "S3", "S4"}
	out := make([]*stubVerifier, 4)
	for i := range out {
		v := votes[i]
		v.Verifier = names[i]
		out[i] = &stubVerifier{vname: names[i], vote: v}
	}
	return out
}

// ---------------------------------------------------------------------------
// meet / effective-verdict mapping.
// ---------------------------------------------------------------------------

// TestMeet_MostRestrictiveWins proves the total order and the effective-
// verdict mapping: no combination promotes toward ALLOW.
func TestMeet_MostRestrictiveWins(t *testing.T) {
	cases := []struct {
		a, b, want Outcome
	}{
		{OutcomeAllow, OutcomeAllow, OutcomeAllow},
		{OutcomeAllow, OutcomeEscalate, OutcomeEscalate},
		{OutcomeEscalate, OutcomeAllow, OutcomeEscalate},
		{OutcomeAllow, OutcomeDeny, OutcomeDeny},
		{OutcomeDeny, OutcomeAllow, OutcomeDeny},
		{OutcomeEscalate, OutcomeDeny, OutcomeDeny},
		{OutcomeDeny, OutcomeDeny, OutcomeDeny},
		{OutcomeEscalate, OutcomeEscalate, OutcomeEscalate},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, meet(c.a, c.b), "meet(%s, %s)", c.a, c.b)
	}

	t.Run("effective verdict mapping never promotes", func(t *testing.T) {
		assert.Equal(t, OutcomeEscalate, effectiveOutcome(Vote{Verdict: VerdictAbstain}),
			"ABSTAIN must map to ESCALATE")
		assert.Equal(t, OutcomeEscalate, effectiveOutcome(Vote{Verdict: VerdictAllow, Confidence: ConfidenceHigh, Err: VoteErrPanic}),
			"a vote carrying an error marker must map to ESCALATE even if it claims ALLOW")
		assert.Equal(t, OutcomeEscalate, effectiveOutcome(Vote{Verdict: VerdictAllow, Confidence: ConfidenceLow}),
			"ALLOW@Low must map to ESCALATE")
		assert.Equal(t, OutcomeAllow, effectiveOutcome(Vote{Verdict: VerdictAllow, Confidence: ConfidenceHigh}))
		assert.Equal(t, OutcomeDeny, effectiveOutcome(Vote{Verdict: VerdictDeny, Confidence: ConfidenceLow}),
			"a DENY vetoes at ANY confidence")
	})
}

// ---------------------------------------------------------------------------
// Decision table (§3).
// ---------------------------------------------------------------------------

// TestEvaluate_DecisionTable exercises every combination row of the §3 table
// that is decidable at the engine level (token rows are gate-level tests).
func TestEvaluate_DecisionTable(t *testing.T) {
	ctx := context.Background()

	t.Run("row 0a: floor match denies without asking", func(t *testing.T) {
		e := New(Config{}, WithLogger(discardLogger()))
		d, err := e.Evaluate(ctx, "tailscale", []string{"funnel", "2586"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeDeny, d.Outcome)
		assert.Equal(t, "funnel-enable", d.FloorRule)
		assert.Empty(t, d.Votes, "verifiers must not run after a floor hit")
	})

	t.Run("row 0b: canary marker denies with alert", func(t *testing.T) {
		alerted := false
		e := New(Config{}, WithLogger(discardLogger()),
			WithAlertFunc(func(context.Context, string, string) { alerted = true }))
		d, err := e.Evaluate(ctx, "cat", []string{"/tmp/" + DefaultCanaryMarker + "/x"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeDeny, d.Outcome)
		assert.Equal(t, "canary-tripwire", d.FloorRule)
		assert.True(t, alerted, "a tripwire hit must dispatch the alert")
	})

	t.Run("row 0c: stage-0 evaluator panic denies", func(t *testing.T) {
		e := New(Config{}, WithLogger(discardLogger()))
		e.floor = nil // force a nil-deref panic inside the stage-0 evaluator
		d, err := e.Evaluate(ctx, "echo", []string{"hello"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeDeny, d.Outcome, "a floor evaluation panic must DENY, never pass")
		assert.Equal(t, floorEvaluationError, d.FloorRule)
	})

	t.Run("row 1: any DENY vetoes", func(t *testing.T) {
		stubs := fourStubs([4]Vote{
			allowHigh(""), {Verdict: VerdictDeny, Confidence: ConfidenceHigh, Code: "x"},
			allowHigh(""), allowHigh(""),
		})
		e := newStubEngine(t, stubs...)
		d, err := e.Evaluate(ctx, "echo", []string{"hello"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeDeny, d.Outcome)
		assert.Equal(t, "S2", d.VetoVerifier)
	})

	t.Run("row 2: exactly one failure escalates at >= Sensitive", func(t *testing.T) {
		stubs := fourStubs([4]Vote{
			allowHigh(""), {Verdict: VerdictAbstain, Err: VoteErrProbe},
			allowHigh(""), allowHigh(""),
		})
		e := newStubEngine(t, stubs...)
		d, err := e.Evaluate(ctx, "echo", []string{"hello"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeEscalate, d.Outcome)
		assert.Equal(t, approve.TierSensitive, d.Tier)
	})

	t.Run("row 2: one failure + a Critical escalate vote demands Critical", func(t *testing.T) {
		stubs := fourStubs([4]Vote{
			{Verdict: VerdictEscalate, Confidence: ConfidenceHigh, Tier: approve.TierCritical, Code: "c"},
			{Verdict: VerdictAbstain, Err: VoteErrProbe},
			allowHigh(""), allowHigh(""),
		})
		e := newStubEngine(t, stubs...)
		d, err := e.Evaluate(ctx, "echo", []string{"hello"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeEscalate, d.Outcome)
		assert.Equal(t, approve.TierCritical, d.Tier)
	})

	t.Run("row 4: any escalate vote escalates at the max demanded tier", func(t *testing.T) {
		stubs := fourStubs([4]Vote{
			{Verdict: VerdictEscalate, Confidence: ConfidenceHigh, Tier: approve.TierSensitive, Code: "a"},
			{Verdict: VerdictEscalate, Confidence: ConfidenceHigh, Tier: approve.TierCritical, Code: "b"},
			allowHigh(""), allowHigh(""),
		})
		e := newStubEngine(t, stubs...)
		d, err := e.Evaluate(ctx, "echo", []string{"hello"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeEscalate, d.Outcome)
		assert.Equal(t, approve.TierCritical, d.Tier)
		assert.ElementsMatch(t, []string{"a", "b"}, d.Matched)
	})

	t.Run("row 6: unanimous confident ALLOW allows at Benign", func(t *testing.T) {
		stubs := fourStubs([4]Vote{allowHigh(""), allowHigh(""), allowHigh(""), allowHigh("")})
		e := newStubEngine(t, stubs...)
		d, err := e.Evaluate(ctx, "echo", []string{"hello"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeAllow, d.Outcome)
		assert.Equal(t, approve.TierBenign, d.Tier)
		assert.Empty(t, d.VetoVerifier)
	})

	t.Run("row 7: canceled context refuses the exec", func(t *testing.T) {
		e := New(Config{}, WithLogger(discardLogger()))
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := e.Evaluate(canceled, "echo", []string{"hello"})
		require.Error(t, err, "a canceled evaluation context must refuse the exec")
	})
}

// TestEvaluate_SingleDenyVetoes places a DENY at every verifier position
// against three confident ALLOWs: the veto must always win.
func TestEvaluate_SingleDenyVetoes(t *testing.T) {
	for pos := range 4 {
		votes := [4]Vote{allowHigh(""), allowHigh(""), allowHigh(""), allowHigh("")}
		votes[pos] = Vote{Verdict: VerdictDeny, Confidence: ConfidenceHigh, Code: "veto"}
		e := newStubEngine(t, fourStubs(votes)...)
		d, err := e.Evaluate(context.Background(), "echo", []string{"x"})
		require.NoError(t, err)
		assert.Equal(t, OutcomeDeny, d.Outcome, "DENY at position %d must veto", pos)
		assert.NotEmpty(t, d.VetoVerifier)
	}
}

// TestEvaluate_UnanimousLowConfidenceEscalates: row 5 — ALLOW votes at Low
// confidence can never produce an ALLOW outcome.
func TestEvaluate_UnanimousLowConfidenceEscalates(t *testing.T) {
	stubs := fourStubs([4]Vote{
		allowHigh(""), allowHigh(""), allowHigh(""),
		{Verdict: VerdictAllow, Confidence: ConfidenceLow, Code: "ambiguous"},
	})
	e := newStubEngine(t, stubs...)
	d, err := e.Evaluate(context.Background(), "echo", []string{"x"})
	require.NoError(t, err)
	assert.Equal(t, OutcomeEscalate, d.Outcome)
	assert.Equal(t, approve.TierSensitive, d.Tier)
}

// TestEvaluate_VerifierErrorFailsClosed: a vote carrying an error marker maps
// to ESCALATE, never ALLOW.
func TestEvaluate_VerifierErrorFailsClosed(t *testing.T) {
	stubs := fourStubs([4]Vote{
		allowHigh(""), allowHigh(""), allowHigh(""),
		{Verdict: VerdictAbstain, Err: VoteErrProbe},
	})
	e := newStubEngine(t, stubs...)
	d, err := e.Evaluate(context.Background(), "echo", []string{"x"})
	require.NoError(t, err)
	assert.Equal(t, OutcomeEscalate, d.Outcome, "a verifier error must escalate, never allow")
}

// TestEvaluate_VerifierTimeoutFailsClosed: a hung verifier (ignores ctx) is
// synthesized into an ABSTAIN at its budget — fail closed.
func TestEvaluate_VerifierTimeoutFailsClosed(t *testing.T) {
	stubs := fourStubs([4]Vote{allowHigh(""), allowHigh(""), allowHigh(""), allowHigh("")})
	stubs[2].sleep = 2 * time.Second // hangs well past the shrunk budget
	e := newStubEngine(t, stubs...)
	e.perVerifierTimeout = 50 * time.Millisecond
	e.totalBudget = 3 * time.Second

	d, err := e.Evaluate(context.Background(), "echo", []string{"x"})
	require.NoError(t, err)
	assert.Equal(t, OutcomeEscalate, d.Outcome, "a verifier timeout must escalate, never allow")
	found := false
	for _, v := range d.Votes {
		if v.Err == VoteErrTimeout {
			found = true
		}
	}
	assert.True(t, found, "the hung verifier must be recorded as a timeout abstain")
}

// TestEvaluate_VerifierPanicFailsClosed: a panicking verifier is recovered to
// ABSTAIN — fail closed, never a crash, never an allow.
func TestEvaluate_VerifierPanicFailsClosed(t *testing.T) {
	stubs := fourStubs([4]Vote{allowHigh(""), allowHigh(""), allowHigh(""), allowHigh("")})
	stubs[1].panicNow = true
	e := newStubEngine(t, stubs...)
	d, err := e.Evaluate(context.Background(), "echo", []string{"x"})
	require.NoError(t, err)
	assert.Equal(t, OutcomeEscalate, d.Outcome)
	found := false
	for _, v := range d.Votes {
		if v.Err == VoteErrPanic {
			found = true
		}
	}
	assert.True(t, found, "the panicking verifier must be recorded as a panic abstain")
}

// TestEvaluate_TwoFailuresForceCriticalTier: row 3 — ≥2 verifier failures are
// systemic and demand TierCritical (TTY-only in v4).
func TestEvaluate_TwoFailuresForceCriticalTier(t *testing.T) {
	stubs := fourStubs([4]Vote{
		allowHigh(""), allowHigh(""),
		{Verdict: VerdictAbstain, Err: VoteErrProbe},
		{Verdict: VerdictAbstain, Err: VoteErrProbe},
	})
	e := newStubEngine(t, stubs...)
	d, err := e.Evaluate(context.Background(), "echo", []string{"x"})
	require.NoError(t, err)
	assert.Equal(t, OutcomeEscalate, d.Outcome)
	assert.Equal(t, approve.TierCritical, d.Tier, "two failures are systemic — Critical tier")
}

// TestEvaluate_TotalBudgetExceededRefuses: row 7 — the total budget expiring
// before the vote vector completes returns an error (exec refused).
func TestEvaluate_TotalBudgetExceededRefuses(t *testing.T) {
	stubs := fourStubs([4]Vote{allowHigh(""), allowHigh(""), allowHigh(""), allowHigh("")})
	for _, s := range stubs {
		s.sleep = time.Second
	}
	e := newStubEngine(t, stubs...)
	e.perVerifierTimeout = 2 * time.Second
	e.totalBudget = 50 * time.Millisecond

	_, err := e.Evaluate(context.Background(), "echo", []string{"x"})
	require.Error(t, err, "total budget exhaustion must refuse the exec, never allow")
}

// TestEvaluate_TierOverridesRaiseOnly: an override can raise a matched rule's
// tier; the engine-level max() makes lowering structurally inert.
func TestEvaluate_TierOverridesRaiseOnly(t *testing.T) {
	e := New(Config{
		TierOverrides: map[string]approve.TierLevel{"rm-recursive-force": approve.TierCritical},
	}, WithLogger(discardLogger()))
	dir := t.TempDir() // a plain temp dir: no protected path, no VCS
	d, err := e.Evaluate(context.Background(), "rm", []string{"-rf", dir + "/x"})
	require.NoError(t, err)
	assert.Equal(t, OutcomeEscalate, d.Outcome)
	assert.Equal(t, approve.TierCritical, d.Tier, "the raise-only override must lift rm-recursive-force to Critical")
}

// ---------------------------------------------------------------------------
// Audit hygiene and completeness.
// ---------------------------------------------------------------------------

// TestQuorumAudit_NoRawArgv feeds a sentinel SECRET argv token through an
// escalating evaluation and asserts it appears nowhere in audit content or in
// the slog mirror (C-03/C-09, D-38/T-27-14).
func TestQuorumAudit_NoRawArgv(t *testing.T) {
	const sentinel = "SECRET-sentinel-hostname-token"
	app := &fakeAppender{}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	e := New(Config{}, WithLogger(logger), WithAuditAppender(app))
	d, err := e.Evaluate(context.Background(), "rm", []string{"-rf", "/tmp/" + sentinel})
	require.NoError(t, err)
	require.NotEqual(t, OutcomeAllow, d.Outcome, "rm -rf must not be allowed")

	entries := app.all()
	require.NotEmpty(t, entries, "every evaluation must be audited")
	for _, en := range entries {
		assert.NotContains(t, string(en.content), sentinel, "raw argv must NEVER reach audit content")
		assert.NotContains(t, en.target, sentinel)
	}
	assert.NotContains(t, logBuf.String(), sentinel, "raw argv must NEVER reach the slog mirror")

	// The human prompt content is hygiene-ruled too.
	assert.NotContains(t, d.Title(), sentinel)
	assert.NotContains(t, d.Body(), sentinel)
}

// TestQuorumAudit_VoteVectorComplete: the quorum-decision audit entry carries
// the full vote vector — verifier, verdict, confidence, tier, code — for all
// four verifiers, in enforcing AND shadow labeling.
func TestQuorumAudit_VoteVectorComplete(t *testing.T) {
	for _, enforcing := range []bool{true, false} {
		app := &fakeAppender{}
		e := New(Config{Enforcing: enforcing}, WithLogger(discardLogger()), WithAuditAppender(app))
		_, err := e.Evaluate(context.Background(), "echo", []string{"hello"})
		require.NoError(t, err)

		entries := app.all()
		require.Len(t, entries, 1)
		assert.Equal(t, "quorum-decision", entries[0].op)
		assert.True(t, strings.HasPrefix(entries[0].target, "exec:"), "target must be exec:<closure8>")

		var rec decisionRecord
		require.NoError(t, json.Unmarshal(entries[0].content, &rec))
		assert.Equal(t, 1, rec.V)
		wantMode := "shadow"
		if enforcing {
			wantMode = "enforcing"
		}
		assert.Equal(t, wantMode, rec.Mode)
		require.Len(t, rec.Votes, 4, "all four verifiers must appear in the vote vector")
		seen := map[string]bool{}
		for _, v := range rec.Votes {
			seen[v.Verifier] = true
			assert.NotEmpty(t, v.Verdict)
			assert.NotEmpty(t, v.Confidence)
			assert.NotEmpty(t, v.Tier)
		}
		for _, name := range []string{"V1 syntactic", "V2 policy", "V3 behavior", "V4 reversibility"} {
			assert.True(t, seen[name], "vote vector missing %s", name)
		}
		assert.NotEmpty(t, rec.DecisionID)
		assert.Equal(t, "echo", rec.Binary)
	}
}

// TestDecision_DissentFirstSummary: the human prompt leads with the strongest
// objection, never a consensus summary.
func TestDecision_DissentFirstSummary(t *testing.T) {
	d := Decision{
		Binary:   "git",
		Closure8: "0011223344556677",
		Votes: []Vote{
			{Verifier: "V1 syntactic", Verdict: VerdictAllow, Confidence: ConfidenceHigh},
			{Verifier: "V4 reversibility", Verdict: VerdictEscalate, Confidence: ConfidenceHigh, Tier: approve.TierCritical, Code: "no-undo", Reason: "no undo — unpushed commits"},
			{Verifier: "V2 policy", Verdict: VerdictAllow, Confidence: ConfidenceHigh},
			{Verifier: "V3 behavior", Verdict: VerdictEscalate, Confidence: ConfidenceHigh, Tier: approve.TierSensitive, Code: "dry-run-first"},
		},
	}
	summary := d.VoteSummary()
	require.NotEmpty(t, summary)
	assert.True(t, strings.HasPrefix(summary, "V4 reversibility: ESCALATE(critical)"),
		"dissent (highest tier objection) must come first, got: %s", summary)
	assert.Contains(t, d.Title(), "no undo", "the title must carry the top human-readable reason")
}

// TestRecordExec_FeedsBehaviorRing: RecordExec events are visible to V3.
func TestRecordExec_FeedsBehaviorRing(t *testing.T) {
	e := New(Config{}, WithLogger(discardLogger()))
	e.RecordExec("terraform", []string{"plan"})

	d, err := e.Evaluate(context.Background(), "terraform", []string{"apply"})
	require.NoError(t, err)
	// dry-run-first is satisfied by the recorded plan; terraform apply still
	// has no other rule hits, so V3 must NOT be the escalation source.
	for _, v := range d.Votes {
		if v.Verifier == verifierBehaviorName {
			assert.NotEqual(t, "dry-run-first", v.Code,
				"a recorded prior dry-run must satisfy the dry-run-first precondition")
		}
	}
}
