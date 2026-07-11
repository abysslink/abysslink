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

package gate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/quorum"
	"github.com/abysslink/abysslink/internal/shell"
)

// stubPolicy is a scripted QuorumPolicy for gate wiring tests.
type stubPolicy struct {
	mu        sync.Mutex
	decision  quorum.Decision
	err       error
	evaluated [][]string
	recorded  [][]string
	slow      time.Duration
}

var _ QuorumPolicy = (*stubPolicy)(nil)

func (s *stubPolicy) Evaluate(_ context.Context, name string, args []string) (quorum.Decision, error) {
	if s.slow > 0 {
		time.Sleep(s.slow)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evaluated = append(s.evaluated, append([]string{name}, args...))
	return s.decision, s.err
}

func (s *stubPolicy) RecordExec(name string, args []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorded = append(s.recorded, append([]string{name}, args...))
}

func (s *stubPolicy) evalCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.evaluated)
}

func (s *stubPolicy) recordedCalls() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.recorded))
	copy(out, s.recorded)
	return out
}

// TestGated_QuorumDenyBlocksInner: a quorum DENY refuses the exec with
// ErrQuorumDenied; the inner runner is never called; the counter still
// increments.
func TestGated_QuorumDenyBlocksInner(t *testing.T) {
	inner := &fakeInner{}
	q := &stubPolicy{decision: quorum.Decision{Outcome: quorum.OutcomeDeny, VetoVerifier: "V1 syntactic"}}
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)), WithQuorum(q))

	_, err := g.Run(context.Background(), "rm", "-rf", "/")
	require.ErrorIs(t, err, ErrQuorumDenied)
	assert.NotContains(t, inner.seen(), "Run", "inner must NOT be called on a quorum deny")
	assert.Equal(t, uint64(1), g.Count(), "counter still increments on a refused exec")
	assert.Empty(t, q.recordedCalls(), "a denied exec must not feed the behavior history")
}

// TestGated_QuorumEscalateReturnsApprovalRequiredWithTier: an ESCALATE with
// no token returns *ApprovalRequiredError carrying the demanded tier and
// satisfying errors.Is(err, ErrApprovalRequired).
func TestGated_QuorumEscalateReturnsApprovalRequiredWithTier(t *testing.T) {
	inner := &fakeInner{}
	q := &stubPolicy{decision: quorum.Decision{Outcome: quorum.OutcomeEscalate, Tier: approve.TierCritical}}
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)), WithQuorum(q))

	_, err := g.Run(context.Background(), "git", "push", "--force", "origin", "main")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrApprovalRequired, "existing errors.Is callers must keep working")

	var areq *ApprovalRequiredError
	require.ErrorAs(t, err, &areq)
	assert.Equal(t, approve.TierCritical, areq.Tier, "the demanded tier must ride the error")
	assert.NotContains(t, inner.seen(), "Run")
}

// TestGated_QuorumAllowPassesThrough: a unanimous confident ALLOW proceeds
// with no token — audit-only — and feeds RecordExec.
func TestGated_QuorumAllowPassesThrough(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "ok"}}
	q := &stubPolicy{decision: quorum.Decision{Outcome: quorum.OutcomeAllow}}
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)), WithQuorum(q))

	res, err := g.Run(context.Background(), "ls", "-la")
	require.NoError(t, err)
	assert.Equal(t, "ok", res.Stdout)
	assert.Contains(t, inner.seen(), "Run")
	require.Len(t, q.recordedCalls(), 1, "a passed exec must feed the behavior history")
	assert.Equal(t, []string{"ls", "-la"}, q.recordedCalls()[0])
}

// TestGated_QuorumEvaluationErrorRefuses: row 7 — an Evaluate error (canceled
// ctx / budget exceeded) refuses the exec. Fail closed: never an allow.
func TestGated_QuorumEvaluationErrorRefuses(t *testing.T) {
	inner := &fakeInner{}
	q := &stubPolicy{err: errors.New("budget exceeded")}
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)), WithQuorum(q))

	_, err := g.Run(context.Background(), "echo", "hello")
	require.Error(t, err, "a quorum evaluation error must refuse the exec")
	assert.NotContains(t, inner.seen(), "Run")
}

// TestGated_FloorDenyBeatsValidToken uses a REAL quorum engine: a stage-0
// floor action carrying a VALID approval token must still be denied — the
// floor precedes token honor (row 0a).
func TestGated_FloorDenyBeatsValidToken(t *testing.T) {
	inner := &fakeInner{}
	engine := quorum.New(quorum.Config{Enforcing: true}, quorum.WithLogger(discardLogger()))
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)), WithQuorum(engine))

	name, args := "tailscale", []string{"funnel", "2586"}
	tok := &approveToken{ClosureHash: closureHash(name, args), Tier: approve.TierCritical}
	ctx := WithApprovalToken(context.Background(), tok)

	_, err := g.Run(ctx, name, args...)
	require.ErrorIs(t, err, ErrQuorumDenied, "a valid token must NOT bypass the deny floor")
	assert.NotContains(t, inner.seen(), "Run")
}

// TestGated_TokenTierInsufficientReescalates: row 9 — a Sensitive token
// against a Critical escalation re-escalates at the computed tier.
func TestGated_TokenTierInsufficientReescalates(t *testing.T) {
	inner := &fakeInner{}
	q := &stubPolicy{decision: quorum.Decision{Outcome: quorum.OutcomeEscalate, Tier: approve.TierCritical}}
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)), WithQuorum(q))

	name, args := "rm", []string{"-rf", "/etc/ssh"}
	tok := &approveToken{ClosureHash: closureHash(name, args), Tier: approve.TierSensitive}
	ctx := WithApprovalToken(context.Background(), tok)

	_, err := g.Run(ctx, name, args...)
	var areq *ApprovalRequiredError
	require.ErrorAs(t, err, &areq, "an insufficient token tier must re-escalate")
	assert.Equal(t, approve.TierCritical, areq.Tier)
	assert.NotContains(t, inner.seen(), "Run")
}

// TestGated_TokenSufficientTierPasses: a matching token at (or above) the
// demanded tier lets the escalated exec proceed and feeds RecordExec.
func TestGated_TokenSufficientTierPasses(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "done"}}
	q := &stubPolicy{decision: quorum.Decision{Outcome: quorum.OutcomeEscalate, Tier: approve.TierSensitive}}
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)), WithQuorum(q))

	name, args := "git", []string{"push", "--force", "origin", "feature/x"}
	tok := &approveToken{ClosureHash: closureHash(name, args), Tier: approve.TierSensitive}
	ctx := WithApprovalToken(context.Background(), tok)

	res, err := g.Run(ctx, name, args...)
	require.NoError(t, err)
	assert.Equal(t, "done", res.Stdout)
	assert.Len(t, q.recordedCalls(), 1)
}

// TestGated_QuorumTokenHashMismatchStillRefuses: the TOCTOU closure hash
// re-verification is unchanged under quorum wiring.
func TestGated_QuorumTokenHashMismatchStillRefuses(t *testing.T) {
	inner := &fakeInner{}
	q := &stubPolicy{decision: quorum.Decision{Outcome: quorum.OutcomeEscalate, Tier: approve.TierSensitive}}
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)), WithQuorum(q))

	tok := &approveToken{ClosureHash: [32]byte{1}, Tier: approve.TierCritical}
	ctx := WithApprovalToken(context.Background(), tok)

	_, err := g.Run(ctx, "echo", "hello")
	require.ErrorIs(t, err, ErrClosureHashMismatch)
	assert.NotContains(t, inner.seen(), "Run")
}

// TestGated_ShadowModeNeverBlocksOrSlows: a non-enforcing gate with quorum
// wired must delegate immediately even when Evaluate is slow or the decision
// is DENY; RecordExec still runs synchronously.
func TestGated_ShadowModeNeverBlocksOrSlows(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "shadow-ok"}}
	q := &stubPolicy{
		decision: quorum.Decision{Outcome: quorum.OutcomeDeny},
		slow:     300 * time.Millisecond,
	}
	g := New(inner, WithLogger(discardLogger()), WithQuorum(q)) // NOT enforcing

	start := time.Now()
	res, err := g.Run(context.Background(), "rm", "-rf", "/")
	elapsed := time.Since(start)

	require.NoError(t, err, "shadow mode must never block an exec")
	assert.Equal(t, "shadow-ok", res.Stdout)
	assert.Contains(t, inner.seen(), "Run")
	assert.Less(t, elapsed, 200*time.Millisecond,
		"the slow shadow evaluation must run asynchronously, not inline")
	assert.Len(t, q.recordedCalls(), 1, "RecordExec runs synchronously in shadow mode")

	// The async evaluation eventually fires (shadow calibration corpus).
	assert.Eventually(t, func() bool { return q.evalCount() == 1 },
		2*time.Second, 10*time.Millisecond, "the shadow decision must still be evaluated")
}

// TestGated_RecordExecFeedsBehaviorHistory drives a REAL engine through the
// gate twice: the first pass records history that satisfies V3's
// dry-run-first precondition on the second pass.
func TestGated_RecordExecFeedsBehaviorHistory(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "ok"}}
	engine := quorum.New(quorum.Config{}, quorum.WithLogger(discardLogger()))

	// Shadow gate with the real engine.
	g := New(inner, WithLogger(discardLogger()), WithQuorum(engine))
	_, err := g.Run(context.Background(), "terraform", "plan")
	require.NoError(t, err)

	// The recorded plan must now satisfy dry-run-first for a direct Evaluate.
	d, err := engine.Evaluate(context.Background(), "terraform", []string{"apply"})
	require.NoError(t, err)
	for _, v := range d.Votes {
		if v.Verifier == "V3 behavior" {
			assert.NotEqual(t, "dry-run-first", v.Code,
				"the gate's RecordExec must warm V3 history")
		}
	}
}

// TestGated_InternalBypassUnchanged: D-40 — a plain New (no WithEnforcing, no
// WithQuorum) never blocks, exactly as before.
func TestGated_InternalBypassUnchanged(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "bypass"}}
	g := New(inner, WithLogger(discardLogger()))

	res, err := g.Run(context.Background(), "tmux", "-CC", "attach-session")
	require.NoError(t, err)
	assert.Equal(t, "bypass", res.Stdout)
}

// TestGated_LegacyEnforcingWithoutQuorumUnchanged: row 16 — an enforcing gate
// with NO quorum wired keeps the pre-quorum behavior: every exec requires
// approval (strictly tighter than quorum).
func TestGated_LegacyEnforcingWithoutQuorumUnchanged(t *testing.T) {
	inner := &fakeInner{}
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(approve.NewRegistry(nil)))

	_, err := g.Run(context.Background(), "ls")
	require.ErrorIs(t, err, ErrApprovalRequired)
	assert.NotContains(t, inner.seen(), "Run")
}

// ---------------------------------------------------------------------------
// Escalation resolution through the existing approve seams (fail-closed
// timeout semantics are inherited, not re-implemented).
// ---------------------------------------------------------------------------

// escalationFixture opens a Sensitive-tier pending request as the quorum
// escalation path would (quorum tier = declared tier).
func escalationFixture(t *testing.T, reg *approve.Registry, name string, args []string) (*approve.ApprovalToken, string) {
	t.Helper()
	const requestID = "quorum-esc-0001"
	req, err := reg.OpenWithDenySig(requestID, closureHash(name, args), approve.TierSensitive, "sig", "denysig")
	require.NoError(t, err)
	tok := approve.Token(req)
	return &tok, requestID
}

// TestEscalate_PhoneApproveMintsTokenAndExecProceeds: approve resolution
// mints a token whose tier satisfies the quorum decision; the retried exec
// passes.
func TestEscalate_PhoneApproveMintsTokenAndExecProceeds(t *testing.T) {
	inner := &fakeInner{res: shell.Result{Stdout: "approved-run"}}
	q := &stubPolicy{decision: quorum.Decision{Outcome: quorum.OutcomeEscalate, Tier: approve.TierSensitive}}
	reg := approve.NewRegistry(nil)
	g := New(inner, WithLogger(discardLogger()), WithEnforcing(reg), WithQuorum(q))

	name, args := "git", []string{"push", "origin", "feature/x"}

	// First attempt escalates.
	_, err := g.Run(context.Background(), name, args...)
	require.ErrorIs(t, err, ErrApprovalRequired)

	// Phone taps approve (daemon CAS), the waiter receives the resolution.
	tok, requestID := escalationFixture(t, reg, name, args)
	require.True(t, reg.Resolve(requestID, approve.StateApproved))
	res, err := reg.WaitByID(context.Background(), requestID, false)
	require.NoError(t, err)
	require.True(t, res.Approved)

	// Retry with the minted token: re-evaluation runs, the exec proceeds.
	ctx := WithApprovalToken(context.Background(), tok)
	out, err := g.Run(ctx, name, args...)
	require.NoError(t, err)
	assert.Equal(t, "approved-run", out.Stdout)
	assert.Equal(t, 2, q.evalCount(), "the token retry must RE-EVALUATE against current world state")
}

// TestEscalate_PhoneDenyRefuses: a deny resolution yields ErrDenied; no exec.
func TestEscalate_PhoneDenyRefuses(t *testing.T) {
	reg := approve.NewRegistry(nil)
	name, args := "git", []string{"push", "origin", "feature/x"}
	_, requestID := escalationFixture(t, reg, name, args)

	require.True(t, reg.Resolve(requestID, approve.StateDenied))
	res, err := reg.WaitByID(context.Background(), requestID, false)
	require.ErrorIs(t, err, approve.ErrDenied)
	assert.False(t, res.Approved, "no deny path may ever read as approved")
}

// TestEscalate_HeadlessTimeoutDenies: an unanswered headless wait resolves to
// ErrHeadlessTimeoutDenied — fail closed, no exec (dead-man semantics).
func TestEscalate_HeadlessTimeoutDenies(t *testing.T) {
	reg := approve.NewRegistry(nil)
	name, args := "rm", []string{"-rf", "./build"}
	_, requestID := escalationFixture(t, reg, name, args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	res, err := reg.WaitByID(ctx, requestID, false)
	require.ErrorIs(t, err, approve.ErrHeadlessTimeoutDenied)
	assert.ErrorIs(t, err, approve.ErrDenied, "headless timeout wraps the deny sentinel")
	assert.False(t, res.Approved)
}

// TestEscalate_TTYTimeoutFallsBackNeverAutoApproves: a TTY wait timeout
// returns ErrTimeout (the TTY-fallback signal) and never an approval.
func TestEscalate_TTYTimeoutFallsBackNeverAutoApproves(t *testing.T) {
	reg := approve.NewRegistry(nil)
	name, args := "rm", []string{"-rf", "./build"}
	_, requestID := escalationFixture(t, reg, name, args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	res, err := reg.WaitByID(ctx, requestID, true)
	require.ErrorIs(t, err, approve.ErrTimeout)
	assert.False(t, res.Approved, "a TTY timeout must fall back to a prompt, never auto-approve")
}

// TestEscalate_CriticalTierIsTTYOnly: a Critical-tier open is refused outright
// (D-07) — the quorum's Critical escalations cannot take the phone path in v4.
func TestEscalate_CriticalTierIsTTYOnly(t *testing.T) {
	reg := approve.NewRegistry(nil)
	_, err := reg.OpenWithDenySig("quorum-esc-crit", [32]byte{}, approve.TierCritical, "sig", "denysig")
	require.ErrorIs(t, err, approve.ErrCriticalTierTTYOnly)
}
