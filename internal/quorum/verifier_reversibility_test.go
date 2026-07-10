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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/shell"
)

// tempTarget creates a real file so V4's stat sweep finds an existing target.
func tempTarget(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "data.txt")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	return p
}

// v4Check runs V4 with a scripted runner over one argv.
func v4Check(t *testing.T, runner shell.Runner, name string, args ...string) Vote {
	t.Helper()
	v := newReversibilityVerifier(runner, nil, time.Now)
	return v.check(context.Background(), action{name: name, args: args, binary: filepath.Base(name)})
}

func TestReversibility_NoVCSNoUndoEscalates(t *testing.T) {
	target := tempTarget(t)
	// Probe 1 answers "not a work tree" (non-zero exit).
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 128, Stderr: "fatal: not a git repository"}})

	vote := v4Check(t, runner, "rm", "-rf", target)
	assert.Equal(t, VerdictEscalate, vote.Verdict)
	assert.Equal(t, codeNoUndo, vote.Code)
	assert.Equal(t, approve.TierSensitive, vote.Tier)
	assert.NotContains(t, vote.Reason, target, "the reason must never carry the raw path")
}

func TestReversibility_CleanPushedTreeAllows(t *testing.T) {
	target := tempTarget(t)
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "true\n"}}, // in work tree
		shell.Call{Result: shell.Result{Stdout: ""}},       // clean status
		shell.Call{Result: shell.Result{Stdout: "0\n"}},    // nothing unpushed
	)

	vote := v4Check(t, runner, "rm", "-f", target)
	assert.Equal(t, VerdictAllow, vote.Verdict)
	assert.Equal(t, ConfidenceHigh, vote.Confidence)
	assert.Equal(t, codeUndoAvailable, vote.Code)
	assert.True(t, runner.Done(), "all three probes must have run")
}

func TestReversibility_DirtyTreeEscalates(t *testing.T) {
	target := tempTarget(t)
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "true\n"}},
		shell.Call{Result: shell.Result{Stdout: "?? data.txt\n"}}, // untracked
		shell.Call{Result: shell.Result{Stdout: "0\n"}},
	)

	vote := v4Check(t, runner, "rm", "-f", target)
	assert.Equal(t, VerdictEscalate, vote.Verdict)
	assert.Equal(t, codeNoUndo, vote.Code)
	assert.Contains(t, vote.Reason, "dirty or untracked")
}

func TestReversibility_UnpushedCommitsEscalate(t *testing.T) {
	target := tempTarget(t)
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "true\n"}},
		shell.Call{Result: shell.Result{Stdout: ""}},
		shell.Call{Result: shell.Result{Stdout: "3\n"}}, // 3 unpushed commits
	)

	vote := v4Check(t, runner, "rm", "-f", target)
	assert.Equal(t, VerdictEscalate, vote.Verdict)
	assert.Contains(t, vote.Reason, "unpushed commits")
}

func TestReversibility_MissingUpstreamCountsAsUnpushed(t *testing.T) {
	target := tempTarget(t)
	runner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "true\n"}},
		shell.Call{Result: shell.Result{Stdout: ""}},
		shell.Call{Result: shell.Result{ExitCode: 128, Stderr: "fatal: no upstream configured"}},
	)

	vote := v4Check(t, runner, "rm", "-f", target)
	assert.Equal(t, VerdictEscalate, vote.Verdict,
		"no upstream means nothing is backed up remotely — no undo")
}

func TestReversibility_ProbeErrorAbstains(t *testing.T) {
	target := tempTarget(t)
	runner := shell.NewMockRunner(shell.Call{Err: errors.New("git binary missing")})

	vote := v4Check(t, runner, "rm", "-f", target)
	assert.Equal(t, VerdictAbstain, vote.Verdict, "a probe error must ABSTAIN (fail closed), never allow")
	assert.Equal(t, VoteErrProbe, vote.Err)
	assert.Equal(t, OutcomeEscalate, effectiveOutcome(vote), "the lattice escalates an abstain")
}

func TestReversibility_NilRunnerAbstainsWhenTriggered(t *testing.T) {
	target := tempTarget(t)
	vote := v4Check(t, nil, "rm", "-f", target)
	assert.Equal(t, VerdictAbstain, vote.Verdict, "no probe path = fail closed when triggered")
}

func TestReversibility_NotTriggeredAllows(t *testing.T) {
	// Non-mutating binary, no protected path args: not triggered, no probes.
	runner := shell.NewMockRunner() // zero scripted calls — any probe would error
	vote := v4Check(t, runner, "ls", "-la")
	assert.Equal(t, VerdictAllow, vote.Verdict)
	assert.Equal(t, ConfidenceHigh, vote.Confidence)
	assert.True(t, runner.Done())
}

func TestReversibility_NonexistentTargetAllows(t *testing.T) {
	// Mutating binary but the target does not stat: no blast radius.
	runner := shell.NewMockRunner()
	vote := v4Check(t, runner, "rm", "-rf", "/nonexistent/path/xyz")
	assert.Equal(t, VerdictAllow, vote.Verdict)
	assert.True(t, runner.Done(), "no probes may run for a nonexistent target")
}

func TestReversibility_ProbeCacheTTL(t *testing.T) {
	target := tempTarget(t)
	clock := newFakeClock()
	runner := shell.NewMockRunner(
		// Only ONE probe triple scripted: the second check must hit the cache.
		shell.Call{Result: shell.Result{Stdout: "true\n"}},
		shell.Call{Result: shell.Result{Stdout: ""}},
		shell.Call{Result: shell.Result{Stdout: "0\n"}},
	)
	v := newReversibilityVerifier(runner, nil, clock.now)
	act := action{name: "rm", args: []string{"-f", target}, binary: "rm"}

	first := v.check(context.Background(), act)
	assert.Equal(t, codeUndoAvailable, first.Code)

	clock.advance(5 * time.Second) // inside the 10s TTL
	second := v.check(context.Background(), act)
	assert.Equal(t, codeUndoAvailable, second.Code, "the cached probe must serve the second check")
	assert.True(t, runner.Done(), "no extra probe calls inside the TTL")
}

func TestReversibility_ProtectedPrefixNoUndoIsCritical(t *testing.T) {
	// Use a config-added protected path pointing at a real temp dir so the
	// stat sweep and the protected match line up hermetically.
	dir := t.TempDir()
	p := filepath.Join(dir, "inventory.db")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))

	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 128}}) // not a work tree
	v := newReversibilityVerifier(runner, []string{dir}, time.Now)
	vote := v.check(context.Background(), action{name: "rm", args: []string{"-rf", p}, binary: "rm"})

	assert.Equal(t, VerdictEscalate, vote.Verdict)
	assert.Equal(t, codeNoUndoProtected, vote.Code)
	assert.Equal(t, approve.TierCritical, vote.Tier, "no undo on a protected prefix demands Critical")
}
