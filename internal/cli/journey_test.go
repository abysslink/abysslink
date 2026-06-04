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

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJourneyStageCount asserts that journeyStages returns exactly 8 stages.
func TestJourneyStageCount(t *testing.T) {
	stages := journeyStages(false, config.Defaults(), &shell.ExecRunner{}, true)
	assert.Len(t, stages, 8, "journey must have exactly 8 stages")
}

// TestJourneyStageLabels asserts that the 8 stage labels match the specified names,
// including the new ACL stage at index 6 (before Done at index 7).
func TestJourneyStageLabels(t *testing.T) {
	stages := journeyStages(false, config.Defaults(), &shell.ExecRunner{}, true)
	require.Len(t, stages, 8)

	expectedLabels := []string{
		"Account",
		"Prerequisites",
		"Converge",
		"Lock",
		"Enroll",
		"Verify",
		"ACL",
		"Done",
	}
	for i, expected := range expectedLabels {
		assert.Equal(t, expected, stages[i].label, "stage %d label mismatch", i+1)
	}
}

// TestJourneyStateRoundTrip asserts that writeJourneyState and readJourneyState
// can persists and recover the last completed stage index, and that the file
// contains no secret content — only a stage integer.
func TestJourneyStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "journey-state.json")

	// Write stage 3 as last completed.
	err := writeJourneyState(stateFile, 3)
	require.NoError(t, err)

	// Read it back.
	stage, err := readJourneyState(stateFile)
	require.NoError(t, err)
	assert.Equal(t, 3, stage, "round-trip must return the same stage")

	// Assert the file contains no secrets — only an integer field.
	raw, err := os.ReadFile(stateFile)
	require.NoError(t, err)
	content := string(raw)
	assert.NotContains(t, content, "key", "resume file must not contain any key field")
	assert.NotContains(t, content, "secret", "resume file must not contain any secret field")
	assert.NotContains(t, content, "token", "resume file must not contain any token field")
	assert.Contains(t, content, "last_stage", "resume file must contain the last_stage field")
}

// TestJourneyStateResumesFromStage asserts that readJourneyState returns 0
// for a missing file (start from beginning) and the correct stage for an
// existing file.
func TestJourneyStateResumesFromStage(t *testing.T) {
	dir := t.TempDir()

	// Missing file → 0 (start from beginning).
	missingFile := filepath.Join(dir, "nonexistent.json")
	stage, err := readJourneyState(missingFile)
	require.NoError(t, err, "missing state file must not error (start from stage 0)")
	assert.Equal(t, 0, stage, "missing file must return 0")

	// Write stage 5.
	stateFile := filepath.Join(dir, "journey-state.json")
	require.NoError(t, writeJourneyState(stateFile, 5))

	stage, err = readJourneyState(stateFile)
	require.NoError(t, err)
	assert.Equal(t, 5, stage)
}

// TestRunJourney_AutoYes asserts that runJourney with autoYes=true runs all
// stages without hanging (no interactive Pause calls that would block in CI).
// The stages' run functions are stubs in this test so no real system changes occur.
func TestRunJourney_AutoYes(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	// Build a minimal stub journey with 2 stages that just return nil.
	stagesRan := 0
	stages := []journeyStage{
		{
			index: 1,
			label: "StageA",
			run: func(ctx context.Context, p Printer) error {
				stagesRan++
				return nil
			},
		},
		{
			index: 2,
			label: "StageB",
			run: func(ctx context.Context, p Printer) error {
				stagesRan++
				return nil
			},
		},
	}

	// runJourney with autoYes=true and no Pause calls.
	stateFile := filepath.Join(t.TempDir(), "journey-state.json")
	err := runJourney(ctx, p, stages, 0, stateFile, true)
	require.NoError(t, err)
	assert.Equal(t, 2, stagesRan, "all stages must run")
	// No JourneyHeader or Pause written since autoYes skips interactive elements.
}

// TestRunJourney_ResumesFromStage asserts that runJourney skips stages before
// the resume point and runs stages from resume+1 onward.
func TestRunJourney_ResumesFromStage(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	ran := make([]int, 0)
	stages := []journeyStage{
		{index: 1, label: "A", run: func(_ context.Context, _ Printer) error { ran = append(ran, 1); return nil }},
		{index: 2, label: "B", run: func(_ context.Context, _ Printer) error { ran = append(ran, 2); return nil }},
		{index: 3, label: "C", run: func(_ context.Context, _ Printer) error { ran = append(ran, 3); return nil }},
	}

	stateFile := filepath.Join(t.TempDir(), "journey-state.json")
	// Resume from stage 2 (completed) — should only run stage 3.
	err := runJourney(ctx, p, stages, 2, stateFile, true)
	require.NoError(t, err)
	assert.Equal(t, []int{3}, ran, "must only run stages after the resume point")
}

// TestJourneyInitCmd_YesFlagRegistered asserts that newInitCmd registers a
// --resume flag (sanity check for cmd_init.go wiring).
func TestJourneyInitCmd_YesFlagRegistered(t *testing.T) {
	cmd := newInitCmd()
	require.NotNil(t, cmd.Flags().Lookup("resume"), "--resume flag must be registered on init command")
}

// TestJourneyStage2_NoDuplicateCalls asserts that Stage 2's run closure does not
// call ensureTailscale or runSecurityFixes (those already ran in cmd_init RunE).
//
// Strategy: pass a MockRunner scripted with zero calls; if Stage 2 makes any
// subprocess call, MockRunner will return an unexpected-call error. Additionally,
// we assert the output contains "Prerequisites verified." to confirm the new
// summary path (not the old re-run path).
//
// runner.Done() proves no calls went through the injected runner; output assertion
// proves Stage 2 is the new summary path, not the old re-run path.
func TestJourneyStage2_NoDuplicateCalls(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	// Zero scripted calls — any subprocess call = test failure.
	runner := shell.NewMockRunner()

	// autoYes=true ensures no huh prompts block.
	stages := journeyStages(false, config.Defaults(), runner, true)
	require.True(t, len(stages) >= 2)

	// Run only stage 2 (index 1 in the slice — 0-based).
	stage2 := stages[1]
	err := stage2.run(ctx, p)
	require.NoError(t, err)

	// runner.Done() proves no calls went through the injected runner.
	assert.True(t, runner.Done(), "Stage 2 must not make any subprocess calls through the injected runner")

	// Output assertion distinguishes the fixed Stage 2 (which emits "Prerequisites verified.")
	// from the old Stage 2 (which emitted ensureTailscale/runSecurityFixes output).
	// The old code created its own &shell.ExecRunner{} and never used the passed runner,
	// so runner.Done() would be vacuously true — this output check catches that regression.
	assert.Contains(t, buf.String(), "Prerequisites verified.",
		"Stage 2 output must contain 'Prerequisites verified.' to confirm the new summary path")
}

// TestRunJourney_NonTTY asserts that the journey completes without hanging
// when stdin is not a TTY (as is always the case under `go test`).
//
// Under go test, stdin is never a TTY — stdinIsTTY() returns false, so all
// stage gates (tui.Pause and interactive()) are no-ops regardless of autoYes=false.
// This exercises the non-TTY branch explicitly.
func TestRunJourney_NonTTY(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	stagesRan := 0
	stages := []journeyStage{
		{index: 1, label: "A", run: func(_ context.Context, _ Printer) error {
			stagesRan++
			return nil
		}},
		{index: 2, label: "B", run: func(_ context.Context, _ Printer) error {
			stagesRan++
			return nil
		}},
	}

	stateFile := filepath.Join(t.TempDir(), "journey-state.json")
	// autoYes=false but non-TTY (go test stdin) — must not hang.
	err := runJourney(ctx, p, stages, 0, stateFile, false)
	require.NoError(t, err)
	assert.Equal(t, 2, stagesRan, "all stages must run under non-TTY stdin")
}
