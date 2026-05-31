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

// TestJourneyStageCount asserts that journeyStages returns exactly 7 stages.
func TestJourneyStageCount(t *testing.T) {
	stages := journeyStages(false, config.Defaults(), &shell.ExecRunner{})
	assert.Len(t, stages, 7, "journey must have exactly 7 stages")
}

// TestJourneyStageLabels asserts that the 7 stage labels match the specified names.
func TestJourneyStageLabels(t *testing.T) {
	stages := journeyStages(false, config.Defaults(), &shell.ExecRunner{})
	require.Len(t, stages, 7)

	expectedLabels := []string{
		"Account",
		"Prerequisites",
		"Converge",
		"Lock",
		"Enroll",
		"Verify",
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
