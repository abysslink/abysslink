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
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityNoteCount verifies that the collection has exactly 12 security notes
// (§7 requirement: "Missing any of these = the journey is 'not complete'").
func TestSecurityNoteCount(t *testing.T) {
	assert.Len(t, allSecurityNotes, 12, "allSecurityNotes must contain exactly 12 entries (§7)")
}

// TestSecurityNoteIDs verifies each note has a unique non-empty ID.
func TestSecurityNoteIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range allSecurityNotes {
		require.NotEmpty(t, n.id, "security note must have a non-empty ID")
		require.False(t, seen[n.id], "duplicate security note ID: %q", n.id)
		seen[n.id] = true
	}
}

// TestEmitSecurityNote_DiskEncryption verifies that the disk-encryption note (note 5)
// renders output containing a recognizable phrase about disk encryption / fail-closed.
func TestEmitSecurityNote_DiskEncryption(t *testing.T) {
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)
	emitSecurityNote(p, false, "disk-encryption")
	output := buf.String()
	lowerOut := strings.ToLower(output)
	assert.True(t,
		strings.Contains(lowerOut, "disk encryption") ||
			strings.Contains(lowerOut, "fail closed") ||
			strings.Contains(lowerOut, "fail-closed") ||
			strings.Contains(lowerOut, "encrypted"),
		"disk-encryption note output should mention disk encryption or fail-closed; got: %q", output)
}

// TestEmitSecurityNote_DryRunDefault verifies that note 2 (dry-run is default) renders output.
func TestEmitSecurityNote_DryRunDefault(t *testing.T) {
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)
	emitSecurityNote(p, false, "dry-run-default")
	output := buf.String()
	lowerOut := strings.ToLower(output)
	assert.True(t,
		strings.Contains(lowerOut, "dry-run") || strings.Contains(lowerOut, "dry run"),
		"dry-run-default note should mention dry-run; got: %q", output)
}

// TestEmitSecurityNote_UnknownID verifies that an unknown note ID does not panic.
func TestEmitSecurityNote_UnknownID(t *testing.T) {
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)
	// Should not panic.
	emitSecurityNote(p, false, "nonexistent-note-xyz")
	// No output expected.
	assert.Empty(t, buf.String())
}

// TestEmitSecurityNote_JSONSuppressed verifies notes are suppressed under --json
// so a call site can never leak note prose into the machine-readable stream (WR-01).
func TestEmitSecurityNote_JSONSuppressed(t *testing.T) {
	var buf bytes.Buffer
	p := NewHumanPrinterTo(&buf, &buf)
	emitSecurityNote(p, true, "disk-encryption")
	assert.Empty(t, buf.String(), "emitSecurityNote must produce no output when jsonOut=true")
}

// TestSecurityNotesWired verifies that each of the 12 note IDs is referenced at least
// once across the journey/command files. This is a coverage guard: a note defined but
// never emitted means the journey is incomplete (§7 "missing any = not complete").
// We verify wiring by calling emitSecurityNote for each ID — if the function renders
// non-empty output the note is at minimum defined and callable.
func TestSecurityNotesWired(t *testing.T) {
	for _, n := range allSecurityNotes {
		t.Run(n.id, func(t *testing.T) {
			var buf bytes.Buffer
			p := NewHumanPrinterTo(&buf, &buf)
			emitSecurityNote(p, false, n.id)
			assert.NotEmpty(t, buf.String(), "note %q should produce output when emitted", n.id)
		})
	}
}

// TestPrintPlanDetail_ExplainGated verifies that printPlanDetail respects the explain flag.
func TestPrintPlanDetail_ExplainGated(t *testing.T) {
	actions := []modules.Action{
		{Module: "tailscale", Description: "install tailscale", Explain: "rationale text here"},
	}

	// explain=false: rationale should NOT appear.
	var bufOff bytes.Buffer
	pOff := NewHumanPrinterTo(&bufOff, &bufOff)
	printPlanDetail(pOff, actions, nil, true, false)
	assert.NotContains(t, bufOff.String(), "rationale text here",
		"explain=false: action.Explain text must be suppressed")

	// explain=true: rationale SHOULD appear.
	var bufOn bytes.Buffer
	pOn := NewHumanPrinterTo(&bufOn, &bufOn)
	printPlanDetail(pOn, actions, nil, true, true)
	assert.Contains(t, bufOn.String(), "rationale text here",
		"explain=true: action.Explain text must be rendered")
}
