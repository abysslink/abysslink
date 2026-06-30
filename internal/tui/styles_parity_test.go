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

package tui_test

// styles_parity_test.go — byte-stability golden tests for the tui header and
// livetable renderers (Plan 34-02 / TUI-08 success criterion 3).
//
// These goldens are captured BEFORE the Plan 03 color consolidation so that
// any accidental byte change on a NO_COLOR path fails a test instead of
// shipping silently.
//
// Isolation: t.Setenv("NO_COLOR","1") so renderers take the no-color path
// (deterministic, no ANSI). Both JourneyHeader and RenderRows are pure
// functions (no I/O, no shell calls) so no runner seam is needed.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/tui"
	"github.com/stretchr/testify/require"
)

// captureOrAssertTUIGolden is the shared capture-on-first-run / assert-on-
// subsequent-run helper used by every TUI styles parity test. It mirrors the
// pattern in internal/cli/parity_test.go.
func captureOrAssertTUIGolden(t *testing.T, goldenPath, got string) {
	t.Helper()
	if _, statErr := os.Stat(goldenPath); os.IsNotExist(statErr) {
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o750))
		require.NoError(t, os.WriteFile(goldenPath, []byte(got), 0o600),
			"failed to write golden file %s", goldenPath)
		t.Logf("golden captured at %s (%d bytes)", goldenPath, len(got))
		return
	}
	golden, err := os.ReadFile(goldenPath) //nolint:gosec // G304: test reads a committed fixture path, not user input
	require.NoError(t, err)
	require.Equal(t, string(golden), got,
		"output differs from golden %s; if the change is intentional, delete the golden and re-run to regenerate", goldenPath)
}

// TestJourneyHeaderParity captures the byte-for-byte JourneyHeader output
// as a golden fixture (internal/tui/testdata/header_v1.golden).
//
// A representative argument set (stage=3, total=5, five labels) is used so
// that all three header row states render: done (stages 1-2), current (stage 3),
// and remaining (stages 4-5). Under NO_COLOR=1, JourneyHeader takes the
// no-color ASCII path — no lipgloss box, no ANSI escape codes.
func TestJourneyHeaderParity(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	labels := []string{"Account", "Prerequisites", "Converge", "Lock", "Done"}
	got := tui.JourneyHeader(3, 5, labels)

	goldenPath := filepath.Join("testdata", "header_v1.golden")
	captureOrAssertTUIGolden(t, goldenPath, got)

	// Byte-stability assertions: the golden must be non-empty and contain
	// content that exercises the done/current/remaining paths.
	require.NotEmpty(t, got, "JourneyHeader output must not be empty")
	// NO_COLOR ASCII done glyph: "v" (v = completed stage dot)
	require.Contains(t, got, "v", "header golden must contain done-stage ASCII glyph (v)")
	// NO_COLOR ASCII current glyph: "o" (o = current stage dot)
	require.Contains(t, got, "o", "header golden must contain current-stage ASCII glyph (o)")
	// NO_COLOR ASCII remaining glyph: "." (. = remaining stage dot)
	require.Contains(t, got, ".", "header golden must contain remaining-stage ASCII glyph (.)")
	// Stage text
	require.Contains(t, got, "Stage 3 of 5", "header golden must contain stage text")
}

// TestLiveTableRowParity captures the byte-for-byte RenderRows output for all
// four settled RowEvent states as a golden fixture
// (internal/tui/testdata/livetable_v1.golden).
//
// Four rows are rendered — success, error, warn, and a bare default — to
// exercise all branches of renderRow. Under NO_COLOR=1 lipgloss strips ANSI;
// the glyph characters (✓/⚠) remain as plain UTF-8.
func TestLiveTableRowParity(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	rows := []tui.RowEvent{
		// success: no error, no warn → ✓ done
		{Module: "tailscale", Index: 1, Total: 4},
		// error: HasError → ⚠ with message
		{Module: "ntfy", Index: 2, Total: 4, HasError: true, ErrMsg: "not installed"},
		// warn: HasWarn → ⚠ with warn message
		{Module: "mosh", Index: 3, Total: 4, HasWarn: true, WarnMsg: "version below floor"},
		// success: another clean row to round out the counter
		{Module: "ssh", Index: 4, Total: 4},
	}
	got := tui.RenderRows(rows)

	goldenPath := filepath.Join("testdata", "livetable_v1.golden")
	captureOrAssertTUIGolden(t, goldenPath, got)

	// Byte-stability assertions: golden must be non-empty and contain
	// the module names and both icon glyphs used by livetable.go.
	require.NotEmpty(t, got, "RenderRows output must not be empty")
	require.Contains(t, got, "tailscale", "livetable golden must contain module name")
	require.Contains(t, got, "ntfy", "livetable golden must contain error-row module name")
	// Under NO_COLOR=1, lipgloss renders glyph chars without ANSI wrapping.
	hasIcon := false
	for _, glyph := range []string{"✓", "⚠"} {
		if bytes.Contains([]byte(got), []byte(glyph)) {
			hasIcon = true
			break
		}
	}
	require.True(t, hasIcon, "livetable golden must contain at least one icon glyph (✓ ⚠)")
}
