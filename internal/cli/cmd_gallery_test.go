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

// cmd_gallery_test.go — TUI-07 gallery coverage: the hidden `abysslink
// gallery` command renders EVERY themed element and its headless output is
// byte-stable. The gallery needs none of the styles-parity runner/probe seams
// — it shells nothing, dials nothing, and mutates nothing — so plain env
// isolation (NO_COLOR/CLICOLOR) is sufficient. Non-TTY handling is implicit:
// colorEnabled() and tui.noColor() probe the REAL os.Stdout, which is never a
// terminal under `go test`, so the ASCII/no-ANSI path is always taken.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runGalleryHeadless executes `abysslink gallery` with the given extra args
// through the root-command harness and returns the combined captured output.
func runGalleryHeadless(t *testing.T, extraArgs ...string) string {
	t.Helper()
	var buf bytes.Buffer
	cmd := buildRootCmd()
	cmd.SetArgs(append([]string{"gallery"}, extraArgs...))
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	require.NoError(t, cmd.Execute(), "gallery must exit 0 headless")
	return buf.String()
}

// TestGalleryByteStability asserts that under NO_COLOR + non-TTY the gallery
// (a) exits 0, (b) yields BYTE-IDENTICAL output across two runs, (c) labels
// every section, (d) contains zero ANSI escape bytes, (e) takes the ASCII
// note-label / box-border fallbacks, (f) shows only the obviously-fake
// placeholder secret, and (g) creates no files. The output is additionally
// pinned as a golden (testdata/gallery_v1.golden) via the shared
// captureOrAssertGolden helper so any accidental byte change on the headless
// surface fails a test instead of shipping silently. Gallery output is
// OS-independent (no shell-outs, no host probes), so the golden is not
// darwin-scoped like the status/doctor parity goldens.
func TestGalleryByteStability(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR", "0")
	// Redirect every well-known write root into the inspected tmpDir so an
	// accidental write by the gallery would land where assertion (g) looks —
	// without this the ReadDir check would inspect a directory the command
	// never sees and could never fail.
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpDir, "xdg-config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmpDir, "xdg-state"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmpDir, "xdg-cache"))

	first := runGalleryHeadless(t)
	second := runGalleryHeadless(t)

	require.NotEmpty(t, first, "gallery must produce output")
	require.Equal(t, first, second, "gallery output must be byte-identical across runs")

	// (c) Every labelled section header must be present.
	for _, label := range []string{
		"Palette",
		"Status & semantic styles",
		"Boxes & rules",
		"TUI components",
		"Progress & module rows",
		"Markdown",
	} {
		assert.Contains(t, first, label, "gallery must render the %q section", label)
	}

	// (d) NO_COLOR: zero ANSI escape sequences anywhere in the output.
	assert.NotContains(t, first, "\x1b[", "gallery output must contain no ANSI escapes under NO_COLOR")

	// (e) ASCII fallbacks: the four note-level labels and the +/-/| box set.
	assert.Contains(t, first, "* INFO", "NoteInfo must take its ASCII label under NO_COLOR")
	assert.Contains(t, first, "! WARN", "NoteWarn must take its ASCII label under NO_COLOR")
	assert.Contains(t, first, "* SECURITY", "NoteSecurity must take its ASCII label under NO_COLOR")
	assert.Contains(t, first, "x DANGER", "NoteDanger must take its ASCII label under NO_COLOR")
	assert.Contains(t, first, "+", "boxes must use the ASCII +/-/| border fallback on non-TTY")

	// (f) The SecretBox demo must be visibly placeholder-only.
	assert.Contains(t, first, "NOT-A-REAL-SECRET", "SecretBox demo must show an obviously-fake placeholder")
	assert.Contains(t, first, "(SAMPLE)", "SecretBox demo title must be marked as a sample")

	// Element spot-checks: journey dots, live-table rows, scan/apply rows,
	// plain progress fallbacks, converged summary, canonical footer hint.
	assert.Contains(t, first, "Abysslink Setup — Stage 3 of 5", "JourneyHeader must render")
	assert.Contains(t, first, "version below floor", "warn live-table row must render")
	assert.Contains(t, first, "not installed", "error live-table row must render")
	assert.Contains(t, first, "up to date", "scanRowStr up-to-date row must render")
	assert.Contains(t, first, "1 change: install ntfy", "scanRowStr planned-change row must render")
	assert.Contains(t, first, "[2/3]", "applyRowStr counter must render")
	assert.Contains(t, first, "[3/7]", "PlainBar must render")
	assert.Contains(t, first, "checking daemon...", "PlainStatus must render")
	assert.Contains(t, first, "System converged", "printFinalSummary converged line must render")
	assert.Contains(t, first, "ctrl+c quit", "canonical footer hint must render")

	// (g) No file mutations.
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "gallery must not create any files")

	// Golden pin for the headless byte-stable surface.
	captureOrAssertGolden(t, filepath.Join("testdata", "gallery_v1.golden"), first)
}

// TestGalleryJSONNoOp asserts the --json path: the gallery is a human-only
// theme preview, so under --json it degrades to a no-op — exit 0, no output,
// no crash — instead of pushing boxed prose into the newline-delimited JSON
// stream as {"msg":…} records (D-15 / §9).
func TestGalleryJSONNoOp(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR", "0")

	out := runGalleryHeadless(t, "--json")
	assert.Empty(t, strings.TrimSpace(out), "gallery --json must emit no output (human-only preview)")
}
