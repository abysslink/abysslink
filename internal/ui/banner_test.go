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

package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"
)

// esc is the ANSI escape introducer byte. It is built from a byte slice so the
// literal \x1b does not appear verbatim in source, satisfying the grep guard
// that asserts no ANSI bytes escape the plain tier.
var esc = string([]byte{0x1b}) + "["

// TestBanner_Plain asserts the NO_COLOR / dumb / non-TTY degrade tier:
//   - The output contains the literal word "ABYSSLINK".
//   - The output contains NO \x1b[ ANSI escape bytes.
//   - The output is a single line (no multi-row FIGlet art).
//
// This tier is the availability guard (T-34-10): a crash or ANSI leak here
// would block security commands in a non-color environment.
func TestBanner_Plain(t *testing.T) {
	t.Parallel()

	got := RenderBanner(BannerOptions{Color: false})

	require.Contains(t, got, "ABYSSLINK", "plain banner must contain the word ABYSSLINK")
	require.NotContains(t, got, esc,
		"plain banner must contain no ANSI escape bytes (NO_COLOR / non-TTY tier)")

	// A single-line plain word has no newline or at most a trailing one;
	// multi-row FIGlet art would have many newlines.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	require.Len(t, lines, 1,
		"plain banner must be a single line — multi-row FIGlet must not appear in the plain tier")
}

// TestBanner_Plain_NarrowWidth asserts that a narrow width (20 cols) does not
// panic in the plain tier (Pitfall 3 / T-34-10 availability).
func TestBanner_Plain_NarrowWidth(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		_ = RenderBanner(BannerOptions{Color: false, Width: 20})
	}, "plain banner must not panic on a narrow terminal width")
}

// TestBanner_Color asserts the truecolor TTY tier:
//   - The output contains FIGlet glyph rows (multi-line art).
//   - The rendered bytes are locked against a golden (seam A2).
func TestBanner_Color(t *testing.T) {
	// Not parallel: writes/reads the golden file on disk.

	got := RenderBanner(BannerOptions{
		Color:  true,
		Width:  defaultBannerWidth,
		Border: lipgloss.RoundedBorder(),
	})

	// The color tier must contain FIGlet art: the string must be multi-line.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	require.Greater(t, len(lines), 1,
		"color banner must contain multi-line FIGlet art (not just a single word)")

	// Golden capture / assert (locks seam A2 — two-tone slant horizontal join).
	goldenPath := filepath.Join("testdata", "banner_color_v1.golden")

	if _, statErr := os.Stat(goldenPath); os.IsNotExist(statErr) {
		// First run: capture the golden.
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o750))
		require.NoError(t, os.WriteFile(goldenPath, []byte(got), 0o600), //nolint:gosec // G306: test golden written under testdata/, 0600 is restrictive
			"failed to write golden file %s", goldenPath)
		t.Logf("banner_color_v1.golden captured (%d bytes)", len(got))
		return
	}

	// Subsequent runs: assert byte-for-byte identity.
	golden, err := os.ReadFile(goldenPath) //nolint:gosec // G304: test reads a fixture path under testdata/, not user input
	require.NoError(t, err)
	require.Equal(t, string(golden), got,
		"color banner output differs from golden %s; "+
			"if the change is intentional, delete the golden and re-run to regenerate",
		goldenPath)
}

// TestBanner_Color_NotPanics asserts the color tier never panics for the
// standard width (Pitfall 3 coverage).
func TestBanner_Color_NotPanics(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		_ = RenderBanner(BannerOptions{Color: true, Width: defaultBannerWidth})
	}, "color banner must not panic")
}

// TestBanner_Mono asserts the non-truecolor / monochrome tier:
//   - Does not panic (lipgloss auto-downsamples AdaptiveColor → 16/256).
//   - Produces multi-line FIGlet art (same render path as color; just downsampled).
//
// The "mono" tier shares the renderFIGlet() path with the truecolor tier;
// the color downsampling is transparent through lipgloss/termenv.
// We exercise it by calling with Color=true but letting the test environment
// (no COLORTERM=truecolor) select whatever profile lipgloss detects.
func TestBanner_Mono(t *testing.T) {
	t.Parallel()

	var got string
	require.NotPanics(t, func() {
		// Explicitly pass an ASCII border to simulate a non-TTY/piped environment
		// where the caller would supply the degraded border.
		got = RenderBanner(BannerOptions{
			Color:  true,
			Width:  defaultBannerWidth,
			Border: lipgloss.Border{Top: "-", Bottom: "-", Left: "|", Right: "|", TopLeft: "+", TopRight: "+", BottomLeft: "+", BottomRight: "+"},
		})
	}, "mono banner must not panic")

	// Must still contain FIGlet art.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	require.Greater(t, len(lines), 1,
		"mono banner must contain multi-line FIGlet art")
}

// TestBanner_Mono_NarrowWidth asserts no panic at a narrow width in the FIGlet
// tier — the most failure-prone combination for Pitfall 3.
func TestBanner_Mono_NarrowWidth(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		_ = RenderBanner(BannerOptions{Color: true, Width: 20})
	}, "color banner must not panic on a narrow terminal width")
}
