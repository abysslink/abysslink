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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"
)

// TestAbyssTheme verifies that AbyssTheme() returns a non-nil *huh.Theme
// and that key FieldStyles fields carry the Abyss palette foreground colors.
//
// Assertions compare each theme field's rendered output against a style built
// from the palette constant, not against a hard-coded hex string. This way the
// test tracks the single source of truth: if the palette constant changes, the
// test changes with it (not the other way round).
func TestAbyssTheme(t *testing.T) {
	t.Parallel()

	theme := AbyssTheme()
	require.NotNil(t, theme, "AbyssTheme() must return a non-nil *huh.Theme")

	probe := "probe"

	// Focused.Title must carry ColorAccent (cyan) foreground.
	accentStyle := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true)
	require.Equal(t,
		accentStyle.Render(probe),
		theme.Focused.Title.Render(probe),
		"Focused.Title must use ColorAccent (cyan accent)")

	// Focused.SelectedOption must carry ColorSelection (violet) foreground.
	selectionStyle := lipgloss.NewStyle().Foreground(ColorSelection).Bold(true)
	require.Equal(t,
		selectionStyle.Render(probe),
		theme.Focused.SelectedOption.Render(probe),
		"Focused.SelectedOption must use ColorSelection (violet)")

	// Focused.Description must carry ColorMuted (steel) foreground.
	mutedStyle := lipgloss.NewStyle().Foreground(ColorMuted)
	require.Equal(t,
		mutedStyle.Render(probe),
		theme.Focused.Description.Render(probe),
		"Focused.Description must use ColorMuted (steel)")
}

// TestSingleSourceOfColor is a static-text guard that walks the repo's
// internal/ source tree (excluding internal/ui/ itself and _test.go files)
// and asserts that no brand-color hex literals or AdaptiveColor{ literals
// exist outside internal/ui. This proves the Abyss brand palette is defined
// in exactly one place (D-01, D-02, TUI-08).
//
// Semantic color literals (#04B575, #FFD060, etc.) are NOT in scope yet;
// Plan 03 migrates them and may tighten this guard at that point.
//
//nolint:gosec // G304: reads Go source files under a repo path resolved from runtime.Caller; not user input
func TestSingleSourceOfColor(t *testing.T) {
	t.Parallel()

	// Resolve the internal/ directory relative to this test file's own path so
	// the walk root is stable regardless of the working directory.
	//   thisFile → .../abysslink/internal/ui/theme_test.go
	//   uiDir   → .../abysslink/internal/ui/
	//   internalDir → .../abysslink/internal/
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller(0) must succeed")
	uiDir := filepath.Dir(thisFile)
	internalDir := filepath.Dir(uiDir)

	// Brand literals that must live ONLY in internal/ui.
	// (planner-discipline-allow tags below permit these strings to appear in this
	// _test.go file, which is excluded from its own walk.)
	// planner-discipline-allow: #22D3EE
	// planner-discipline-allow: #8B5CF6
	// planner-discipline-allow: #64748B
	// planner-discipline-allow: AdaptiveColor{
	needles := []string{
		"#22D3EE",
		"#8B5CF6",
		"#64748B",
		"AdaptiveColor{",
	}

	var violations []string

	walkErr := filepath.WalkDir(internalDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip the ui/ directory entirely — that is where these literals belong.
		if d.IsDir() && filepath.Base(path) == "ui" {
			return fs.SkipDir
		}

		// Only inspect non-test .go files.
		name := d.Name()
		if d.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec
		if readErr != nil {
			return readErr
		}

		content := string(data)
		relPath, _ := filepath.Rel(internalDir, path)

		for _, needle := range needles {
			if strings.Contains(content, needle) {
				violations = append(violations,
					"  "+needle+" found in internal/"+relPath)
			}
		}

		return nil
	})

	require.NoError(t, walkErr, "WalkDir over internal/ must not error")
	require.Empty(t, violations,
		"brand color literals must exist ONLY in internal/ui — found elsewhere:\n%s",
		strings.Join(violations, "\n"))
}
