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

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/abysslink/abysslink/internal/ui"
)

// JourneyHeader renders the "Abysslink Setup ─ Stage N of M" progress strip as
// a string. It is a pure renderer — no I/O; the caller in internal/cli prints
// it via the Printer.
//
// stage is the current 1-based stage number.
// total is the total number of stages.
// labels are the short names for each stage; if len(labels) < total only the
// provided names are shown; extra stages are shown as their number.
//
// The strip shows:
//   - "Abysslink Setup ─ Stage N of M"
//   - A dot-row: ✓ for completed stages, ● for the current stage, · for remaining
//   - A bracketed numbered label list e.g. [1] Account  [2] Prerequisites  …
//
// When noColor() is true, plain ASCII glyphs and no ANSI codes are used.
func JourneyHeader(stage, total int, labels []string) string {
	title := buildJourneyTitle(stage, total)
	dots := buildJourneyDots(stage, total)
	labelRow := buildJourneyLabels(stage, total, labels)

	body := strings.Join([]string{title, dots, labelRow}, "\n")

	if noColor() {
		return body
	}
	// Wrap in a subtle blue box matching the project's header palette.
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ui.ColorInfo).
		Padding(0, 2)
	w := terminalWidth() - 4
	if w < 54 {
		w = 54
	}
	boxStyle = boxStyle.Width(w)
	return boxStyle.Render(body)
}

// buildJourneyTitle returns the heading line "Abysslink Setup — Stage N of M".
func buildJourneyTitle(stage, total int) string {
	return fmt.Sprintf("Abysslink Setup — Stage %d of %d", stage, total)
}

// buildJourneyDots returns the progress indicator row.
// Completed stages (< stage): ✓ (checkmark), or "v" under noColor.
// Current stage (== stage): ● or "o".
// Remaining stages (> stage): · or ".".
func buildJourneyDots(stage, total int) string {
	if noColor() {
		return buildJourneyDotsASCII(stage, total)
	}
	return buildJourneyDotsUnicode(stage, total)
}

func buildJourneyDotsUnicode(stage, total int) string {
	stylesDone := lipgloss.NewStyle().Foreground(ui.ColorSuccess) // green (#04B575)
	stylesCurrent := lipgloss.NewStyle().Foreground(ui.ColorInfo).Bold(true)
	stylesRemain := lipgloss.NewStyle().Foreground(ui.ColorMutedSemantic)

	var parts []string
	for i := 1; i <= total; i++ {
		switch {
		case i < stage:
			parts = append(parts, stylesDone.Render("✓"))
		case i == stage:
			parts = append(parts, stylesCurrent.Render("●"))
		default:
			parts = append(parts, stylesRemain.Render("·"))
		}
	}
	return strings.Join(parts, " ")
}

func buildJourneyDotsASCII(stage, total int) string {
	var parts []string
	for i := 1; i <= total; i++ {
		switch {
		case i < stage:
			parts = append(parts, "v")
		case i == stage:
			parts = append(parts, "o")
		default:
			parts = append(parts, ".")
		}
	}
	return strings.Join(parts, " ")
}

// buildJourneyLabels returns the bracketed numbered label list.
func buildJourneyLabels(stage, total int, labels []string) string {
	var parts []string
	for i := 1; i <= total; i++ {
		label := fmt.Sprintf("%d", i)
		if i <= len(labels) {
			label = labels[i-1]
		}
		if noColor() {
			if i == stage {
				parts = append(parts, fmt.Sprintf("[%d] %s *", i, label))
			} else {
				parts = append(parts, fmt.Sprintf("[%d] %s", i, label))
			}
		} else {
			if i == stage {
				current := lipgloss.NewStyle().Bold(true).Foreground(ui.ColorInfo)
				parts = append(parts, current.Render(fmt.Sprintf("[%d] %s", i, label)))
			} else {
				parts = append(parts, fmt.Sprintf("[%d] %s", i, label))
			}
		}
	}
	return strings.Join(parts, "  ")
}
