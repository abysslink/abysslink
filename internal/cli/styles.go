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
	"os"

	"github.com/charmbracelet/lipgloss"
	cterm "github.com/charmbracelet/x/term"

	"github.com/abysslink/abysslink/internal/ui"
)

// Palette — re-sourced from internal/ui (single source of color, D-03).
// The hex values are IDENTICAL to their former local definitions; only the
// definition site has moved. Rendered bytes on non-TTY/--json/NO_COLOR
// surfaces are unchanged (D-04 byte-stability gate).
var (
	colorGreen  = ui.ColorSuccess       // #04B575
	colorYellow = ui.ColorWarn          // #FFD060
	colorRed    = ui.ColorFatal         // #FF5F87
	colorBlue   = ui.ColorInfo          // #5C7CFA
	colorMuted  = ui.ColorMutedSemantic // #6B7280 (NOT brand steel — D-04)
	colorDim    = ui.ColorDim           // #4B5563
)

// Text styles.
var (
	styleSuccess = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	styleWarn    = lipgloss.NewStyle().Foreground(colorYellow).Bold(true)
	styleFatal   = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
	styleInfo    = lipgloss.NewStyle().Foreground(colorBlue)
	styleMuted   = lipgloss.NewStyle().Foreground(colorMuted)
	styleBold    = lipgloss.NewStyle().Bold(true)
	styleCode    = lipgloss.NewStyle().Foreground(colorBlue).Background(colorDim).Padding(0, 1)
)

// defaultBoxWidth is the box width used on wide terminals and when the
// terminal width cannot be determined (non-TTY output, tests, pipes).
const defaultBoxWidth = 54

// boxWidth returns the width for bordered boxes: min(54, termwidth-2). The
// marketed environment is a phone SSH client that is frequently narrower than
// 54 columns; a fixed width there makes lipgloss hard-wrap the borders into
// garbage (UX review #10/#6).
func boxWidth() int {
	if w, _, err := cterm.GetSize(os.Stdout.Fd()); err == nil && w > 2 && w-2 < defaultBoxWidth {
		return w - 2
	}
	return defaultBoxWidth
}

// boxBorder returns the border set for boxes: rounded glyphs on a TTY, an
// ASCII +/-/| fallback when output is piped or redirected so logs and CI
// captures stay readable (UX review #10).
func boxBorder() lipgloss.Border {
	if stdoutIsTTY() {
		return lipgloss.RoundedBorder()
	}
	return lipgloss.Border{
		Top: "-", Bottom: "-", Left: "|", Right: "|",
		TopLeft: "+", TopRight: "+", BottomLeft: "+", BottomRight: "+",
	}
}

// Box styles.
var (
	styleHeaderBox = lipgloss.NewStyle().
			Border(boxBorder()).
			BorderForeground(colorBlue).
			Padding(0, 2).
			Width(boxWidth())

	styleNextStepBox = lipgloss.NewStyle().
				Border(boxBorder()).
				BorderForeground(colorYellow).
				Padding(1, 2).
				Width(boxWidth())

	styleStatusBox = lipgloss.NewStyle().
			Border(boxBorder()).
			BorderForeground(colorBlue).
			Padding(0, 2).
			Width(boxWidth())

	// styleFooterHint renders the persistent footer hint text in muted steel:
	// "↑/↓ navigate  •  space toggle  •  enter select  •  esc back  •  ctrl+c quit"
	// (UI-SPEC §Copywriting Contract "Persistent footer hint"). Consumed by Plan 35-03.
	styleFooterHint = lipgloss.NewStyle().Foreground(colorMuted) //nolint:unused // wired by plan 35-03 (TUI-06)
)

// Icons.
const (
	iconOK    = "●"
	iconWarn  = "⚠"
	iconFatal = "✕"
	iconArrow = "→"
	iconDone  = "✓"
	iconSpin  = "◌"
	// iconNeutral marks a deliberately-disabled (not failing) feature in the
	// status panel — never red, the user chose this state (UX review #4/U4).
	iconNeutral = "○"
)

// iconNeutralStr returns a muted neutral icon for deliberately-disabled rows.
func iconNeutralStr() string { return styleMuted.Render(iconNeutral) }

// iconOKStr returns a green OK icon.
func iconOKStr() string { return styleSuccess.Render(iconOK) }

// iconWarnStr returns a yellow warning icon.
func iconWarnStr() string { return styleWarn.Render(iconWarn) }

// iconFatalStr returns a red fatal icon.
func iconFatalStr() string { return styleFatal.Render(iconFatal) }

// iconDoneStr returns a green done icon.
func iconDoneStr() string { return styleSuccess.Render(iconDone) }

// iconArrowStr returns a blue arrow icon.
func iconArrowStr() string { return styleInfo.Render(iconArrow) }

// iconSpinStr returns a muted spinner icon.
func iconSpinStr() string { return styleMuted.Render(iconSpin) }
