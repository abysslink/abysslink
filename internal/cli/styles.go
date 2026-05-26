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

import "github.com/charmbracelet/lipgloss"

// Palette.
const (
	colorGreen  = lipgloss.Color("#04B575")
	colorYellow = lipgloss.Color("#FFD060")
	colorRed    = lipgloss.Color("#FF5F87")
	colorBlue   = lipgloss.Color("#5C7CFA")
	colorMuted  = lipgloss.Color("#6B7280")
	colorWhite  = lipgloss.Color("#F8F8F2")
	colorDim    = lipgloss.Color("#4B5563")
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

// Box styles.
var (
	styleHeaderBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBlue).
			Padding(0, 2).
			Width(54)

	styleNextStepBox = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorYellow).
				Padding(1, 2).
				Width(54)

	styleStatusBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBlue).
			Padding(0, 2).
			Width(54)
)

// Icons.
const (
	iconOK    = "●"
	iconWarn  = "⚠"
	iconFatal = "✕"
	iconArrow = "→"
	iconDone  = "✓"
	iconSpin  = "◌"
)

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
