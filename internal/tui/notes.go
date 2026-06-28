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
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/abysslink/abysslink/internal/ui"
)

// NoteLevel identifies the severity / intent of a Note callout box.
type NoteLevel int

// Note severity levels, ordered from least to most urgent.
const (
	NoteInfo     NoteLevel = iota // blue border; informational
	NoteWarn                      // yellow border; advisory
	NoteSecurity                  // cyan border; security callout
	NoteDanger                    // red border; destructive / irreversible
)

// noteLevelMeta holds the display attributes for a single NoteLevel.
type noteLevelMeta struct {
	// borderColor is the lipgloss border colour; empty string → default (used under NO_COLOR).
	borderColor lipgloss.Color
	// unicodeLabel is the icon+word label shown when colour is available.
	unicodeLabel string
	// asciiLabel is the plain-text fallback used when noColor() is true.
	asciiLabel string
}

var noteLevelTable = map[NoteLevel]noteLevelMeta{
	NoteInfo:     {borderColor: ui.ColorInfo, unicodeLabel: "● INFO", asciiLabel: "* INFO"},             // #5C7CFA
	NoteWarn:     {borderColor: ui.ColorWarn, unicodeLabel: "⚠ WARN", asciiLabel: "! WARN"},             // #FFD060
	NoteSecurity: {borderColor: ui.ColorSecurity, unicodeLabel: "● SECURITY", asciiLabel: "* SECURITY"}, // #00B4D8 (ui.ColorSecurity)
	NoteDanger:   {borderColor: ui.ColorFatal, unicodeLabel: "✕ DANGER", asciiLabel: "x DANGER"},        // #FF5F87
}

// noteLevelLabel returns the label string (icon + word) for level, choosing
// the ASCII fallback when noColor() is true.
func noteLevelLabel(level NoteLevel) string {
	meta, ok := noteLevelTable[level]
	if !ok {
		return "* NOTE"
	}
	if noColor() {
		return meta.asciiLabel
	}
	return meta.unicodeLabel
}

// noteBoxStyle returns a lipgloss border style appropriate for level.
// When noColor() is true, no colour is applied to the border.
func noteBoxStyle(level NoteLevel) lipgloss.Style {
	base := lipgloss.NewStyle().
		Border(boxBorder()).
		Padding(0, 2)

	// Responsive width: track the terminal (terminalWidth()-4), shrinking on
	// narrow (phone) terminals. The previous `if w < 54 { w = 54 }` floor
	// forced a 54-col box even on a 40-col terminal, overflowing the viewport
	// with wrapped/clipped borders (T-001). Removing the floor keeps the
	// wide-terminal width unchanged and lets it shrink below 54 when needed.
	w := max(1, terminalWidth()-4)
	base = base.Width(w)

	if noColor() {
		return base
	}

	meta, ok := noteLevelTable[level]
	if !ok {
		return base
	}
	return base.BorderForeground(meta.borderColor)
}

// Note renders a callout box as a string. It is a pure renderer: it performs
// no I/O and returns the formatted box to the caller (internal/cli prints it
// via the Printer). Every level is paired with an icon+word label so that
// the level is conveyed without relying on colour alone (§10 requirement).
//
// level — one of NoteInfo, NoteWarn, NoteSecurity, NoteDanger.
// title — short heading line inside the box.
// lines — body lines rendered below the title.
func Note(level NoteLevel, title string, lines []string) string {
	label := noteLevelLabel(level)
	var sb strings.Builder
	sb.WriteString(label)
	sb.WriteString(" — ")
	sb.WriteString(title)
	if len(lines) > 0 {
		sb.WriteString("\n")
		sb.WriteString(strings.Join(lines, "\n"))
	}
	return noteBoxStyle(level).Render(sb.String())
}
