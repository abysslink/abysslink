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

// SecretBox renders a once-only red-bordered box containing the title, the
// numbered secret lines, and a mandatory warning that the secrets will not be
// shown again.
//
// IMPORTANT: This is a PURE function. It performs NO logging, NO file I/O, and
// NO slog calls. The returned string must NEVER be passed to slog or
// internal/audit. The caller (internal/cli) is solely responsible for printing
// this string exactly once via the Printer, and must not log or audit the
// output.
//
// noColor() is honoured: the box structure and the "will NOT be shown again"
// line are always rendered; only ANSI colour codes are suppressed.
func SecretBox(title string, secrets []string) string {
	const warningLine = "This will NOT be shown again — copy to your password manager AND print one on paper."

	var sb strings.Builder
	sb.WriteString(title)
	sb.WriteString("\n")
	for i, s := range secrets {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, s))
	}
	sb.WriteString("\n")
	sb.WriteString(warningLine)

	body := sb.String()

	if noColor() {
		// Still render the box structure without colour.
		return lipgloss.NewStyle().
			Border(boxBorder()).
			Padding(0, 2).
			Width(secretBoxWidth()).
			Render(body)
	}

	return lipgloss.NewStyle().
		Border(boxBorder()).
		BorderForeground(ui.ColorFatal). // #FF5F87 — re-sourced from internal/ui (D-03)
		Foreground(ui.ColorFatal).
		Bold(true).
		Padding(0, 2).
		Width(secretBoxWidth()).
		Render(body)
}

// secretBoxWidth returns the responsive width for the secret box. It caps at 54
// columns and shrinks on narrow (phone) terminals — it never FLOORS at 54. The
// previous `if w < 54 { return 54 }` floor forced a 54-col box on a sub-54-col
// terminal, overflowing the viewport and garbling the once-only Tailnet Lock
// disablement secret on the very device the product targets (T-001).
func secretBoxWidth() int {
	return max(1, min(54, terminalWidth()-4))
}
