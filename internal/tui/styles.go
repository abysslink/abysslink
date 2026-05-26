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
	"os"

	"github.com/charmbracelet/lipgloss"
)

// noColor reports whether NO_COLOR is set (https://no-color.org).
func noColor() bool {
	_, set := os.LookupEnv("NO_COLOR")
	return set
}

// Styles groups the lipgloss styles used across TUI components.
type Styles struct {
	Success lipgloss.Style
	Warning lipgloss.Style
	Error   lipgloss.Style
	Muted   lipgloss.Style
	Bold    lipgloss.Style
}

// DefaultStyles returns the standard abysslink colour palette.
// All colours are suppressed when NO_COLOR is set.
func DefaultStyles() Styles {
	if noColor() {
		return Styles{
			Success: lipgloss.NewStyle(),
			Warning: lipgloss.NewStyle(),
			Error:   lipgloss.NewStyle(),
			Muted:   lipgloss.NewStyle(),
			Bold:    lipgloss.NewStyle().Bold(true),
		}
	}
	return Styles{
		Success: lipgloss.NewStyle().Foreground(lipgloss.Color("10")), // bright green
		Warning: lipgloss.NewStyle().Foreground(lipgloss.Color("11")), // bright yellow
		Error:   lipgloss.NewStyle().Foreground(lipgloss.Color("9")),  // bright red
		Muted:   lipgloss.NewStyle().Foreground(lipgloss.Color("8")),  // dark grey
		Bold:    lipgloss.NewStyle().Bold(true),
	}
}
