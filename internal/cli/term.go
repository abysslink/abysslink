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

// Package cli provides terminal capability detection helpers for the Abysslink CLI.
// Functions in this file detect TTY, color, animation, and interactivity from
// file descriptors and environment variables. They never print; printing is the
// Printer's responsibility.
package cli

import (
	"fmt"
	"os"

	cterm "github.com/charmbracelet/x/term"
)

// stdoutIsTTY reports whether os.Stdout is attached to a terminal.
func stdoutIsTTY() bool {
	return cterm.IsTerminal(os.Stdout.Fd())
}

// stdinIsTTY reports whether os.Stdin is attached to a terminal.
func stdinIsTTY() bool {
	return cterm.IsTerminal(os.Stdin.Fd())
}

// colorEnabled reports whether color output should be produced.
//
// Returns false when any of the following hold (in order):
//   - The NO_COLOR environment variable is set to any value (https://no-color.org).
//   - CLICOLOR is set to "0" (https://bixense.com/clicolors).
//   - os.Stdout is not a terminal (pipe, file, CI, --json mode, etc.).
func colorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("CLICOLOR") == "0" {
		return false
	}
	return stdoutIsTTY()
}

// animationEnabled reports whether animated output (spinners, progress bars) should
// be produced. Animation is disabled when:
//   - jsonOut is true (structured output mode)
//   - stdout is not a TTY
//   - color is not enabled (which implies non-TTY or NO_COLOR/CLICOLOR=0)
func animationEnabled(jsonOut bool) bool {
	if jsonOut {
		return false
	}
	return colorEnabled()
}

// interactive reports whether the current session can prompt the user for input.
// It returns false when:
//   - yes is true (--yes flag auto-confirms all prompts)
//   - jsonOut is true (--json flag implies machine-readable non-interactive output)
//   - os.Stdin is not a terminal (pipe, CI, heredoc, etc.)
//
// Any code path that would otherwise block on a prompt must call this predicate
// first and return errMissingInput if it returns false.
func interactive(yes, jsonOut bool) bool {
	if yes || jsonOut {
		return false
	}
	return stdinIsTTY()
}

// errMissingInput returns a clear, actionable error for non-interactive contexts
// where required user input is absent. The message names the flag that supplies
// the missing input so the user knows exactly what to pass.
//
// Example: errMissingInput("apply") → "non-interactive: required input missing;
// pass --apply to supply it"
func errMissingInput(flag string) error {
	return fmt.Errorf("non-interactive: required input missing; pass --%s to supply it", flag)
}
