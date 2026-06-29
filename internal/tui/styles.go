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
	"golang.org/x/term"
)

// noColor reports whether colour and the unicode-glyph styling should be
// suppressed. It mirrors the inverse of cli.colorEnabled() so the internal/tui
// renderers (Note, SecretBox, JourneyHeader) take their ASCII-glyph + ASCII-box
// fallback on exactly the same surfaces the rest of the CLI drops colour on:
//   - NO_COLOR is set (https://no-color.org), OR
//   - CLICOLOR=0 (https://bixense.com/clicolors), OR
//   - stdout is not a terminal (pipe, file, CI, redirected log, --json).
//
// Previously it checked NO_COLOR alone, so a piped tui box still emitted unicode
// glyphs (●/⚠/✕) and rounded borders while the surrounding CLI degraded to the
// clean ASCII fallback — two different "is colour on?" truths in one binary
// (T-018). internal/tui stays a leaf package: it computes this itself rather
// than importing internal/cli.
func noColor() bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return true
	}
	if os.Getenv("CLICOLOR") == "0" {
		return true
	}
	return !term.IsTerminal(int(os.Stdout.Fd()))
}

// boxBorder returns the border set used by the tui callout boxes (Note,
// SecretBox, JourneyHeader): lipgloss's rounded glyphs on a colour TTY, and an
// ASCII +/-/| set when noColor() is true. This matches cli.boxBorder() so a
// piped/redirected capture renders a clean ASCII box instead of a unicode one
// that mojibakes in plain pagers (T-018).
func boxBorder() lipgloss.Border {
	if noColor() {
		return lipgloss.Border{
			Top: "-", Bottom: "-", Left: "|", Right: "|",
			TopLeft: "+", TopRight: "+", BottomLeft: "+", BottomRight: "+",
		}
	}
	return lipgloss.RoundedBorder()
}

// terminalWidth returns the current terminal width, defaulting to 80 if
// the width cannot be determined (e.g. in tests or non-TTY environments).
func terminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// brandBoxWidth caps the inner width of every tui callout box (Note, SecretBox)
// at 54 columns, matching cli.defaultBoxWidth and the `up`/`enroll` header box.
// One width for every framed box means they line up on a wide terminal instead
// of some hugging 54 cols (header, secret) while notes sprawl the full viewport
// — the "mix of old and new" the notes used to create.
const brandBoxWidth = 54

// boxWidth returns the responsive inner width for tui callout boxes: capped at
// brandBoxWidth on wide terminals and shrinking on narrow (phone) terminals so
// the box never overflows the viewport (T-001 — no hard floor).
func boxWidth() int {
	return max(1, min(brandBoxWidth, terminalWidth()-4))
}
