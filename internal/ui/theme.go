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
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Brand palette (D-01): three AdaptiveColor tones sampled from the abyss-vortex
// logo (electric-cyan rain, violet vortex, indigo mid-tone). Dark hexes are
// LOCKED to the logo; light-mode counterparts are chosen for WCAG-AA legibility
// on light surfaces.
// ---------------------------------------------------------------------------

// ColorAccent is the Abyss cyan accent used for nav, titles, banner "ABYSS",
// huh SelectSelector, TextInput cursor/prompt, and SelectedPrefix. Sampled from
// the electric-cyan matrix rain / "ABYSS" wordmark of the abyss-vortex logo;
// #2CE0F5 measures 10.39:1 on #1e1e1e. Light side #0E7490 = 5.36:1 on white.
var ColorAccent = lipgloss.AdaptiveColor{Dark: "#2CE0F5", Light: "#0E7490"}

// ColorSelection is the Abyss violet used for huh SelectedOption, FocusedButton,
// MultiSelectSelector, and banner "LINK". Sampled from the logo's violet vortex
// / "LINK" gradient (the punchy #A06CF0–#E060F8 swirl), replacing the washed-out
// pastel #A78BFA. #B57BFF measures 5.75:1 on #1e1e1e and the light side #7C3AED
// 5.70:1 on white — both clear WCAG AA, so the selected option stays the
// HIGHEST-contrast row, not the lowest (T-021).
var ColorSelection = lipgloss.AdaptiveColor{Dark: "#B57BFF", Light: "#7C3AED"}

// ColorMuted is the Abyss steel tone used for secondary/muted text,
// huh Description, and non-truecolor banner monochrome.
var ColorMuted = lipgloss.AdaptiveColor{Dark: "#64748B", Light: "#475569"}

// ---------------------------------------------------------------------------
// Semantic palette (D-04 / T-002): AdaptiveColor so status/health output stays
// legible on a LIGHT terminal (default macOS Terminal/iTerm, many phone SSH
// clients). The DARK side is byte-identical to the former flat hexes, so output
// on a dark terminal — and on every --json / non-TTY / NO_COLOR surface, where
// lipgloss strips ANSI regardless — is unchanged; only the light-terminal path
// gains AA-legible counterparts (the flat hexes measured 1.45:1–3.67:1 on white,
// all failing WCAG AA). internal/cli/styles.go re-sources these.
// ---------------------------------------------------------------------------

// ColorSuccess is the semantic green for OK icons and positive status output.
var ColorSuccess = lipgloss.AdaptiveColor{Dark: "#04B575", Light: "#02764C"}

// ColorWarn is the semantic yellow for WARN icons and advisory output.
var ColorWarn = lipgloss.AdaptiveColor{Dark: "#FFD060", Light: "#946200"}

// ColorFatal is the semantic red for FATAL icons and error output.
var ColorFatal = lipgloss.AdaptiveColor{Dark: "#FF5F87", Light: "#B3003A"}

// ColorInfo is the semantic blue for arrows and info markers. Aligned to the
// logo's indigo blue-violet mid-tone (the #5060F8 band between the cyan rain and
// the violet vortex); #6E80F7 = 4.84:1 on #1e1e1e, light side #2540C0 8.16:1.
var ColorInfo = lipgloss.AdaptiveColor{Dark: "#6E80F7", Light: "#2540C0"}

// ColorSecurity is the semantic blue for SECURITY note borders. Centralized
// here (T-022) so the single-source-of-color contract holds; was a hardcoded
// literal in internal/tui/notes.go. AdaptiveColor so the security frame stays
// legible on a light terminal (the flat #00B4D8 measured 2.46:1 on white).
var ColorSecurity = lipgloss.AdaptiveColor{Dark: "#00B4D8", Light: "#006883"}

// ColorFg is the primary foreground text color.
const ColorFg = lipgloss.Color("#F8F8F2")

// ColorDim is used for code block backgrounds and secondary surfaces.
const ColorDim = lipgloss.Color("#4B5563")

// ColorMutedSemantic is the muted tone for secondary text (status labels,
// doctor check names, footer hints, remaining journey dots). The dark side was
// brightened from #6B7280 (3.45:1 on #1e1e1e — below AA for body text) to
// #8B95A5 (~5:1) so the large share of UI chrome rendered in this tone is no
// longer washed out (T-019); the light side (#475569) already clears AA on
// white. Exported distinct from the brand-steel ColorMuted — do NOT conflate.
// Dark-terminal callers that re-source the old flat value see a brighter grey;
// every NO_COLOR / non-TTY / --json surface (where ANSI is stripped) is
// byte-unchanged.
var ColorMutedSemantic = lipgloss.AdaptiveColor{Dark: "#8B95A5", Light: "#475569"}

// ---------------------------------------------------------------------------
// Reusable styles (exported for consumers in internal/cli and internal/tui).
// Each style is a pure constructor value — no I/O, no stdout writes.
// ---------------------------------------------------------------------------

// StyleTitle renders section headings in bold cyan accent.
var StyleTitle = lipgloss.NewStyle().Bold(true).Foreground(ColorAccent)

// StyleMuted renders footer/hint text in the steel muted tone.
var StyleMuted = lipgloss.NewStyle().Foreground(ColorMuted)

// StyleSuccess renders positive output in bold semantic green.
var StyleSuccess = lipgloss.NewStyle().Bold(true).Foreground(ColorSuccess)

// StyleWarn renders advisory output in bold semantic yellow.
var StyleWarn = lipgloss.NewStyle().Bold(true).Foreground(ColorWarn)

// StyleFatal renders error output in bold semantic red.
var StyleFatal = lipgloss.NewStyle().Bold(true).Foreground(ColorFatal)

// StyleInfo renders info markers in semantic blue.
var StyleInfo = lipgloss.NewStyle().Foreground(ColorInfo)

// StyleCode renders inline code as near-white foreground on a dim background.
// The previous ColorInfo blue (#6E80F7) on ColorDim grey (#4B5563) measured
// ~2.06:1 — failing WCAG AA regardless of terminal theme, on the exact command
// snippets the user is meant to copy/run. ColorFg (#F8F8F2) on #4B5563 is
// ~7.5:1 (T-003).
var StyleCode = lipgloss.NewStyle().Foreground(ColorFg).Background(ColorDim).Padding(0, 1)

// StyleBold renders text in bold with no color modification.
var StyleBold = lipgloss.NewStyle().Bold(true)

// ---------------------------------------------------------------------------
// AbyssTheme builds the branded huh.Theme from the Abyss palette.
// Field names are verified against pinned huh v1.0.0 via `go doc`.
// Never call go get -u or bump huh/lipgloss.
// ---------------------------------------------------------------------------

// AbyssTheme returns a *huh.Theme with the Abyss two-tone palette applied to
// all FieldStyles. It starts from huh.ThemeBase() and overrides Focused and
// Blurred field styles with the palette.
func AbyssTheme() *huh.Theme {
	t := huh.ThemeBase()
	setFocusedStyles(t)
	setBlurredStyles(t)
	return t
}

// setFocusedStyles applies the Abyss palette to the Focused (active) FieldStyles.
func setFocusedStyles(t *huh.Theme) {
	f := &t.Focused

	// Titles and descriptions.
	f.Title = f.Title.Foreground(ColorAccent).Bold(true)
	f.Description = f.Description.Foreground(ColorMuted)

	// Error feedback.
	f.ErrorIndicator = f.ErrorIndicator.Foreground(ColorFatal).Bold(true)
	f.ErrorMessage = f.ErrorMessage.Foreground(ColorFatal)

	// Select / multi-select.
	f.SelectSelector = f.SelectSelector.Foreground(ColorAccent)
	f.MultiSelectSelector = f.MultiSelectSelector.Foreground(ColorAccent)
	f.SelectedOption = f.SelectedOption.Foreground(ColorSelection).Bold(true)
	f.SelectedPrefix = f.SelectedPrefix.Foreground(ColorAccent)
	f.UnselectedOption = f.UnselectedOption.Foreground(ColorFg)
	f.UnselectedPrefix = f.UnselectedPrefix.Foreground(ColorMuted)

	// Text input.
	f.TextInput.Cursor = f.TextInput.Cursor.Foreground(ColorAccent)
	f.TextInput.Prompt = f.TextInput.Prompt.Foreground(ColorAccent)
	f.TextInput.Text = f.TextInput.Text.Foreground(ColorFg)
	f.TextInput.Placeholder = f.TextInput.Placeholder.Foreground(ColorMuted)

	// Buttons.
	f.FocusedButton = f.FocusedButton.Foreground(ColorSelection).Bold(true)
	f.BlurredButton = f.BlurredButton.Foreground(ColorMuted)

	// Note title.
	f.NoteTitle = f.NoteTitle.Bold(true)

	// Bordered padded container around the ACTIVE group (TUI-06). A full rounded
	// box in the brand blue with vertical breathing room — replaces huh's default
	// left-bar so each wizard step is visibly framed. Mirrors the intent of the
	// internal/cli styleFlowContainer (boxBorder + colorBlue + Padding(1,2)); the
	// theme is the real source of truth since a lipgloss wrapper cannot frame a
	// live huh form.
	f.Base = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorInfo).
		Padding(1, 2)
}

// setBlurredStyles applies the Abyss palette to the Blurred (inactive) FieldStyles.
func setBlurredStyles(t *huh.Theme) {
	b := &t.Blurred

	// Mirror title and description from focused with muted treatment.
	b.Title = b.Title.Foreground(ColorMuted)
	b.Description = b.Description.Foreground(ColorMuted)

	// Error feedback (keep semantic red even when blurred).
	b.ErrorIndicator = b.ErrorIndicator.Foreground(ColorFatal)
	b.ErrorMessage = b.ErrorMessage.Foreground(ColorFatal)

	// Select / multi-select.
	b.SelectSelector = b.SelectSelector.Foreground(ColorMuted)
	b.MultiSelectSelector = b.MultiSelectSelector.Foreground(ColorMuted)
	b.SelectedOption = b.SelectedOption.Foreground(ColorSelection)
	b.SelectedPrefix = b.SelectedPrefix.Foreground(ColorMuted)
	b.UnselectedOption = b.UnselectedOption.Foreground(ColorFg)
	b.UnselectedPrefix = b.UnselectedPrefix.Foreground(ColorMuted)

	// Text input.
	b.TextInput.Cursor = b.TextInput.Cursor.Foreground(ColorMuted)
	b.TextInput.Prompt = b.TextInput.Prompt.Foreground(ColorMuted)
	b.TextInput.Text = b.TextInput.Text.Foreground(ColorFg)
	b.TextInput.Placeholder = b.TextInput.Placeholder.Foreground(ColorMuted)

	// Buttons.
	b.FocusedButton = b.FocusedButton.Foreground(ColorMuted)
	b.BlurredButton = b.BlurredButton.Foreground(ColorMuted)

	// Bordered container for INACTIVE groups (TUI-06): same rounded box but in
	// muted steel so blurred steps recede behind the focused one.
	b.Base = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorMuted).
		Padding(1, 2)
}
