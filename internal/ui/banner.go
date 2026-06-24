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

// Package ui provides the Abyss brand palette, huh theme, reusable lipgloss
// styles, and the two-tone slant FIGlet banner.
//
// IO boundary (D-07): internal/ui is a leaf package — it MUST NOT import
// internal/cli. TTY/color decisions flow IN as parameters; internal/ui never
// calls colorEnabled() or stdoutIsTTY() directly.
package ui

import (
	"github.com/charmbracelet/lipgloss"
	figure "github.com/common-nighthawk/go-figure"
)

// BannerOptions carries the capability decisions computed by the caller from
// colorEnabled() / stdoutIsTTY() in internal/cli/term.go.  internal/ui never
// inspects the environment itself (D-07).
//
// Width is the target inner width for the border box (pass boxWidth() from the
// caller, or 0 to use the package default of 80).
// Border is the border style (pass boxBorder() from the caller, or the zero
// value to use lipgloss.RoundedBorder()).
type BannerOptions struct {
	// Color enables the FIGlet two-tone (or monochrome) tier.
	// When false the banner collapses to the plain "ABYSSLINK" word —
	// no FIGlet art, no ANSI escape bytes (NO_COLOR / dumb / non-TTY tier).
	Color bool

	// Width is the inner width to pass to lipgloss Border.Width().
	// 0 means "let lipgloss decide" (natural content width).
	Width int

	// Border is the border style to apply.
	// The zero value uses lipgloss.RoundedBorder().
	Border lipgloss.Border
}

// defaultBannerWidth is the inner width used when BannerOptions.Width is 0.
// It matches the defaultBoxWidth constant in internal/cli/styles.go (54 cols).
const defaultBannerWidth = 54

// RenderBanner returns the two-tone slant FIGlet brand banner as a string.
// The return value is always safe to print via the caller's Printer — it is
// never written to stdout by this function.
//
// Degradation tiers (D-06):
//   - opts.Color == false   → plain "ABYSSLINK" word; no FIGlet; NO \x1b[ bytes.
//   - opts.Color == true    → slant FIGlet; ABYSS styled ColorAccent (cyan) and
//     LINK styled ColorSelection (violet), joined horizontally inside a border.
//     On a non-truecolor terminal lipgloss/termenv auto-downsample the colors
//     to 256/16-color; no extra branch is required (Pitfall 14 avoided).
//
// The function NEVER panics — the plain word tier is the final safety net for
// any unexpected environment (Pitfall 3 / T-34-10 availability threat).
func RenderBanner(opts BannerOptions) string {
	if !opts.Color {
		return renderPlain()
	}
	return renderFIGlet(opts)
}

// renderPlain returns the plain "ABYSSLINK" fallback: no FIGlet, no border,
// no ANSI escape bytes.  This is the NO_COLOR / TERM=dumb / non-TTY tier.
func renderPlain() string {
	return "ABYSSLINK"
}

// renderFIGlet renders the two-tone slant banner using go-figure's pure path.
//
// Safety contract: ONLY figure.NewFigure(...).String() and .Slicify() are safe.
// The "color" variants (NewColor*, Color*) call log.Fatalf on unsupported colors
// and write to stdout, bypassing Printer and crashing on brand hex values
// (RESEARCH Pitfall 2 / T-34-12). They are banned from this file by forbidigo.
func renderFIGlet(opts BannerOptions) string {
	// Build each half using the safe, pure go-figure path.
	// NewFigure returns a figure value (unexported type); .String() converts it
	// to a multi-line ASCII-art string with no ANSI codes and no terminal writes.
	abyssText := figure.NewFigure("ABYSS", "slant", true).String()
	linkText := figure.NewFigure("LINK", "slant", true).String()

	// Apply brand colors.  lipgloss/termenv auto-downsamples truecolor →
	// 256 → 16-color depending on the terminal profile; no explicit branch
	// is needed for the non-truecolor monochrome tier (D-06 tier 2).
	abyssStyled := lipgloss.NewStyle().Foreground(ColorAccent).Render(abyssText)
	linkStyled := lipgloss.NewStyle().Foreground(ColorSelection).Render(linkText)

	// Join the two halves side-by-side, aligning their tops.
	body := lipgloss.JoinHorizontal(lipgloss.Top, abyssStyled, linkStyled)

	// Apply the border.
	border := opts.Border
	if border == (lipgloss.Border{}) {
		border = lipgloss.RoundedBorder()
	}

	width := opts.Width
	if width <= 0 {
		width = defaultBannerWidth
	}

	boxStyle := lipgloss.NewStyle().
		Border(border).
		BorderForeground(ColorAccent).
		Padding(0, 1).
		Width(width)

	return boxStyle.Render(body)
}
