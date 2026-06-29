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
// styles, and the two-tone stacked FIGlet banner.
//
// IO boundary (D-07): internal/ui is a leaf package — it MUST NOT import
// internal/cli. TTY/color decisions flow IN as parameters; internal/ui never
// calls colorEnabled() or stdoutIsTTY() directly.
package ui

import (
	"strings"

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

// RenderBanner returns the two-tone stacked FIGlet brand banner as a string.
// The return value is always safe to print via the caller's Printer — it is
// never written to stdout by this function.
//
// Degradation tiers (D-06):
//   - opts.Color == false   → plain "ABYSSLINK" word; no FIGlet; NO \x1b[ bytes.
//   - opts.Color == true    → stacked FIGlet; ABYSS styled ColorAccent (cyan)
//     over LINK styled ColorSelection (violet), centered inside a border.
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

// renderFIGlet renders the two-tone STACKED banner using go-figure's pure path:
// "ABYSS" (ColorAccent cyan) on top of "LINK" (ColorSelection violet), centered.
//
// Why stacked, not the old side-by-side slant: a single-line "ABYSSLINK" FIGlet
// is ~64+ columns wide and the brand box is capped at 54 (phone-friendly), so the
// art wrapped into unreadable fragments. Stacking the two halves keeps each word
// well under the cap (standard "ABYSS" ≈ 42 cols, small ≈ 34) while staying large
// and legible. The font is chosen to FIT the available width so it never wraps;
// below the smallest FIGlet that fits, a plain two-tone wordmark is used.
//
// Safety contract: ONLY figure.NewFigure(...).String() and .Slicify() are safe.
// The "color" variants (NewColor*, Color*) call log.Fatalf on unsupported colors
// and write to stdout, bypassing Printer and crashing on brand hex values
// (RESEARCH Pitfall 2 / T-34-12). They are banned from this file by forbidigo.
func renderFIGlet(opts BannerOptions) string {
	border := opts.Border
	if border == (lipgloss.Border{}) {
		border = lipgloss.RoundedBorder()
	}

	width := opts.Width
	if width <= 0 {
		width = defaultBannerWidth
	}

	// Available content columns after the box's horizontal padding (0,1).
	// Size the FIGlet to the WIDER half ("ABYSS") so neither word wraps.
	inner := width - 2
	font := ""
	switch {
	case inner >= 42:
		font = "standard" // ABYSS ≈ 42 cols — crisp and large
	case inner >= 34:
		font = "small" // ABYSS ≈ 34 cols — compact fallback
	}

	body := bannerBody(font)

	boxStyle := lipgloss.NewStyle().
		Border(border).
		BorderForeground(ColorAccent).
		Padding(0, 1).
		Width(width).
		Align(lipgloss.Center)

	return boxStyle.Render(body)
}

// bannerBody builds the centered two-tone stacked wordmark. An empty font means
// the box is too narrow for any readable FIGlet, so a plain bold two-tone
// wordmark is stacked instead — still no wrapping, still on-brand.
func bannerBody(font string) string {
	if font == "" {
		abyss := lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Render("ABYSS")
		link := lipgloss.NewStyle().Foreground(ColorSelection).Bold(true).Render("LINK")
		return lipgloss.JoinVertical(lipgloss.Center, abyss, link)
	}
	// NewFigure(...).String() yields multi-line ASCII art with no ANSI codes and
	// no terminal writes; TrimRight drops the trailing blank line go-figure emits
	// so JoinVertical does not insert a gap between the two words.
	abyssArt := strings.TrimRight(figure.NewFigure("ABYSS", font, true).String(), "\n")
	linkArt := strings.TrimRight(figure.NewFigure("LINK", font, true).String(), "\n")
	// lipgloss/termenv auto-downsamples truecolor → 256 → 16-color by terminal
	// profile; no explicit branch is needed for the monochrome tier (D-06 tier 2).
	abyssStyled := lipgloss.NewStyle().Foreground(ColorAccent).Render(abyssArt)
	linkStyled := lipgloss.NewStyle().Foreground(ColorSelection).Render(linkArt)
	return lipgloss.JoinVertical(lipgloss.Center, abyssStyled, linkStyled)
}
