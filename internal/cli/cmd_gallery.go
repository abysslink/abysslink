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
	"errors"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/abysslink/abysslink/internal/ui"
)

// newGalleryCmd returns the hidden `abysslink gallery` command that renders
// the FULL Abyss theme preview for eyeballing (TUI-07): banner, palette
// swatches, semantic text styles, icon legend, boxes and rules, the tui
// components (journey header, all four note levels, secret box with FAKE
// sample data, module rows, static progress fallbacks), the glamour markdown
// sample, and the footer hint. The huh form remains the ONLY interactive
// element and is gated behind interactive().
//
// Security constraints (D-15):
//   - Hidden: true — does not appear in `abysslink --help`
//   - No file mutations (no audit.WriteFile, no config.Write)
//   - No network calls (no browser.OpenURL, no HTTP)
//   - No keychain access
//   - huh form is skipped in headless / non-TTY (interactive() gate)
//   - --json is a no-op (exit 0, no output) — the gallery is a human-only
//     preview; boxed prose has no machine-readable shape (§9)
//   - The SecretBox demo renders an OBVIOUSLY-FAKE placeholder secret only;
//     it is printed once via the Printer and never logged or audited
//   - No animated component ever runs (spinner/live table are represented by
//     their static frames), so the command can never hang a CI pipe
func newGalleryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "gallery",
		Short:  "Abyss theme preview (hidden)",
		Hidden: true,
		Example: `  # Preview the Abyss theme — banner, palette, styles, tui components,
  # glamour sample, and a sample form (interactive only)
  abysslink gallery`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			p := newPrinter(cmd)

			// Read the real --json / --yes flags so the documented
			// "skipped under --json / headless" contract actually holds (T-044).
			jsonOut, _ := cmd.Flags().GetBool("json")
			yes, _ := cmd.Flags().GetBool("yes")

			// --json degrades to a no-op: the gallery output is human prose
			// (boxes, swatches, sample rows) that would only pollute the
			// newline-delimited JSON stream as {"msg":…} records. Mirrors the
			// self-guards in commandHeader/emitNote, applied wholesale (D-15).
			if jsonOut {
				return nil
			}

			// 1. Banner (Phase 34 D-05: banner at every init/gallery entry).
			banner := ui.RenderBanner(ui.BannerOptions{
				Color:  colorEnabled(),
				Width:  boxWidth(),
				Border: boxBorder(),
			})
			printerInfo(p, banner)

			// 2. Canonical Tier-1 command header (styleHeaderBox + styleTitle).
			commandHeader(p, "gallery", styleMuted.Render("theme preview"))

			// 3. Sample huh form — interactive path only.
			// The form is skipped in headless / non-TTY (CI, --json, pipe) so the
			// gallery command always exits 0 without hanging (D-15).
			if interactive(yes, jsonOut) {
				var choice string
				form := huh.NewForm(huh.NewGroup(
					huh.NewSelect[string]().
						Title("Abyss theme preview — abysslink gallery").
						Description("Select to see the focused state").
						Options(
							huh.NewOption("Tailscale (cloud)", "tailscale"),
							huh.NewOption("Headscale (self-hosted)", "headscale"),
						).
						Value(&choice),
				))
				// Honour ctx cancellation (ctrl+c during the preview) and
				// propagate real form errors instead of swallowing them and
				// reporting a clean exit 0 (WR-05). ErrUserAborted is a user
				// intent signal, not an error — the gallery still completes
				// normally (no mutations, exit 0) when the user aborts.
				if err := form.WithTheme(ui.AbyssTheme()).RunWithContext(ctx); err != nil &&
					!errors.Is(err, huh.ErrUserAborted) {
					return err
				}
			}

			// 4–9. Static sections — pure string renders only, never a program
			// loop, so the output is deterministic on every headless surface.
			galleryPalette(p)
			galleryTextStyles(p)
			galleryBoxes(p)
			galleryTUIComponents(p)
			galleryProgressRows(p)
			galleryMarkdown(p)

			// 10. Footer hints: the UI-SPEC canonical navigation copy plus the
			// no-mutation reassurance line.
			printerInfo(p, "")
			printerInfo(p, styleFooterHint.Render("↑/↓ navigate  •  space toggle  •  enter select  •  esc back  •  ctrl+c quit"))
			printerInfo(p, styleFooterHint.Render("This is a theme preview. No changes were made."))
			return nil
		},
	}
	return cmd
}

// gallerySection prints a muted rule + cyan title header separating the
// gallery's labelled sections (hrule doubles as the ruleN/hrule demo).
func gallerySection(p Printer, title string) {
	printerInfo(p, "")
	printerInfo(p, styleMuted.Render(hrule()))
	printerInfo(p, styleTitle.Render(title))
	printerInfo(p, "")
}

// galleryPalette renders one swatch line per Abyss palette tone
// (internal/ui theme.go — brand + semantic palettes, D-01/D-04). Under
// NO_COLOR / non-TTY lipgloss strips the ANSI and the block glyphs degrade to
// plain "██ name" lines — byte-stable.
func galleryPalette(p Printer) {
	gallerySection(p, "Palette")
	swatches := []struct {
		name string
		c    lipgloss.TerminalColor
	}{
		{"ColorAccent — brand cyan", ui.ColorAccent},
		{"ColorSelection — brand violet", ui.ColorSelection},
		{"ColorMuted — brand steel", ui.ColorMuted},
		{"ColorSuccess — semantic green", ui.ColorSuccess},
		{"ColorWarn — semantic yellow", ui.ColorWarn},
		{"ColorFatal — semantic red", ui.ColorFatal},
		{"ColorInfo — semantic blue", ui.ColorInfo},
		{"ColorSecurity — security cyan", ui.ColorSecurity},
		{"ColorMutedSemantic — muted grey", ui.ColorMutedSemantic},
		{"ColorFg — primary foreground", ui.ColorFg},
		{"ColorDim — code-block background", ui.ColorDim},
	}
	for _, s := range swatches {
		block := lipgloss.NewStyle().Foreground(s.c).Render("██")
		printerInfo(p, "  "+block+"  "+s.name)
	}
}

// galleryTextStyles renders one sample line per semantic text style. The cli
// styleX vars mirror the exported ui.StyleX twins (same palette, D-03), so
// showing the cli set covers both.
func galleryTextStyles(p Printer) {
	gallerySection(p, "Status & semantic styles")
	printerInfo(p, "  "+styleTitle.Render("styleTitle — branded section title"))
	printerInfo(p, "  "+styleSuccess.Render("styleSuccess — converged"))
	printerInfo(p, "  "+styleWarn.Render("styleWarn — advisory"))
	printerInfo(p, "  "+styleFatal.Render("styleFatal — failed closed"))
	printerInfo(p, "  "+styleInfo.Render("styleInfo — info marker"))
	printerInfo(p, "  "+styleMuted.Render("styleMuted — secondary text"))
	printerInfo(p, "  "+styleBold.Render("styleBold — emphasis"))
	printerInfo(p, "  "+styleCode.Render("abysslink up --apply")+"  "+styleMuted.Render("(styleCode — copy/run snippet, T-003)"))
	printerInfo(p, "")

	// Icon legend — every glyph from the styles.go icon set.
	printerInfo(p, "  "+iconOKStr()+" ok   "+iconWarnStr()+" warn   "+iconFatalStr()+" fatal   "+
		iconDoneStr()+" done   "+iconArrowStr()+" change   "+iconSpinStr()+" busy   "+iconNeutralStr()+" disabled")
	printerInfo(p, "")

	// Fleet status-cell words — one per statusCellStyle branch.
	cells := ""
	for _, state := range []string{"reachable", "degraded", "unreachable", "paused"} {
		cells += statusCellStyle(state).Render(state) + "   "
	}
	printerInfo(p, "  "+cells+styleMuted.Render("(statusCellStyle)"))
}

// galleryBoxes renders the bordered box styles and the fixed-width rule.
// styleHeaderBox is already showcased by commandHeader at the top; the border
// glyph set is frozen at package init (ASCII +/-/| on non-TTY), so captures
// stay byte-stable.
func galleryBoxes(p Printer) {
	gallerySection(p, "Boxes & rules")
	printerInfo(p, styleNextStepBox.Render("Next step\n\nRun  "+styleCode.Render("abysslink up --apply")+"  to converge."))
	printerInfo(p, "")
	printerInfo(p, styleStatusBox.Render("status panel sample — see abysslink status"))
	printerInfo(p, "")
	printerInfo(p, "  "+styleMuted.Render(ruleN(24))+"  "+styleMuted.Render("(ruleN(24) — fixed-width rule)"))
}

// galleryTUIComponents renders the internal/tui string components: journey
// header, all four Note levels, one canonical §7 security note, and the
// SecretBox. The SecretBox demo feeds an OBVIOUSLY-FAKE placeholder — it is
// printed exactly once via the Printer and must never be passed to slog or
// internal/audit (SecretBox contract).
func galleryTUIComponents(p Printer) {
	gallerySection(p, "TUI components")

	// Journey progress strip — done (✓/v), current (●/o), remaining (·/.).
	printerInfo(p, tui.JourneyHeader(3, 5, []string{"Account", "Prerequisites", "Converge", "Lock", "Done"}))
	printerInfo(p, "")

	// All four note levels via the json-safe emitNote wrapper.
	emitNote(p, tui.NoteInfo, "Sample info note", []string{"Informational body line."})
	emitNote(p, tui.NoteWarn, "Sample warning note", []string{"Advisory body line."})
	emitNote(p, tui.NoteSecurity, "Sample security note", []string{"Security callout body line."})
	emitNote(p, tui.NoteDanger, "Sample danger note", []string{"Destructive-action body line."})

	// One canonical §7 callout, referenced by ID (single source of truth).
	// jsonOut is hard-false: the gallery's --json path already no-ops with an
	// early return before any section renders.
	emitSecurityNote(p, false, "dry-run-default")

	// Secret box — FAKE placeholder data only.
	printerInfo(p, tui.SecretBox("Tailnet Lock disablement secret (SAMPLE)", []string{
		"s3cr3t-EXAMPLE-0000-NOT-A-REAL-SECRET",
	}))
}

// galleryProgressRows renders the static progress vocabulary: settled live
// table rows, the cli scan/apply row twins, the plain progress fallbacks, a
// static spinner frame, and the final summary line. No Bubble Tea program is
// ever started — the animated LiveTable/RunSpinner looks are represented by
// these static frames only (D-15).
func galleryProgressRows(p Printer) {
	gallerySection(p, "Progress & module rows")

	// Settled live-table rows: done / warn / error branches (tui.RenderRows).
	printerInfo(p, tui.RenderRows([]tui.RowEvent{
		{Module: "tailscale", Index: 1, Total: 3},
		{Module: "ntfy", Index: 2, Total: 3, HasWarn: true, WarnMsg: "version below floor"},
		{Module: "mosh", Index: 3, Total: 3, HasError: true, ErrMsg: "not installed"},
	}))
	printerInfo(p, "")

	// cli scan/apply row twins — the only static way to show the →/✓ scan look.
	printerInfo(p, scanRowStr(modules.ModuleEvent{Module: "tailscale"}))
	printerInfo(p, scanRowStr(modules.ModuleEvent{Module: "ntfy", Actions: []modules.Action{
		{Module: "ntfy", Description: "install ntfy"},
	}}))
	printerInfo(p, applyRowStr(modules.ModuleEvent{Module: "ssh", Index: 2, Total: 3}))
	printerInfo(p, "")

	// Static progress fallbacks + one static spinner frame (never animated here).
	printerInfo(p, "  "+tui.PlainBar(3, 7)+"  "+styleMuted.Render("(PlainBar — non-animated progress)"))
	printerInfo(p, "  "+tui.PlainStatus("checking daemon...")+"  "+styleMuted.Render("(PlainStatus — non-animated spinner)"))
	printerInfo(p, "  "+lipgloss.NewStyle().Foreground(ui.ColorAccent).Render("⠋")+
		"  installing mosh...  "+styleMuted.Render("(static spinner frame — animated on a colour TTY)"))

	// Final summary line (green converged form) over a fake 1-action run.
	printFinalSummary(p, []modules.Action{
		{Module: "tailscale", Description: "sample converged action"},
	}, nil, 1500*time.Millisecond, nil)
}

// galleryMarkdown renders the glamour sample covering every styled node of
// AbyssGlamourStyle: H1/H2/H3, strong, emphasis, inline code, link, list,
// fenced code block, and blockquote (D-13: glamour via Printer, never stdout).
func galleryMarkdown(p Printer) {
	gallerySection(p, "Markdown")
	sampleMD := "# Gallery\n\n" +
		"**Abyss theme preview** — `abysslink gallery`\n\n" +
		"## Headings are cyan\n\n" +
		"### Inline code and links\n\n" +
		"Run `abysslink doctor` — see [the design doc](https://github.com/abysslink/abysslink) for details.\n\n" +
		"*Emphasis is violet*\n\n" +
		"- list item one\n" +
		"- list item two\n\n" +
		"```go\nfunc main() { fmt.Println(\"hello\") }\n```\n\n" +
		"> Blockquotes are muted steel\n\n" +
		"This is a theme preview. No changes were made."
	printerInfo(p, ui.RenderMarkdown(sampleMD, !colorEnabled()))
}
