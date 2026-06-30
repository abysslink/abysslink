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

	"github.com/abysslink/abysslink/internal/ui"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

// newGalleryCmd returns the hidden `abysslink gallery` command that renders
// the Abyss theme preview for eyeballing — banner + glamour sample + huh form
// (interactive only).
//
// Security constraints (D-15):
//   - Hidden: true — does not appear in `abysslink --help`
//   - No file mutations (no audit.WriteFile, no config.Write)
//   - No network calls (no browser.OpenURL, no HTTP)
//   - No keychain access
//   - huh form is skipped in headless / non-TTY (interactive() gate)
func newGalleryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "gallery",
		Short:  "Abyss theme preview (hidden)",
		Hidden: true,
		Example: `  # Preview the Abyss theme — banner, glamour sample, and a sample form
  abysslink gallery`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			p := newPrinter(cmd)

			// 1. Banner (Phase 34 D-05: banner at every init/gallery entry).
			banner := ui.RenderBanner(ui.BannerOptions{
				Color:  colorEnabled(),
				Width:  boxWidth(),
				Border: boxBorder(),
			})
			printerInfo(p, banner)

			// 2. Sample huh form — interactive path only.
			// The form is skipped in headless / non-TTY (CI, --json, pipe) so the
			// gallery command always exits 0 without hanging (D-15). Read the real
			// --json / --yes flags so the documented "skipped under --json / headless"
			// contract actually holds (T-044) instead of hard-coding false.
			jsonOut, _ := cmd.Flags().GetBool("json")
			yes, _ := cmd.Flags().GetBool("yes")
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

			// 3. Glamour markdown sample (D-13: glamour via Printer, never stdout).
			sampleMD := "# Gallery\n\n" +
				"**Abyss theme preview** — `abysslink gallery`\n\n" +
				"## Headings are cyan\n\n" +
				"*Emphasis is violet*\n\n" +
				"```go\nfunc main() { fmt.Println(\"hello\") }\n```\n\n" +
				"> Blockquotes are muted steel\n\n" +
				"This is a theme preview. No changes were made."
			printerInfo(p, ui.RenderMarkdown(sampleMD, !colorEnabled()))

			// 4. Footer hint.
			printerInfo(p, styleFooterHint.Render("This is a theme preview. No changes were made."))
			return nil
		},
	}
	return cmd
}
