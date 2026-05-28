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
	"fmt"
	"os"
	"strings"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Exhaustive verification of all modules and security posture",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			header := styleBold.Render("abysslink doctor") + "  " + styleMuted.Render("health check")
			printerInfo(p, styleHeaderBox.Render(header))
			printerInfo(p, "")

			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("doctor: %w", err)
			}
			mods := allModules(deps)
			r, err := modules.NewRunner(mods, cc.cfg)
			if err != nil {
				return err
			}

			findings, err := r.Doctor(ctx)
			if err != nil {
				return fmt.Errorf("doctor: %w", err)
			}

			hasFatal := false
			hasWarn := false

			if len(findings) == 0 {
				printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("All checks passed. System is healthy."))
				printerInfo(p, "")
				return nil
			}

			// Group findings by module.
			seenMod := map[string]bool{}
			for _, f := range findings {
				if !seenMod[f.Module] {
					seenMod[f.Module] = true
					printerInfo(p, styleMuted.Render("  "+strings.Repeat("─", 50)))
					printerInfo(p, "  "+styleBold.Render(f.Module))
				}

				switch f.Severity {
				case modules.SeverityOK:
					printerInfo(p, fmt.Sprintf("    %s  %s",
						iconDoneStr(),
						styleMuted.Render(f.Check)))
				case modules.SeverityWarning:
					hasWarn = true
					printerInfo(p, fmt.Sprintf("    %s  %s\n       %s",
						iconWarnStr(),
						styleWarn.Render(f.Check),
						styleMuted.Render(f.Message)))
				case modules.SeverityFatal:
					hasFatal = true
					printerInfo(p, fmt.Sprintf("    %s  %s\n       %s",
						iconFatalStr(),
						styleFatal.Render(f.Check),
						f.Message))
				}
			}

			printerInfo(p, styleMuted.Render("  "+strings.Repeat("─", 50)))
			printerInfo(p, "")

			if hasFatal {
				printerInfo(p, "  "+iconFatalStr()+"  "+styleFatal.Render("Fatal issues found — system is not safe."))
				printerInfo(p, "  "+styleMuted.Render("Run: abysslink repair"))
				printerInfo(p, "")
				os.Exit(2)
			}
			if hasWarn {
				printerInfo(p, "  "+iconWarnStr()+"  "+styleWarn.Render("Warnings found — review the issues above."))
				printerInfo(p, "  "+styleMuted.Render("Run: abysslink repair"))
				printerInfo(p, "")
				os.Exit(1)
			}
			return nil
		},
	}
}
