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

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/spf13/cobra"
)

func newUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Converge the system to match abysslink.yaml (dry-run by default)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			if cc.dryRun {
				printerInfo(p, "Dry-run mode (use --apply to apply changes)")
			}

			mods := allModules(cc.runner, cc.cfg)
			r, err := modules.NewRunner(mods, cc.cfg)
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}

			actions, findings, err := r.Up(ctx, cc.dryRun)
			if err != nil {
				return fmt.Errorf("up: %w", err)
			}

			// Print actions.
			if len(actions) == 0 {
				printerInfo(p, "System is already converged — nothing to do.")
			} else {
				for _, a := range actions {
					prefix := "  [plan]"
					if !cc.dryRun {
						prefix = "  [done]"
					}
					printerInfo(p, fmt.Sprintf("%s %s: %s", prefix, a.Module, a.Description))
				}
			}

			// Print findings.
			for _, f := range findings {
				switch f.Severity {
				case modules.SeverityFatal:
					printerError(p, fmt.Sprintf("FATAL [%s] %s: %s", f.Module, f.Check, f.Message))
				case modules.SeverityWarning:
					printerWarn(p, fmt.Sprintf("WARN  [%s] %s: %s", f.Module, f.Check, f.Message))
				}
			}

			return nil
		},
	}
}
