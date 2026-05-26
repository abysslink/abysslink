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

func newRepairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repair",
		Short: "Auto-fix failures detected by doctor",
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
				return fmt.Errorf("repair: %w", err)
			}

			// Run doctor to find all current findings.
			findings, err := r.Doctor(ctx)
			if err != nil {
				return fmt.Errorf("repair: doctor: %w", err)
			}

			if len(findings) == 0 {
				printerInfo(p, "No issues found — system is healthy.")
				return nil
			}

			// Collect modules with non-OK findings.
			needsRepair := map[string]bool{}
			for _, f := range findings {
				if f.Severity != modules.SeverityOK {
					needsRepair[f.Module] = true
				}
			}

			if len(needsRepair) == 0 {
				printerInfo(p, "All checks passed — nothing to repair.")
				return nil
			}

			// Attempt repair on each affected module.
			modMap := make(map[string]modules.Module, len(mods))
			for _, m := range mods {
				modMap[m.Name()] = m
			}

			var repairErrs []error
			for modName := range needsRepair {
				m, ok := modMap[modName]
				if !ok {
					continue
				}

				printerInfo(p, fmt.Sprintf("  Repairing module: %s", modName))
				if !cc.dryRun {
					if repErr := m.Repair(ctx); repErr != nil {
						printerError(p, fmt.Sprintf("  repair [%s]: %v", modName, repErr))
						repairErrs = append(repairErrs, repErr)
					} else {
						printerInfo(p, fmt.Sprintf("  Repaired: %s", modName))
					}
				} else {
					printerInfo(p, fmt.Sprintf("  [plan] would repair: %s", modName))
				}
			}

			if len(repairErrs) > 0 {
				return fmt.Errorf("repair: %d module(s) failed to repair", len(repairErrs))
			}

			return nil
		},
	}
}
