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
			mods := allModules(cc.runner, cc.cfg)
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

			for _, f := range findings {
				switch f.Severity {
				case modules.SeverityOK:
					printerInfo(p, fmt.Sprintf("  OK    [%s] %s", f.Module, f.Check))
				case modules.SeverityWarning:
					hasWarn = true
					printerWarn(p, fmt.Sprintf("  WARN  [%s] %s: %s", f.Module, f.Check, f.Message))
				case modules.SeverityFatal:
					hasFatal = true
					printerError(p, fmt.Sprintf("  FATAL [%s] %s: %s", f.Module, f.Check, f.Message))
				}
			}

			if len(findings) == 0 {
				printerInfo(p, "All checks passed.")
				return nil
			}

			if hasFatal {
				printerError(p, "doctor: fatal issues found — system is not safe")
				os.Exit(2)
			}
			if hasWarn {
				printerWarn(p, "doctor: warnings found — review the above")
				os.Exit(1)
			}
			return nil
		},
	}
}
