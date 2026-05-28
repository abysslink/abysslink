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

// threatRow is one defense line. failChecks lists the Verify/Detect check names
// that, if present in a doctor pass, flip the row from ✓ to ✗. An empty
// failChecks means the defense is structural (always on by construction).
type threatRow struct {
	desc       string
	failChecks []string
}

var threatRows = []threatRow{
	{"No public exposure (no Funnel)", []string{"funnel"}},
	{"Phone restricted: SSH + mosh ports only", []string{"acl_drift"}},
	{"SSH re-auth interval <= 12h", nil},
	{"OpenSSH daemon off when Tailscale SSH on", []string{"remote_login", "sshd_running"}},
	{"FileVault / LUKS full-disk encryption", []string{"filevault", "luks"}},
	{"API key in keychain, never on argv", nil},
	{"Audit trail on every mutation", nil},
	{"Reversible (backup + restore)", nil},
	{"No SSH agent forwarding", nil},
	{"No telemetry", nil},
	{"Tailnet Lock enabled", []string{"lock_enabled"}},
	{"ntfy binds tailnet IP only (never 0.0.0.0)", []string{"listen_address"}},
}

func newThreatModelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "threat-model",
		Short: "Print the security threat model with the current ✓/✗ status of each defense",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)

			// Derive live status from a doctor pass (best-effort).
			present := map[string]bool{}
			if deps, derr := buildDeps(ctx, cc); derr == nil {
				if r, rerr := modules.NewRunner(allModules(deps), cc.cfg); rerr == nil {
					findings, _ := r.Doctor(ctx)
					for _, f := range findings {
						if f.Severity != modules.SeverityOK {
							present[f.Check] = true
						}
					}
				}
			}

			printerInfo(p, styleBold.Render("Abysslink threat model")+"  "+styleMuted.Render("(live status)"))
			printerInfo(p, "")
			for _, row := range threatRows {
				ok := true
				for _, c := range row.failChecks {
					if present[c] {
						ok = false
						break
					}
				}
				mark := styleSuccess.Render("✓")
				if !ok {
					mark = styleFatal.Render("✗")
				}
				printerInfo(p, fmt.Sprintf("  %s  %s", mark, row.desc))
			}
			printerInfo(p, "")
			printerInfo(p, styleMuted.Render("✗ means a doctor check is currently failing — run `abysslink doctor` for detail."))
			return nil
		},
	}
}
