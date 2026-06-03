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

// v3SurfaceRows are the in-process surfaces added in v3 (metrics endpoint, Web
// UI, audit chain). They render for every backend. Each failChecks entry lists
// BOTH the sec-* alias ID and the original module check ID so the row flips to ✗
// if either fires, even if the alias naming evolves.
var v3SurfaceRows = []threatRow{
	{"Metrics endpoint bound to tailnet IP only (sec-metrics-bind)", []string{"sec-metrics-bind", "metrics-bind-tailnet"}},
	{"Web UI bound to tailnet IP only + WhoIs-authenticated (sec-webui-bind)", []string{"sec-webui-bind", "webui-bind"}},
	{"Audit chain integrity verified < 24h (sec-audit-anchor-age)", []string{"sec-audit-anchor-age", "audit-anchor-age"}},
}

// backendRows holds the backend-specific threat rows appended when --backend is
// supplied. An unknown backend key returns nil (no panic).
var backendRows = map[string][]threatRow{
	"tailscale": {
		{"Tailnet Lock enabled", []string{"lock_enabled"}},
		{"ACL policy not drifted", []string{"acl_drift"}},
		{"Tailscale Funnel rejected at schema level (sec-funnel-schema)", []string{"sec-funnel-schema", "funnel"}},
	},
	"headscale": {
		{"Headscale API served over TLS (hs-tls)", []string{"hs-tls"}},
		{"Headscale API authenticated (hs-api-auth)", []string{"hs-api-auth"}},
		{"No Tailnet Lock on Headscale — permanent advisory (hs-lock)", []string{"hs-lock"}},
		{"Headscale OIDC allow-list configured (hs-oidc-filter)", []string{"hs-oidc-filter"}},
	},
	"netbird": {
		{"NetBird management API over TLS (nb-tls)", []string{"nb-tls"}},
		{"NetBird server meets minimum version (nb-version)", []string{"nb-version"}},
		{"ZITADEL admin token configured (nb-zitadel)", []string{"nb-zitadel"}},
		{"No Tailnet Lock on NetBird — permanent advisory (nb-lock)", []string{"nb-lock"}},
	},
}

// checkState records whether a check ID ran and whether it failed.
// It drives the tri-state render: absent (never ran) ⇒ —; ran+OK ⇒ ✓; ran+failed ⇒ ✗.
type checkState struct {
	ran    bool
	failed bool
}

func newThreatModelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "threat-model",
		Short: "Print the security threat model with the current ✓/✗/— status of each defense",
		Example: `  # Show the threat model and current security posture
  abysslink threat-model

  # Include backend-specific threat rows
  abysslink threat-model --backend=headscale`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			backend, _ := cmd.Flags().GetString("backend")

			// DOC-01: derive live status from the shared collectDoctorFindings set —
			// the same source of truth doctor and the web-UI dashboard consume.
			// Build a tri-state map so absent checks render — (never ✓).
			state := map[string]checkState{}
			if deps, derr := buildDeps(ctx, cc); derr == nil {
				findings := collectDoctorFindings(ctx, cc, deps)
				for _, f := range findings {
					st := state[f.Check]
					st.ran = true
					if f.Severity != modules.SeverityOK {
						st.failed = true
					}
					state[f.Check] = st
				}
			}

			printerInfo(p, styleBold.Render("Abysslink threat model")+"  "+styleMuted.Render("(live status)"))

			printerInfo(p, "")
			printerInfo(p, styleBold.Render("  Base threat model"))
			renderThreatRows(p, threatRows, state)

			printerInfo(p, "")
			printerInfo(p, styleBold.Render("  v3 surfaces"))
			renderThreatRows(p, v3SurfaceRows, state)

			if backend != "" {
				if rows, ok := backendRows[backend]; ok {
					printerInfo(p, "")
					printerInfo(p, styleBold.Render(fmt.Sprintf("  Backend: %s", backend)))
					renderThreatRows(p, rows, state)
				} else {
					printerInfo(p, "")
					printerInfo(p, styleMuted.Render(fmt.Sprintf("  unknown backend %q — rendering base + v3 surfaces only (valid: tailscale, headscale, netbird)", backend)))
				}
			}

			printerInfo(p, "")
			printerInfo(p, styleMuted.Render("✗ means a doctor check is currently failing — run `abysslink doctor` for detail."))
			printerInfo(p, styleMuted.Render("— means the backing check did not run this pass (non-active backend or probe unavailable)."))
			return nil
		},
	}
	cmd.Flags().String("backend", "", "render backend-specific threat rows (tailscale, headscale, netbird)")
	return cmd
}

// renderThreatRows prints each row with a tri-state ✓/✗/— mark derived from the
// checkState map built over the shared collectDoctorFindings set (DOC-01).
//
// Per-row logic (D-02, D-04):
//   - empty failChecks (structural rows) ⇒ always ✓ (Pitfall 3 — always on by construction)
//   - any failCheck ran && failed ⇒ ✗ (styleFatal)
//   - else any failCheck ran ⇒ ✓ (styleSuccess)
//   - else (no failCheck present in the set) ⇒ — (styleMuted; honest unknown, never fabricated ✓)
func renderThreatRows(p Printer, rows []threatRow, state map[string]checkState) {
	for _, row := range rows {
		var mark string
		if len(row.failChecks) == 0 {
			// Structural row: defense is always on by construction.
			mark = styleSuccess.Render("✓")
		} else {
			anyRan := false
			anyFailed := false
			for _, c := range row.failChecks {
				if st, ok := state[c]; ok && st.ran {
					anyRan = true
					if st.failed {
						anyFailed = true
					}
				}
			}
			switch {
			case anyFailed:
				mark = styleFatal.Render("✗")
			case anyRan:
				mark = styleSuccess.Render("✓")
			default:
				// No backing check ran this pass — render honestly as unknown.
				mark = styleMuted.Render("—")
			}
		}
		printerInfo(p, fmt.Sprintf("  %s  %s", mark, row.desc))
	}
}
