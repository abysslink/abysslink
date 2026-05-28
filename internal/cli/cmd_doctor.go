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
					fix := findingFix(f.Check)
					msg := fmt.Sprintf("    %s  %s\n       %s",
						iconWarnStr(), styleWarn.Render(f.Check), styleMuted.Render(f.Message))
					if fix != "" {
						msg += "\n       " + styleCode.Render("fix: "+fix)
					}
					printerInfo(p, msg)
				case modules.SeverityFatal:
					hasFatal = true
					fix := findingFix(f.Check)
					msg := fmt.Sprintf("    %s  %s\n       %s",
						iconFatalStr(), styleFatal.Render(f.Check), f.Message)
					if fix != "" {
						msg += "\n       " + styleCode.Render("fix: "+fix)
					}
					printerInfo(p, msg)
				}
			}

			printerInfo(p, styleMuted.Render("  "+strings.Repeat("─", 50)))
			printerInfo(p, "")

			if hasFatal {
				printerInfo(p, "  "+iconFatalStr()+"  "+styleFatal.Render("Fatal issues found — system is not safe."))
				printerInfo(p, "  "+styleMuted.Render("Run: abysslink repair --apply  to auto-fix what can be fixed."))
				printerInfo(p, "")
				os.Exit(2)
			}
			if hasWarn {
				printerInfo(p, "  "+iconWarnStr()+"  "+styleWarn.Render("Warnings found — review the issues above."))
				printerInfo(p, "  "+styleMuted.Render("Run: abysslink repair --apply  to auto-fix what can be fixed."))
				printerInfo(p, "")
				os.Exit(1)
			}
			return nil
		},
	}
}

// findingFix maps a finding check name to a short remediation command or
// instruction. Returns "" when no specific guidance exists (generic repair
// message is shown instead).
func findingFix(check string) string {
	fixes := map[string]string{
		// Disk encryption.
		"filevault": "System Settings → Privacy & Security → FileVault → Turn On",
		"luks":      "Enable full-disk encryption (LUKS) before exposing remote access",
		// Firewall.
		"firewall":             "System Settings → Network → Firewall → Turn On  (macOS)",
		"application_firewall": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
		// SSH.
		"sshd_running": "sudo systemctl enable --now ssh  (Linux)  |  System Preferences → Sharing → Remote Login  (macOS)",
		"checkperiod":  "Lower ssh_check_period in abysslink.yaml (max 12h)",
		// Tailscale.
		"needs_login":   "tailscale login",
		"ssh_sandboxed": "brew install tailscale  (replaces App Store version)",
		"installed":     "abysslink up --apply",
		// Tailnet Lock.
		"lock_enabled": "tailscale lock init   (then abysslink up --apply)",
		"lock_status":  "ensure tailscale is running: brew services restart tailscale",
		// Claude Code hooks.
		"stop_hook_configured":         "abysslink up --apply",
		"notification_hook_configured": "abysslink up --apply",
		"api_key_present":              "export ANTHROPIC_API_KEY=<key>  then  abysslink up --apply",
		"api_key_keychain":             "unlock your login keychain in Keychain Access.app",
		// ntfy.
		"ntfy_bind":  "abysslink up --apply  (ntfy must bind to tailnet IP, not 0.0.0.0)",
		"ntfy_admin": "abysslink up --apply",
		// Generic install / config.
		"not_installed":        "abysslink up --apply",
		"panes_configured":     "add panes to modules.watch.panes in abysslink.yaml",
		"claude_dir_exists":    "install Claude Code: npm i -g @anthropic-ai/claude-code",
		"settings_json_exists": "abysslink up --apply",
	}
	return fixes[check]
}
