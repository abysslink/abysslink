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
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Execute builds the root command, wires all subcommands, and runs the CLI.
// Returns 0 on success, 1 on error.
func Execute(ctx context.Context) int {
	rootCmd := buildRootCmd()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			// Message already printed by the command; just return the code.
			return ee.ExitCode()
		}
		slog.Error("abysslink error", "err", err)
		return 1
	}
	return 0
}

func buildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "abysslink",
		Short: "Secure phone-to-laptop remote control over Tailscale",
		Long: `Abysslink sets up a hardened, audited remote-access stack on your laptop
so you can develop from your phone: Tailscale VPN, SSH, ntfy push
notifications, tmux, and mosh — all locked down by default.

  Typical setup (run once on a new machine):
    abysslink init          # interactive setup wizard
    abysslink up --apply    # converge system to config
    abysslink enroll phone  # pair your phone

  Check status any time:
    abysslink status        # quick dashboard
    abysslink doctor        # deep health check + fix guidance

Exit codes (doctor, up):
  0  — OK: all checks passed; no action needed.
  1  — Warning: issues found; system operable but review recommended.
  2  — Fatal: fail-closed or fatal issue; system is not safe to use.

Run 'abysslink <command> --help' for details on any command.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Command groups (cobra 1.7+).
	root.AddGroup(
		&cobra.Group{ID: "setup", Title: "Setup:"},
		&cobra.Group{ID: "ops", Title: "Operations:"},
		&cobra.Group{ID: "advanced", Title: "Advanced:"},
		&cobra.Group{ID: "emergency", Title: "Emergency:"},
	)

	// Persistent flags — available to all subcommands.
	pf := root.PersistentFlags()
	pf.String("config", defaultConfigPath(), "path to abysslink.yaml")
	pf.Bool("dry-run", false, "show planned changes without applying")
	pf.Bool("apply", false, "execute planned changes")
	pf.Bool("yes", false, "skip interactive confirmations")
	pf.Bool("json", false, "output as JSON")
	pf.BoolP("verbose", "v", false, "enable debug logging")
	pf.Bool("explain", false, "show per-action rationale alongside each planned change")
	// Fleet targeting flags (Phase 14, Plan 03): consumed by fan-out commands (Plan 05).
	pf.String("rig", "", "target a single enrolled rig by name")
	pf.Bool("all-rigs", false, "fan out to all enrolled rigs")
	pf.Bool("strict", false, "fail (exit 1) if any rig is UNREACHABLE")

	// Register all subcommands with groups.
	setupCmds := []*cobra.Command{
		newInitCmd(),
		newUpCmd(),
		newStatusCmd(),
		newDoctorCmd(),
		newReportCmd(),
		newRepairCmd(),
		newEnrollCmd(),
	}
	for _, c := range setupCmds {
		c.GroupID = "setup"
		root.AddCommand(c)
	}

	opsCmds := []*cobra.Command{
		newNotifyCmd(),
		newWatchCmd(),
		newACLCmd(),
		newLockCmd(),
		newRotateCmd(),
		newLogsCmd(),
		newBackupCmd(),
		newAuditCmd(),
		newUpgradeCmd(),
		newVerifyCmd(),
		newVersionCmd(),
		newDaemonCmd(),
		newServerCmd(),
		newRigCmd(),
	}
	for _, c := range opsCmds {
		c.GroupID = "ops"
		root.AddCommand(c)
	}

	advancedCmds := []*cobra.Command{
		newClaudeCodeCmd(),
		newEnableCmd(),
		newDisableCmd(),
		newThreatModelCmd(),
		newWolCmd(),
		newUninstallCmd(),
	}
	for _, c := range advancedCmds {
		c.GroupID = "advanced"
		root.AddCommand(c)
	}

	emergencyCmds := []*cobra.Command{
		newPanicCmd(),
	}
	for _, c := range emergencyCmds {
		c.GroupID = "emergency"
		root.AddCommand(c)
	}

	return root
}

func defaultConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "abysslink", "abysslink.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "abysslink", "abysslink.yaml")
}
