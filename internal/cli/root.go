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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/spf13/cobra"
)

// Execute builds the root command, wires all subcommands, and runs the CLI.
// Returns 0 on success, 1 on error, or the code carried by an exitError.
func Execute(ctx context.Context) int {
	rootCmd := buildRootCmd()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.err == nil {
				// Message already printed by the command; just return the code.
				return ee.ExitCode()
			}
			// Fail-closed gates carry their message here so it is rendered
			// through the same central path as every other error.
			printCLIError(rootCmd, ee.err)
			return ee.ExitCode()
		}
		printCLIError(rootCmd, err)
		return 1
	}
	return 0
}

// printCLIError renders a terminal command error for the user. Human mode
// prints "Error: <first line>" plus any continuation lines (e.g. cobra's
// multi-line "Did you mean this?" suggestion) verbatim to stderr; JSON mode
// emits a single {"error": "..."} object so machine consumers never have to
// parse slog records. The raw slog record is kept only under --verbose for
// troubleshooting (UX review #2).
func printCLIError(rootCmd *cobra.Command, err error) {
	jsonOut, _ := rootCmd.PersistentFlags().GetBool("json")
	verbose, _ := rootCmd.PersistentFlags().GetBool("verbose")
	if verbose {
		slog.Error("abysslink error", "err", err)
	}

	if jsonOut {
		NewJSONPrinterTo(rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()).Error(err.Error())
		return
	}

	p := NewHumanPrinterTo(rootCmd.OutOrStdout(), rootCmd.ErrOrStderr())
	lines := strings.Split(strings.TrimRight(err.Error(), "\n"), "\n")
	p.Error("Error: " + lines[0])
	for _, l := range lines[1:] {
		p.Error(l)
	}
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
	pf.String("rig", "", "target a single enrolled rig by name (status, doctor, report, notify, panic)")
	pf.Bool("all-rigs", false, "fan out to all enrolled rigs")
	pf.Bool("strict", false, "fail (exit 2) if any rig is UNREACHABLE")

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
		newAsciinemaCmd(),
		newNetBirdCmd(),
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

	// UX review #3: unknown/missing nested subcommands must error (exit 1),
	// not print parent help with exit 0. Applied to every parent below the
	// root; bare `abysslink` keeps cobra's conventional help-on-no-args.
	for _, c := range root.Commands() {
		enforceSubcommandErrors(c)
	}

	return root
}

// enforceSubcommandErrors walks the command tree and gives every parent
// command (a command that only groups subcommands and has no Run/RunE of its
// own) a RunE that fails on a missing or unknown subcommand instead of
// printing help and exiting 0. Suggestions mirror cobra's root-level
// "Did you mean this?" behaviour so `abysslink rotate ntfy` points at
// `ntfy-creds` (UX review #3).
func enforceSubcommandErrors(cmd *cobra.Command) {
	for _, c := range cmd.Commands() {
		enforceSubcommandErrors(c)
	}
	if !cmd.HasSubCommands() || cmd.Run != nil || cmd.RunE != nil {
		return
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("missing subcommand for %q\n\nRun '%s --help' to see available subcommands.",
				cmd.CommandPath(), cmd.CommandPath())
		}
		msg := fmt.Sprintf("unknown subcommand %q for %q", args[0], cmd.CommandPath())
		if suggestions := cmd.SuggestionsFor(args[0]); len(suggestions) > 0 {
			msg += "\n\nDid you mean this?\n\t" + strings.Join(suggestions, "\n\t")
		}
		msg += fmt.Sprintf("\n\nRun '%s --help' to see available subcommands.", cmd.CommandPath())
		return errors.New(msg)
	}
}

// rigTargets is the resolved fleet-targeting selection from the persistent
// --rig / --all-rigs flags (CLI-05).
type rigTargets struct {
	rigs    []config.RigConfig // rigs to fan out to (nil when local-only)
	fanOut  bool               // true when --rig or --all-rigs requested remote execution
	rigOnly bool               // true when --rig was used: execute ONLY on the named rig, skip local
}

// resolveRigTargets resolves the persistent --rig / --all-rigs flags against
// the enrolled rig list (CLI-05). Semantics:
//   - --rig X:     fan out to ONLY the enrolled rig named X (error when X is
//     not enrolled or no rigs are enrolled); local execution is skipped.
//   - --all-rigs:  fan out to every enrolled rig (existing behavior).
//   - neither:     local-only execution (fanOut=false).
//   - both:        rejected — mutually exclusive.
func resolveRigTargets(cmd *cobra.Command, enrolled []config.RigConfig) (rigTargets, error) {
	rigName, _ := cmd.Flags().GetString("rig")
	allRigs, _ := cmd.Flags().GetBool("all-rigs")

	if rigName != "" && allRigs {
		return rigTargets{}, fmt.Errorf("--rig and --all-rigs are mutually exclusive")
	}
	if rigName == "" {
		if allRigs {
			return rigTargets{rigs: enrolled, fanOut: true}, nil
		}
		return rigTargets{}, nil
	}

	for _, r := range enrolled {
		if r.Name == rigName {
			return rigTargets{rigs: []config.RigConfig{r}, fanOut: true, rigOnly: true}, nil
		}
	}
	if len(enrolled) == 0 {
		return rigTargets{}, fmt.Errorf("--rig %q: no rigs are enrolled (enroll one with `abysslink rig add`)", rigName)
	}
	names := make([]string, 0, len(enrolled))
	for _, r := range enrolled {
		names = append(names, r.Name)
	}
	return rigTargets{}, fmt.Errorf("--rig %q: unknown rig; enrolled rigs: %s", rigName, strings.Join(names, ", "))
}

// defaultConfigPath returns the default abysslink.yaml location. When neither
// XDG_CONFIG_HOME nor the home directory can be resolved it returns "" — the
// caller (loadCmdContext) turns that into an explicit error rather than
// silently resolving a relative ".config/..." path against the cwd (I4).
func defaultConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "abysslink", "abysslink.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "abysslink", "abysslink.yaml")
}
