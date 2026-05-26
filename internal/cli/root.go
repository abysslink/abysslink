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
		slog.Error("abysslink error", "err", err)
		return 1
	}
	return 0
}

func buildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "abysslink",
		Short: "Automates a paranoid-by-default phone-to-laptop remote-control setup over Tailscale",
		Long: `Abysslink is a single command that produces a working, auditable, paranoid-by-default
phone-to-laptop remote setup on any macOS or Linux machine.

Run 'abysslink init' to get started.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Persistent flags — available to all subcommands.
	pf := root.PersistentFlags()
	pf.String("config", defaultConfigPath(), "path to abysslink.yaml")
	pf.Bool("dry-run", false, "show planned changes without applying")
	pf.Bool("apply", false, "execute planned changes")
	pf.Bool("yes", false, "skip interactive confirmations")
	pf.Bool("json", false, "output as JSON")
	pf.BoolP("verbose", "v", false, "enable debug logging")
	pf.Bool("explain", false, "print why each action is taken with spec citations")

	// Register all subcommands.
	root.AddCommand(
		newInitCmd(),
		newUpCmd(),
		newStatusCmd(),
		newDoctorCmd(),
		newRepairCmd(),
		newEnrollCmd(),
		newNotifyCmd(),
		newWatchCmd(),
		newACLCmd(),
		newLockCmd(),
		newRotateCmd(),
		newEnableCmd(),
		newDisableCmd(),
		newLogsCmd(),
		newBackupCmd(),
		newThreatModelCmd(),
		newPanicCmd(),
		newUninstallCmd(),
		newUpgradeCmd(),
		newVersionCmd(),
		newDaemonCmd(),
	)

	return root
}

func defaultConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "abysslink", "abysslink.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "abysslink", "abysslink.yaml")
}
