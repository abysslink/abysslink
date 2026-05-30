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

	"github.com/spf13/cobra"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/modules/claudecode"
)

// newClaudeCodeCmd returns the "claudecode" parent command that groups all
// Claude Code integration subcommands.
func newClaudeCodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claudecode",
		Short: "Manage the Claude Code integration",
	}
	cmd.AddCommand(newClaudeCodeDisableCmd())
	return cmd
}

// newClaudeCodeDisableCmd returns the "claudecode disable" subcommand that
// strips abysslink notify hooks from ~/.claude/settings.json.
func newClaudeCodeDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Remove abysslink notify hooks from ~/.claude/settings.json (dry-run by default)",
		Example: `  # Preview which hooks would be removed (dry-run — no changes)
  abysslink claudecode disable

  # Remove the hooks immediately
  abysslink claudecode disable --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)

			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("claudecode disable: audit log path: %w", err)
			}

			deps := modules.Deps{
				Cfg:    cc.cfg,
				Runner: cc.runner,
				Audit:  audit.New(logPath),
				// Platform, Keychain, Prompt are not needed for RemoveHooks.
			}

			mod := claudecode.New(deps)
			removed, err := mod.RemoveHooks(cmd.Context(), cc.dryRun)
			if err != nil {
				return fmt.Errorf("claudecode disable: %w", err)
			}

			printerInfo(p, styleBold.Render("abysslink claudecode disable")+"  "+styleMuted.Render("remove notify hooks"))
			printerInfo(p, "")

			if len(removed) == 0 {
				printerInfo(p, "  No abysslink notify hooks found in ~/.claude/settings.json.")
				return nil
			}

			for _, desc := range removed {
				printerInfo(p, fmt.Sprintf("  remove  %s", desc))
			}
			printerInfo(p, "")

			if cc.dryRun {
				printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
				return nil
			}

			printerInfo(p, styleSuccess.Render(fmt.Sprintf("Done. Removed %d hook(s) from ~/.claude/settings.json.", len(removed))))
			return nil
		},
	}
}
