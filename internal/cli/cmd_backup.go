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
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/spf13/cobra"
)

func newBackupCmd() *cobra.Command {
	backup := &cobra.Command{
		Use:   "backup",
		Short: "List and restore backups of files abysslink has changed",
	}
	backup.AddCommand(newBackupLsCmd(), newBackupRestoreCmd())
	return backup
}

func newBackupLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List files abysslink has modified and their available backups",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := newPrinter(cmd)

			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("backup ls: %w", err)
			}
			targets, err := audit.MutatedTargets(logPath)
			if err != nil {
				return fmt.Errorf("backup ls: %w", err)
			}
			if len(targets) == 0 {
				printerInfo(p, "No modifications recorded — nothing to back up or restore.")
				return nil
			}

			printerInfo(p, styleBold.Render("Files modified by abysslink"))
			printerInfo(p, "")
			for _, t := range targets {
				baks, _ := audit.Backups(t)
				switch len(baks) {
				case 0:
					printerInfo(p, fmt.Sprintf("  %s  %s", t, styleMuted.Render("(created by abysslink — no prior version)")))
				default:
					latest := filepath.Base(baks[len(baks)-1])
					ts := strings.TrimPrefix(latest, filepath.Base(t)+".bak.")
					printerInfo(p, fmt.Sprintf("  %s  %s", t, styleMuted.Render(fmt.Sprintf("(%d backup(s), latest %s)", len(baks), ts))))
				}
			}
			printerInfo(p, "")
			printerInfo(p, styleMuted.Render("Restore one with: abysslink backup restore <path>"))
			return nil
		},
	}
}

func newBackupRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore <path>",
		Short: "Restore a file to its most recent abysslink backup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			target := args[0]

			baks, err := audit.Backups(target)
			if err != nil {
				return fmt.Errorf("backup restore: %w", err)
			}
			if len(baks) == 0 {
				return fmt.Errorf("backup restore: no backup found for %q", target)
			}
			latest := baks[len(baks)-1]

			original, _ := cmd.Flags().GetBool("original")
			if original {
				latest = baks[0]
			}

			if cc.dryRun {
				printerInfo(p, fmt.Sprintf("[plan] would restore %s from %s (use --apply)", target, latest))
				return nil
			}

			ok, err := confirmAction(ctx, cc, fmt.Sprintf("Restore %s from %s?", target, latest))
			if err != nil {
				return err
			}
			if !ok {
				printerInfo(p, "Aborted.")
				return nil
			}

			if err := audit.Restore(target, latest); err != nil {
				return fmt.Errorf("backup restore: %w", err)
			}
			printerInfo(p, fmt.Sprintf("Restored %s from %s", target, latest))
			return nil
		},
	}
	cmd.Flags().Bool("original", false, "Restore the earliest (pre-abysslink) backup instead of the most recent")
	return cmd
}
