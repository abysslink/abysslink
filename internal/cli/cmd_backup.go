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
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/spf13/cobra"
)

func newBackupCmd() *cobra.Command {
	backup := &cobra.Command{
		Use:   "backup",
		Short: "List and restore backups of files abysslink has changed",
	}
	backup.AddCommand(newBackupLsCmd(), newBackupRestoreCmd(), newBackupVerifyCmd())
	return backup
}

// newBackupVerifyCmd verifies the integrity of the audit-log hash chain. It uses
// the SAME audit.Verify path as `abysslink audit verify` (T-17-12: no separate,
// weaker verification), exiting 0 on a clean chain and 2 with
// "CHAIN BROKEN at entry N" on any break or detected truncation.
func newBackupVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the integrity of the audit log chain",
		Example: `  # Verify the tamper-evident audit log chain
  abysslink backup verify`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("backup verify: %w", err)
			}
			return runAuditVerify(ctx, p, logPath, auditKeychain(ctx, cc))
		},
	}
}

func newBackupLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List files abysslink has modified and their available backups",
		Example: `  # List all backed-up files and their modification history
  abysslink backup ls`,
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
		Example: `  # Preview restoring a file (dry-run — no changes)
  abysslink backup restore /etc/ssh/sshd_config

  # Restore a file from its most recent backup
  abysslink backup restore /etc/ssh/sshd_config --apply

  # Override the chain gate for a backup with no chain entry (auditable — A9)
  abysslink backup restore /etc/ssh/sshd_config --accept-unverified-backup --apply`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)

			// Resolve to absolute path; audit.RestoreGated requires absolute dst.
			target, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("backup restore: resolve path %q: %w", args[0], err)
			}

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

			backupLabel := strings.TrimPrefix(filepath.Base(latest),
				filepath.Base(target)+".bak.")

			if cc.dryRun {
				printerInfo(p, fmt.Sprintf("[plan] would restore %s from backup %s (use --apply)", target, backupLabel))
				// Also show the diff preview in dry-run so the user sees what will change.
				if previewErr := restoreDiffPreview(p, target, latest, backupLabel); previewErr != nil {
					printerInfo(p, styleMuted.Render(fmt.Sprintf("  (diff preview unavailable: %v)", previewErr)))
				}
				return nil
			}

			ok, err := confirmRestore(ctx, p, target, latest, backupLabel, cc.yes, cc.jsonOut)
			if err != nil {
				return err
			}
			if !ok {
				printerInfo(p, "Aborted.")
				return nil
			}

			// AUD-01 / T-24-07-01: gate the restore through the signed chain.
			// Build a *SignedAudit so RestoreGated can walk the chain and verify
			// the backup's hash. Fail-closed: if the keychain is unavailable, the
			// chain cannot be consulted at all — we refuse even with
			// --accept-unverified-backup, because the gate itself requires a
			// working keychain. Do not fall back to the unchained audit.Restore.
			acceptUnverified, _ := cmd.Flags().GetBool("accept-unverified-backup")
			sa, saErr := cmdSignedAudit(ctx, cc)
			if saErr != nil {
				return fmt.Errorf("backup restore: chain-verified restore requires a keychain (%w); "+
					"--accept-unverified-backup does not bypass a missing keychain", saErr)
			}
			if err := audit.RestoreGated(ctx, target, latest, sa, acceptUnverified); err != nil {
				return fmt.Errorf("backup restore: %w", err)
			}
			printerInfo(p, fmt.Sprintf("Restored %s from backup dated %s", target, backupLabel))
			return nil
		},
	}
	cmd.Flags().Bool("original", false, "Restore the earliest (pre-abysslink) backup instead of the most recent")
	// AUD-01 / A9: override the fail-closed chain gate for unchained backups.
	// Defaults to false — passing this flag records an auditable "restore-unverified"
	// entry and does NOT bypass a missing keychain (chain must be consultable).
	cmd.Flags().Bool("accept-unverified-backup", false,
		"Override the chain-gate and restore a backup without a signed chain entry (records an auditable non-OK entry; does not bypass a missing keychain)")
	return cmd
}

// restoreDiffPreview computes and prints a change summary before a restore.
// It reads the current live target (if it exists) and the chosen backup file,
// computes SHA-256 hashes for each, and prints a diff summary showing how the
// content will change. It does NOT mutate anything — callers invoke this for
// both dry-run and interactive preview before confirming.
//
// If the target does not exist (i.e. abysslink created it and there is no
// prior version), the preview notes that fact instead of erroring.
func restoreDiffPreview(p Printer, target, backupPath, backupLabel string) error {
	// Read backup content (must exist).
	backupBytes, err := os.ReadFile(backupPath) //nolint:gosec // G304: backupPath is an audit backup path resolved internally, not user input
	if err != nil {
		return fmt.Errorf("read backup %s: %w", backupPath, err)
	}
	backupHash := fmt.Sprintf("%x", sha256.Sum256(backupBytes))

	// Read current target content (may not exist).
	var currentBytes []byte
	var currentHash string
	currentMissing := false
	currentBytes, err = os.ReadFile(target) //nolint:gosec // G304: target is a path from a trusted audit-log entry, not user input
	if err != nil {
		if os.IsNotExist(err) {
			currentMissing = true
		} else {
			return fmt.Errorf("read current %s: %w", target, err)
		}
	} else {
		currentHash = fmt.Sprintf("%x", sha256.Sum256(currentBytes))
	}

	printerInfo(p, "")
	printerInfo(p, styleBold.Render("Restore preview"))
	printerInfo(p, "")

	if currentMissing {
		printerInfo(p, fmt.Sprintf(
			"  %s does not exist (created by abysslink).", target))
		printerInfo(p, fmt.Sprintf(
			"  Restoring backup dated %s (sha256: %s…)",
			backupLabel, backupHash[:12]))
		printerInfo(p, "")
		return nil
	}

	// Same content: nothing to change.
	if currentHash == backupHash {
		printerInfo(p, fmt.Sprintf(
			"  %s and backup dated %s are identical (sha256: %s…).",
			target, backupLabel, backupHash[:12]))
		printerInfo(p, "")
		return nil
	}

	// Show per-file hashes and a concise line-diff summary.
	printerInfo(p, fmt.Sprintf(
		"  Will replace  %s", target))
	printerInfo(p, fmt.Sprintf(
		"  Current sha256: %s…", currentHash[:12]))
	printerInfo(p, fmt.Sprintf(
		"  Backup sha256 : %s…  (dated %s)", backupHash[:12], backupLabel))
	printerInfo(p, "")

	// Print a simple line-level diff summary (first few differing lines).
	printLineDiffSummary(p, currentBytes, backupBytes)
	return nil
}

// printLineDiffSummary prints a concise summary of the first changed lines
// between current and backup bytes. It does not require an external diff library.
// At most maxDiffLines changed lines are shown; excess is summarised.
func printLineDiffSummary(p Printer, current, backup []byte) {
	const maxDiffLines = 6

	currentLines := strings.Split(string(current), "\n")
	backupLines := strings.Split(string(backup), "\n")

	shown := 0
	maxLines := len(currentLines)
	if len(backupLines) > maxLines {
		maxLines = len(backupLines)
	}

	for i := 0; i < maxLines && shown < maxDiffLines; i++ {
		cur := ""
		bak := ""
		if i < len(currentLines) {
			cur = currentLines[i]
		}
		if i < len(backupLines) {
			bak = backupLines[i]
		}
		if cur == bak {
			continue
		}
		if cur != "" {
			printerInfo(p, styleMuted.Render(fmt.Sprintf("  - %s", cur)))
		}
		if bak != "" {
			printerInfo(p, styleInfo.Render(fmt.Sprintf("  + %s", bak)))
		}
		shown++
	}

	if maxLines > maxDiffLines+shown {
		printerInfo(p, styleMuted.Render(fmt.Sprintf(
			"  … and %d more line(s) differ.", maxLines-maxDiffLines-shown)))
	}
	printerInfo(p, "")
}

// confirmRestore prints the diff preview and asks the user to confirm the
// restore. With --yes it returns (true, nil) immediately. In a non-interactive
// context (no TTY, no --yes) it returns errMissingInput so the command exits
// non-zero — a piped/CI invocation must be able to tell the restore did not
// happen (never a silent "Aborted." + exit 0).
func confirmRestore(ctx context.Context, p Printer, target, backupPath, backupLabel string, yes, jsonOut bool) (bool, error) {
	if err := restoreDiffPreview(p, target, backupPath, backupLabel); err != nil {
		printerInfo(p, styleMuted.Render(fmt.Sprintf("  (diff preview unavailable: %v)", err)))
	}

	if yes {
		return true, nil
	}

	// Fail closed under --json (or any non-interactive context): a destructive
	// restore must never render a huh confirm into the machine-readable JSON
	// stream or hang waiting for a TTY that is not there. Previously this passed
	// interactive(false, false), which ignored --json and would prompt on a TTY
	// even with --json set.
	if !interactive(yes, jsonOut) {
		return false, errMissingInput("yes")
	}

	return tui.Confirm(ctx,
		fmt.Sprintf("Restore %s from backup dated %s?", target, backupLabel),
		yes)
}
