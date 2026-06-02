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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/spf13/cobra"
)

// newAuditCmd builds the `abysslink audit` command tree: verify, tail, ls,
// export. All output flows through the Printer abstraction so tests can capture
// it and --json produces ANSI-free structured output.
func newAuditCmd() *cobra.Command {
	a := &cobra.Command{
		Use:   "audit",
		Short: "Inspect and verify the tamper-evident audit log",
	}
	a.AddCommand(newAuditVerifyCmd(), newAuditTailCmd(), newAuditLsCmd(), newAuditExportCmd())
	return a
}

// auditKeychain resolves a keychain store for the audit commands. A missing
// backend is non-fatal: Verify can still walk the hash chain with a nil key
// (skipping the HMAC sig check), and the read-only tail/ls/export paths never
// touch the keychain. Returns nil when no backend is available.
func auditKeychain(ctx context.Context, cc *cmdContext) audit.KeychainStore {
	kc, err := secrets.NewStore(ctx, cc.runner)
	if err != nil {
		slog.Warn("audit: keychain unavailable — HMAC signature checks will be skipped", "err", err)
		return nil
	}
	return kc
}

// runAuditVerify walks the chain and anchor at logPath. It returns nil (exit 0)
// on a clean chain and an *exitError{code:2} on any gap, fork, HMAC mismatch, or
// detected truncation — emitting the exact "CHAIN BROKEN at entry N" string on
// stderr (T-17-09: exit 2 is reserved for genuine chain breaks).
func runAuditVerify(ctx context.Context, p Printer, logPath string, kc audit.KeychainStore) error {
	// WR-02: never let an operator mistake an unverified walk for a real
	// integrity check. When the keychain is unavailable, HMAC signatures (and
	// the anchor) cannot be authenticated, so emit a prominent visible banner —
	// slog.Warn alone is hidden at the default non-TTY level.
	if kc == nil {
		printerError(p, "HMAC checks SKIPPED — keychain unavailable; chain structure walked but signatures NOT authenticated")
	}

	result, err := audit.Verify(ctx, logPath, kc)
	if err != nil {
		// Parse/IO errors are generic failures (exit 1), never exit 2 (T-17-09).
		return fmt.Errorf("audit verify: %w", err)
	}

	if !result.OK {
		printerError(p, fmt.Sprintf("CHAIN BROKEN at entry %d: %s", result.At, result.Reason))
		if result.TruncationDetected {
			printerError(p, "TRUNCATION DETECTED: current entry count is less than the anchor's recorded count")
		}
		return &exitError{code: exitCodeFatal}
	}
	if result.TruncationDetected {
		printerError(p, "TRUNCATION DETECTED: current entry count is less than the anchor's recorded count")
		return &exitError{code: exitCodeFatal}
	}

	// WR-03: distinguish authenticated signatures from skipped/legacy ones so
	// "Chain OK" never overstates what was verified.
	entries, _ := audit.ReadLog(logPath)
	printerInfo(p, fmt.Sprintf("Chain OK — %d entries (%d signatures verified, %d legacy/unsigned/unverifiable skipped)",
		len(entries), result.SigsVerified, result.SigsSkipped))
	if kc == nil {
		// Degraded result: chain walked but unauthenticated. Exit non-zero so
		// scripts do not treat an unverified log as fully trusted (WR-02).
		return &exitError{code: exitCodeError}
	}
	return nil
}

func newAuditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the integrity of the audit log hash chain",
		Example: `  # Verify the tamper-evident audit log chain (exit 2 on a break)
  abysslink audit verify`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit verify: %w", err)
			}
			return runAuditVerify(ctx, p, logPath, auditKeychain(ctx, cc))
		},
	}
}

// tailEntries returns the last n entries of the log. A missing log yields an
// empty slice; n <= 0 or n > len returns all entries.
func tailEntries(logPath string, n int) ([]audit.Entry, error) {
	entries, err := audit.ReadLog(logPath)
	if err != nil {
		return nil, err
	}
	if n <= 0 || n > len(entries) {
		return entries, nil
	}
	return entries[len(entries)-n:], nil
}

// renderEntryTable prints a human-readable table of entries via the Printer.
func renderEntryTable(p Printer, entries []audit.Entry) {
	printerInfo(p, fmt.Sprintf("%-20s  %-8s  %-40s  %s", "TIME", "OP", "TARGET", "DRY_RUN"))
	for _, e := range entries {
		printerInfo(p, fmt.Sprintf("%-20s  %-8s  %-40s  %v",
			e.Time.Format("2006-01-02 15:04:05"), e.Op, e.Target, e.DryRun))
	}
}

// runAuditTail renders the last n entries (table or --json array).
func runAuditTail(p Printer, logPath string, n int, jsonOut bool) error {
	entries, err := tailEntries(logPath, n)
	if err != nil {
		return fmt.Errorf("audit tail: %w", err)
	}
	if len(entries) == 0 {
		printerInfo(p, "No audit entries found")
		return nil
	}
	if jsonOut {
		p.PrintJSON(entries)
		return nil
	}
	renderEntryTable(p, entries)
	return nil
}

func newAuditTailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent audit log entries (default 20)",
		Example: `  # Show the last 20 audit entries
  abysslink audit tail

  # Show the last 5 entries as JSON
  abysslink audit tail --n 5 --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			n, _ := cmd.Flags().GetInt("n")
			jsonOut, _ := cmd.Flags().GetBool("json")
			p := newPrinter(cmd)
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit tail: %w", err)
			}
			return runAuditTail(p, logPath, n, jsonOut)
		},
	}
	cmd.Flags().Int("n", 20, "number of trailing entries to show")
	return cmd
}

// runAuditLs renders all entries (table or --json array).
func runAuditLs(p Printer, logPath string, jsonOut bool) error {
	entries, err := audit.ReadLog(logPath)
	if err != nil {
		return fmt.Errorf("audit ls: %w", err)
	}
	if len(entries) == 0 {
		printerInfo(p, "No audit entries found")
		return nil
	}
	if jsonOut {
		p.PrintJSON(entries)
		return nil
	}
	renderEntryTable(p, entries)
	return nil
}

func newAuditLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List every audit log entry",
		Example: `  # List all audit entries as a table
  abysslink audit ls`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			jsonOut, _ := cmd.Flags().GetBool("json")
			p := newPrinter(cmd)
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit ls: %w", err)
			}
			return runAuditLs(p, logPath, jsonOut)
		},
	}
}

// runAuditExport writes raw JSONL entries (one json object per line) to w.
// Export is for machine consumption, so JSONL is the canonical output regardless
// of the --json flag. A missing log produces no output (empty export).
func runAuditExport(w io.Writer, logPath string) error {
	entries, err := audit.ReadLog(logPath)
	if err != nil {
		return fmt.Errorf("audit export: %w", err)
	}
	for _, e := range entries {
		line, merr := json.Marshal(e)
		if merr != nil {
			return fmt.Errorf("audit export: marshal entry: %w", merr)
		}
		if _, werr := fmt.Fprintf(w, "%s\n", line); werr != nil {
			return fmt.Errorf("audit export: write: %w", werr)
		}
	}
	return nil
}

func newAuditExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export every audit log entry as raw JSONL (one object per line)",
		Example: `  # Export the full audit log as JSONL for archival or analysis
  abysslink audit export > audit.jsonl`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit export: %w", err)
			}
			return runAuditExport(cmd.OutOrStdout(), logPath)
		},
	}
}
