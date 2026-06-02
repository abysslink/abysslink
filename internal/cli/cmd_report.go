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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/spf13/cobra"
)

// rigReachability is the per-rig reachability row in a report. RigID is ALWAYS
// the opaque SHA-256 hash of the rig name (metrics.OpaqueRigLabel) — the raw
// Name, Hostname, and NtfyTopic are never serialised (T-18-13, OBS-04).
type rigReachability struct {
	RigID     string `json:"rig_id"`
	Reachable bool   `json:"reachable"`
}

// newRigReachability builds a rigReachability with an opaque rig id.
func newRigReachability(rigName string, reachable bool) rigReachability {
	return rigReachability{RigID: metrics.OpaqueRigLabel(rigName), Reachable: reachable}
}

// reportOutput is the JSON-serialisable posture snapshot emitted by
// `abysslink report --json`. It bundles doctor findings, the audit tail, and
// (when --all-rigs is set) per-rig reachability. No raw rig identifiers appear.
type reportOutput struct {
	Findings     []doctorFinding   `json:"findings"`
	AuditEntries []audit.Entry     `json:"audit_entries"`
	RigResults   []rigReachability `json:"rig_results,omitempty"`
}

// reportExitCode maps the maximum finding severity to a process exit code,
// matching `abysslink doctor`: 0 clean, 1 on any WARN, 2 on any FATAL.
func reportExitCode(findings []modules.Finding) int {
	code := exitCodeOK
	for _, f := range findings {
		switch f.Severity {
		case modules.SeverityFatal:
			return exitCodeFatal
		case modules.SeverityWarning:
			code = exitCodeError
		case modules.SeverityOK:
			// no-op
		}
	}
	return code
}

// tailEntrySlice returns the last n entries of an already-loaded slice. A
// negative or zero n returns nil; n >= len returns the whole slice. This is the
// pure, testable counterpart of the log-reading tailEntries in cmd_audit.go.
func tailEntrySlice(entries []audit.Entry, n int) []audit.Entry {
	if n <= 0 {
		return nil
	}
	if n >= len(entries) {
		return entries
	}
	return entries[len(entries)-n:]
}

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Point-in-time security posture snapshot (read-only)",
		Long: `Emit a read-only posture snapshot: all doctor findings, the most
recent audit-log entries, and (with --all-rigs) per-rig reachability.

Exit codes mirror abysslink doctor:
  0  — OK: all checks passed.
  1  — Warning: issues found; review recommended.
  2  — Fatal: fail-closed or fatal issue; system is not safe to use.`,
		Example: `  # Human-readable posture snapshot
  abysslink report

  # Machine-readable JSON (ANSI-free), last 50 audit entries
  abysslink --json report --tail 50

  # Fan out reachability to all enrolled rigs
  abysslink report --all-rigs`,
		RunE: runReport,
	}
	cmd.Flags().Int("tail", 20, "last N audit log entries to include")
	// --all-rigs and --strict are persistent root flags (see root.go) consumed
	// by every fan-out command; report reuses them rather than redefining them.
	return cmd
}

// runReport is the report command body. It collects doctor findings (modules +
// backend/fleet + audit + metrics), tails the audit log, optionally fans out to
// rigs, and emits JSON or a human summary. It returns an exitError so the CLI
// exits 0/1/2 by max severity.
func runReport(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	cc, err := loadCmdContext(cmd)
	if err != nil {
		return err
	}
	p := newPrinter(cmd)

	tailN, _ := cmd.Flags().GetInt("tail")
	// --all-rigs and --strict are persistent root flags.
	allRigs, _ := cmd.Flags().GetBool("all-rigs")
	strict, _ := cmd.Flags().GetBool("strict")

	findings, err := collectReportFindings(ctx, cc)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	entries := collectAuditTail(tailN)

	var rigResults []rigReachability
	if allRigs && len(cc.cfg.Rigs) > 0 {
		rigResults = collectRigReachability(ctx, cc, strict)
	}

	exitCode := reportExitCode(findings)

	if cc.jsonOut {
		p.PrintJSON(reportOutput{
			Findings:     buildDoctorFindings(findings),
			AuditEntries: entries,
			RigResults:   rigResults,
		})
		if exitCode != exitCodeOK {
			return &exitError{code: exitCode}
		}
		return nil
	}

	printReportHuman(p, findings, entries, rigResults)
	if exitCode != exitCodeOK {
		return &exitError{code: exitCode}
	}
	return nil
}

// collectReportFindings gathers the full doctor finding set: per-module Detect,
// backend + fleet, supply-chain, audit posture, and metrics posture.
func collectReportFindings(ctx context.Context, cc *cmdContext) ([]modules.Finding, error) {
	deps, err := buildDeps(ctx, cc)
	if err != nil {
		return nil, err
	}
	mods := allModules(deps)
	r, err := modules.NewRunner(mods, cc.cfg)
	if err != nil {
		return nil, err
	}
	findings, err := r.Doctor(ctx)
	if err != nil {
		return nil, err
	}
	findings = appendBackendAndFleetFindings(ctx, cc, deps.Keychain, findings)
	findings = append(findings, supplyChainFindings(ctx, cc.runner, version, "")...)
	if logPath, lpErr := auditDefaultLogPath(); lpErr == nil {
		findings = append(findings, auditDoctorFindings(ctx, logPath, deps.Keychain)...)
	} else {
		slog.Warn("report: audit log path unavailable; skipping audit checks", "err", lpErr)
	}
	findings = append(findings, metricsDoctorFindings(cc.cfg, deps.MetricsRegistry(), resolveTailnetIP(ctx, cc))...)
	return findings, nil
}

// collectAuditTail reads the audit log and returns the last tailN entries.
func collectAuditTail(tailN int) []audit.Entry {
	logPath, err := auditDefaultLogPath()
	if err != nil {
		slog.Warn("report: audit log path unavailable", "err", err)
		return nil
	}
	entries, rerr := audit.ReadLog(logPath)
	if rerr != nil {
		slog.Warn("report: read audit log failed", "err", rerr)
		return nil
	}
	return tailEntrySlice(entries, tailN)
}

// collectRigReachability fans out `status --json` to all enrolled rigs and
// returns opaque per-rig reachability rows.
func collectRigReachability(ctx context.Context, cc *cmdContext, strict bool) []rigReachability {
	const perRigTimeout = 30 * time.Second
	results, _ := fleet.FanOut(ctx, cc.runner, cc.cfg.Rigs, perRigTimeout, strict, []string{"status", "--json"})
	rows := make([]rigReachability, 0, len(results))
	for _, res := range results {
		rows = append(rows, newRigReachability(res.Rig.Name, res.Reachable))
	}
	return rows
}

// printReportHuman renders the human-readable posture snapshot via the Printer.
func printReportHuman(p Printer, findings []modules.Finding, entries []audit.Entry, rigResults []rigReachability) {
	header := styleBold.Render("abysslink report") + "  " + styleMuted.Render("posture snapshot")
	printerInfo(p, styleHeaderBox.Render(header))
	printerInfo(p, "")

	doctorHumanOutput(p, findings)
	printerInfo(p, styleMuted.Render("  "+strings.Repeat("─", 50)))
	printerInfo(p, doctorSeverityCounts(findings))
	printerInfo(p, "")

	printerInfo(p, "  "+styleBold.Render("audit")+"  "+styleMuted.Render(fmt.Sprintf("(%d recent entries)", len(entries))))
	for _, e := range entries {
		printerInfo(p, fmt.Sprintf("    %s  %s  %s",
			styleMuted.Render(e.Time.Format(time.RFC3339)),
			styleBold.Render(e.Op),
			styleMuted.Render(e.Target)))
	}
	printerInfo(p, "")

	if len(rigResults) > 0 {
		printerInfo(p, "  "+styleBold.Render("rigs"))
		for _, rr := range rigResults {
			status := "reachable"
			if !rr.Reachable {
				status = "UNREACHABLE"
			}
			printerInfo(p, fmt.Sprintf("    %s  %s", styleMuted.Render(rr.RigID), styleBold.Render(status)))
		}
		printerInfo(p, "")
	}
}
