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
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
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
	// unknown is the WR-05 honest-unknown flag: the probe could not run (a
	// non-timeout transport error), so reachability is genuinely undetermined
	// rather than a fabricated definite offline. It is rendered as "unknown" in
	// the human output and is intentionally NOT serialised (the JSON contract
	// keeps reachable as a binary flag).
	unknown bool `json:"-"`
}

// newRigReachability builds a rigReachability with an opaque rig id.
func newRigReachability(rigName string, reachable bool) rigReachability {
	return rigReachability{RigID: metrics.OpaqueRigLabel(rigName), Reachable: reachable}
}

// rigReachabilityFromResult maps a fleet result to an opaque reachability row,
// honouring the WR-05 tri-state: a transport error that is NOT a clean timeout
// means the probe never ran — render that as honest "unknown", never a
// fabricated definite "UNREACHABLE" (mirrors fleet_status.go remoteRigStatuses).
func rigReachabilityFromResult(res fleet.RigResult) rigReachability {
	row := newRigReachability(res.Rig.Name, res.Reachable)
	if !res.Reachable && res.Err != nil && !errors.Is(res.Err, context.DeadlineExceeded) {
		row.unknown = true
	}
	return row
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
	// --rig / --all-rigs and --strict are persistent root flags (CLI-05).
	strict, _ := cmd.Flags().GetBool("strict")
	rt, rigErr := resolveRigTargets(cmd, cc.cfg.Rigs)
	if rigErr != nil {
		return rigErr
	}

	findings, err := collectReportFindings(ctx, cc)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	entries := collectAuditTail(tailN)

	var rigResults []rigReachability
	var fanErr error
	if rt.fanOut && len(rt.rigs) > 0 {
		rigResults, fanErr = collectRigReachability(ctx, cc, strict, rt.rigs)
	}

	exitCode := reportExitCode(findings)
	// Fleet honesty: under --strict an unreachable rig must fail the run (exit 2),
	// matching `status`/`doctor`. Previously the fan-out error was discarded
	// (`results, _ := fleet.FanOut(...)`), so `report --all-rigs --strict` could
	// exit 0 with an offline rig — a fabricated all-clear in CI.
	if strict && fanErr != nil && exitCode < exitCodeFatal {
		exitCode = exitCodeFatal
	}

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
// backend + fleet, supply-chain, audit posture, metrics posture, web UI posture
// (P19), security audit posture (P20), and optional-module posture (P21). The
// ordering and signatures mirror cmd_doctor.go RunE exactly so the 3 sec-*
// cross-ref aliases (sec-metrics-bind, sec-webui-bind, sec-audit-anchor-age)
// reuse the pre-computed met/webui/audit slices and the underlying checks run
// exactly once (B2 / RESEARCH Pitfall 3).
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

	// Audit posture (Phase 17) — captured for the sec-audit-anchor-age alias.
	var auditFinds []modules.Finding
	if logPath, lpErr := auditDefaultLogPath(); lpErr == nil {
		auditFinds = auditDoctorFindings(logPath, deps.Keychain)
		findings = append(findings, auditFinds...)
	} else {
		slog.Warn("report: audit log path unavailable; skipping audit checks", "err", lpErr)
	}

	// Metrics posture (Phase 18) — captured for the sec-metrics-bind alias.
	metFinds := metricsDoctorFindings(cc.cfg, deps.MetricsRegistry(), resolveTailnetIP(ctx, cc))
	findings = append(findings, metFinds...)

	// Web UI posture (Phase 19) — captured for the sec-webui-bind alias.
	webuiFinds := webuiDoctorFindings(ctx, cc.cfg)
	findings = append(findings, webuiFinds...)

	// Security audit posture (Phase 20): 18 sec-* checks. The 3 cross-ref aliases
	// reuse the met/webui/audit slices above so the underlying checks run once.
	findings = append(findings, secDoctorFindings(ctx, cc, deps, false, metFinds, webuiFinds, auditFinds)...)

	// Optional-module posture (Phase 21, MOD3-01..05).
	findings = append(findings, mod3DoctorFindings(ctx, cc.cfg, cc.runner)...)

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

// collectRigReachability fans out `status --json` to the targeted rigs (all
// enrolled rigs under --all-rigs, a single rig under --rig, CLI-05) and
// returns opaque per-rig reachability rows.
// collectRigReachability fans out and returns the opaque reachability rows plus
// the fan-out error. Under --strict the error is non-nil when any rig was
// unreachable; the caller escalates the exit code on it (the error was
// previously discarded). Non-strict fan-out only errors on a pre-flight
// validation failure.
func collectRigReachability(ctx context.Context, cc *cmdContext, strict bool, rigs []config.RigConfig) ([]rigReachability, error) {
	const perRigTimeout = 30 * time.Second
	results, fanErr := fleet.FanOut(ctx, cc.runner, rigs, perRigTimeout, strict, []string{"status", "--json"})
	rows := make([]rigReachability, 0, len(results))
	for _, res := range results {
		rows = append(rows, rigReachabilityFromResult(res))
	}
	return rows, fanErr
}

// printReportHuman renders the human-readable posture snapshot via the Printer.
func printReportHuman(p Printer, findings []modules.Finding, entries []audit.Entry, rigResults []rigReachability) {
	header := styleTitle.Render("abysslink report") + "  " + styleMuted.Render("posture snapshot")
	printerInfo(p, styleHeaderBox.Render(header))
	printerInfo(p, "")

	doctorHumanOutput(p, findings)
	printerInfo(p, styleMuted.Render("  "+hrule()))
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
			// WR-05 tri-state: never collapse an honest-unknown probe into a
			// definitive UNREACHABLE.
			status := "reachable"
			switch {
			case rr.unknown:
				status = "unknown"
			case !rr.Reachable:
				status = "UNREACHABLE"
			}
			printerInfo(p, fmt.Sprintf("    %s  %s", styleMuted.Render(rr.RigID), styleBold.Render(status)))
		}
		printerInfo(p, "")
	}
}
