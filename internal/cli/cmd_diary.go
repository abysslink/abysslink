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
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/digest"
	"github.com/spf13/cobra"
)

// newDiaryCmd builds the `abysslink diary` command: a read-only daily digest of
// the audit chain. It writes no audit data and never opens the files the log
// points at — it only reads the audit log. (The shared audit.DefaultLogPath
// helper may MkdirAll the empty state dir on a fresh install, exactly as the
// sibling `logs` command does; no audit entry, backup, or config is written.)
// Mirrors cmd_logs.go / cmd_report.go and, like logs, needs no loadCmdContext
// (no config/rig fan-out).
func newDiaryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diary",
		Short: "Daily digest of audit-chain activity (read-only)",
		Long: `Summarize one local calendar day of the audit chain into operator-meaningful
buckets: actions run, approvals/denies, kill-switch & deadman events, key
rotations, config mutations, backups/restores, and the moments an agent action
was gated on a human.

This is a read-only lens over the audit chain ONLY. It summarizes recorded audit
events; it is NOT a complete activity log — anything that bypasses the audit
chain is invisible to it. Agent recordings ("casts") are surfaced solely from
'arm-run:end' audit entries; there is no separate recording index, so a day with
no armed runs simply reports none.

--json emits a single, byte-stable object (run it twice over the same log and
you get identical bytes): no wall-clock field, categories in a fixed order,
notable events and cast paths stably ordered. The digest renders only op, time,
and an opaque path/id target — never a chain digest or any secret.`,
		Example: `  # Today's digest (local time)
  abysslink diary

  # A specific day
  abysslink diary --date 2026-07-09

  # Machine-readable, byte-stable JSON
  abysslink --json diary --date 2026-07-09`,
		RunE: runDiary,
	}
	cmd.Flags().String("date", "", "day to summarize (YYYY-MM-DD); default today (local)")
	return cmd
}

// runDiary resolves the day window, reads the audit log, computes the digest,
// and renders it. Exit code is always 0 — the diary is informational and never
// escalates severity.
func runDiary(cmd *cobra.Command, _ []string) error {
	p := newPrinter(cmd)
	jsonOut, _ := cmd.Flags().GetBool("json")

	dateStr, _ := cmd.Flags().GetString("date")
	var (
		w   digest.DayWindow
		err error
	)
	if dateStr == "" {
		// Single time.Now, at the command layer — never inside digest.Compute.
		w = digest.TodayWindow(time.Now())
	} else if w, err = digest.ParseWindow(dateStr, time.Local); err != nil {
		return fmt.Errorf("diary: invalid --date %q (want YYYY-MM-DD): %w", dateStr, err)
	}

	// Single source of truth for the log location — never hand-build the path.
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("diary: %w", err)
	}
	// A missing log reads as zero entries (ReadLog returns (nil,nil)) — a fresh
	// install yields a clean empty digest, never a crash.
	entries, err := audit.ReadLog(logPath)
	if err != nil {
		return fmt.Errorf("diary: %w", err)
	}

	d := digest.Compute(entries, w)

	if jsonOut {
		p.PrintJSON(d) // exactly one NDJSON object; no-op on humanPrinter
		return nil
	}
	printDiaryHuman(p, d)
	return nil
}

// activityLabel pairs a category with its curated human label (signal-first,
// routine-last). JSON sorts by slug; the human view uses this curated order —
// data and presentation are deliberately separated.
type activityLabel struct {
	cat   digest.Category
	label string
}

var diaryActivityOrder = []activityLabel{
	{digest.CategoryAction, "actions run"},
	{digest.CategoryApproval, "approvals / denies"},
	{digest.CategoryWaitedOnHuman, "agent waited on human"},
	{digest.CategoryKillSwitch, "kill-switch"},
	{digest.CategoryDeadman, "deadman"},
	{digest.CategoryRotation, "rotations"},
	{digest.CategoryConfigMutation, "config mutations"},
	{digest.CategoryBackup, "backups / restores"},
}

// printDiaryHuman renders the digest through the Printer (never fmt.Println).
// commandHeader self-guards on --json, so this path is only reached in human
// mode.
func printDiaryHuman(p Printer, d digest.Digest) {
	commandHeader(p, "diary", styleMuted.Render(d.Date))

	counts := make(map[string]int, len(d.Categories))
	for _, c := range d.Categories {
		counts[c.Category] = c.Count
	}

	printerInfo(p, fmt.Sprintf("  %s  —  %d entries   (%d applied · %d dry-run)",
		d.Date, d.TotalEntries, d.Applied, d.DryRun))
	printerInfo(p, fmt.Sprintf("  human-gated: %d   (%d approval/deny · %d device-ack)",
		d.HumanGateEvents,
		counts[string(digest.CategoryApproval)],
		counts[string(digest.CategoryWaitedOnHuman)]))
	printerInfo(p, "")

	// activity block: curated order, ALL rows including zeros (a quiet
	// "kill-switch 0 · deadman 0" is reassurance for a security digest).
	printerInfo(p, "  "+styleBold.Render("activity"))
	for _, a := range diaryActivityOrder {
		printerInfo(p, fmt.Sprintf("    %-22s %d", a.label, counts[string(a.cat)]))
	}
	// "other" is unrecognized/future ops — surfaced, never hidden — but only when present.
	if n := counts[string(digest.CategoryOther)]; n > 0 {
		printerInfo(p, fmt.Sprintf("    %-22s %d", "other (unrecognized)", n))
	}
	printerInfo(p, "")

	// Empty day: replace the notable/casts sections with an honest one-liner.
	if d.TotalEntries == 0 {
		printerInfo(p, styleMuted.Render("  no recorded activity on "+d.Date))
		return
	}

	printDiaryNotable(p, d)
	printDiaryCasts(p, d)
}

// printDiaryNotable renders the signal-event block: time · op · target only —
// never a Hash/Sig/digest (the NotableEvent projection cannot carry one).
func printDiaryNotable(p Printer, d digest.Digest) {
	printerInfo(p, "  "+styleBold.Render("notable"))
	if len(d.Notable) == 0 {
		printerInfo(p, styleMuted.Render("    no notable events"))
	} else {
		for _, n := range d.Notable {
			printerInfo(p, fmt.Sprintf("    %s  %-20s %s",
				n.Time.Format("15:04:05"), n.Op, n.Target))
		}
		if d.NotableOmitted > 0 {
			printerInfo(p, styleMuted.Render(fmt.Sprintf("    … %d more omitted", d.NotableOmitted)))
		}
	}
	printerInfo(p, "")
}

// printDiaryCasts renders the agent-recording paths. The header labels the
// provenance ("from arm-run:end") so the operator knows the source is the audit
// chain, not a recording index.
func printDiaryCasts(p Printer, d digest.Digest) {
	printerInfo(p, "  "+styleBold.Render("agent recordings")+"  "+styleMuted.Render("(from arm-run:end)"))
	if len(d.Casts) == 0 {
		printerInfo(p, styleMuted.Render("    no agent runs recorded today"))
		return
	}
	for _, c := range d.Casts {
		printerInfo(p, "    "+c)
	}
}
