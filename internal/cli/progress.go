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
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/modules"
)

// scanRowStr returns a single formatted line for the scan phase.
// Module name is left-padded to 16 chars with bold styling.
// If no actions: checkmark + "up to date"; otherwise arrow + action summary.
func scanRowStr(evt modules.ModuleEvent) string {
	name := styleBold.Render(fmt.Sprintf("%-16s", evt.Module))
	if len(evt.Actions) == 0 {
		return "  " + iconDoneStr() + "  " + name + "  " + styleMuted.Render("up to date")
	}
	return "  " + iconArrowStr() + "  " + name + "  " + styleMuted.Render(actionSummaryStr(evt.Actions))
}

// actionSummaryStr returns a short description of how many actions are planned.
func actionSummaryStr(actions []modules.Action) string {
	switch len(actions) {
	case 1:
		return "1 change: " + actions[0].Description
	default:
		return fmt.Sprintf("%d changes", len(actions))
	}
}

// printPlanDetail prints the section between scan rows and the apply phase.
// It shows a deduplicated action list with optional Explain text.
//
// explain — when true, action.Explain rationale is rendered per-action (gated by --explain flag).
// When false, Explain text is suppressed to keep output concise.
func printPlanDetail(p Printer, actions []modules.Action, _ []modules.Finding, dryRun bool, explain bool) {
	unique := uniqueActions(actions)
	if len(unique) == 0 {
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("System is already converged — nothing to do."))
		return
	}

	printerInfo(p, "  "+styleMuted.Render(strings.Repeat("─", 48)))

	var countLine string
	if dryRun {
		countLine = styleBold.Render(fmt.Sprintf("  %d changes planned", len(unique)))
	} else {
		countLine = styleBold.Render(fmt.Sprintf("  %d changes to apply", len(unique)))
	}
	printerInfo(p, countLine)
	printerInfo(p, "")

	for _, action := range unique {
		line := "  " + iconArrowStr() + "  " + styleBold.Render(fmt.Sprintf("%-12s", action.Module)) + "  " + styleMuted.Render(action.Description)
		printerInfo(p, line)

		// Gate rationale on --explain flag (G8 requirement).
		if explain && action.Explain != "" {
			for _, wrappedLine := range wordWrap(action.Explain, 60) {
				printerInfo(p, "  "+strings.Repeat(" ", 16)+styleMuted.Render(wrappedLine))
			}
		}
	}
	printerInfo(p, "")

	if dryRun {
		printerInfo(p, "  Run  "+styleCode.Render("abysslink up --apply")+fmt.Sprintf("  to apply %d changes.", len(unique)))
	}
}

// applyRowStr returns a single formatted apply-phase row with a [N/M] counter.
func applyRowStr(evt modules.ModuleEvent) string {
	counter := styleMuted.Render(fmt.Sprintf("[%d/%d]", evt.Index, evt.Total))
	mod := styleBold.Render(fmt.Sprintf("  %-14s", evt.Module))

	var status string
	switch {
	case evt.ApplyErr != nil:
		status = iconWarnStr() + "  " + styleWarn.Render(firstFindingMessage(evt.Findings, evt.ApplyErr))
	case hasFindingSeverity(evt.Findings, modules.SeverityFatal):
		status = iconFatalStr() + "  " + styleFatal.Render(firstFindingMessage(evt.Findings, nil))
	case hasFindingSeverity(evt.Findings, modules.SeverityWarning):
		status = iconWarnStr() + "  " + styleWarn.Render(firstFindingMessage(evt.Findings, nil))
	default:
		status = iconDoneStr() + "  " + styleMuted.Render("done")
	}

	return "  " + counter + mod + "  " + status
}

// printFinalSummary prints the final summary line after ApplyAll completes.
//
// U7 honesty contract: "System converged · N applied · 0 errors" is printed
// ONLY when the apply finished without an error AND no fatal findings were
// emitted. On a failing run the line reports the planned count (we cannot
// claim everything applied) and a non-zero error count — never a false green
// right before the command exits non-zero.
func printFinalSummary(p Printer, actions []modules.Action, findings []modules.Finding, elapsed time.Duration, applyErr error) {
	errCount := countFindingSeverity(findings, modules.SeverityFatal)
	plannedCount := len(uniqueActions(actions))
	elapsedStr := fmt.Sprintf("%.1fs", elapsed.Seconds())

	printerInfo(p, "  "+styleMuted.Render(strings.Repeat("─", 48)))

	if errCount == 0 && applyErr == nil {
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render(
			fmt.Sprintf("System converged  ·  %d applied  ·  0 errors  ·  %s", plannedCount, elapsedStr)))
		return
	}
	// An apply error without a fatal finding still counts as ≥1 error.
	if applyErr != nil && errCount == 0 {
		errCount = 1
	}
	printerInfo(p, "  "+iconWarnStr()+"  "+styleWarn.Render(
		fmt.Sprintf("Finished with errors  ·  %d planned  ·  %d error(s)  ·  %s", plannedCount, errCount, elapsedStr)))
}

// --- private helpers ---

// hasFindingSeverity returns true if any finding has the given severity.
func hasFindingSeverity(findings []modules.Finding, sev modules.Severity) bool {
	for _, f := range findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

// firstFindingMessage returns the first finding's Message, or fallback.Error()
// if findings are empty and fallback is non-nil, or "error" otherwise.
func firstFindingMessage(findings []modules.Finding, fallback error) string {
	if len(findings) > 0 {
		return firstLine(findings[0].Message)
	}
	if fallback != nil {
		return firstLine(fallback.Error())
	}
	return "error"
}

// firstLine returns the first line of s, trimmed and capped at 60 runes. A
// multi-line shell-out error (e.g. brew/systemctl stderr) must never blow out a
// single live-table row or interleave with the spinner frame (WR-08).
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 60 {
		return string(r[:57]) + "..."
	}
	return s
}

// countFindingSeverity counts findings at the given severity.
func countFindingSeverity(findings []modules.Finding, sev modules.Severity) int {
	count := 0
	for _, f := range findings {
		if f.Severity == sev {
			count++
		}
	}
	return count
}

// uniqueActions returns a deduplicated slice of actions by Module+Description key.
func uniqueActions(actions []modules.Action) []modules.Action {
	seen := map[string]bool{}
	var result []modules.Action
	for _, a := range actions {
		key := a.Module + "|" + a.Description
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, a)
	}
	return result
}

// wordWrap splits text into lines of at most maxWidth characters, breaking on
// word boundaries. Returns a slice of lines (never empty if text is non-empty).
func wordWrap(text string, maxWidth int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}

	var lines []string
	var current strings.Builder

	for _, word := range words {
		if current.Len() == 0 {
			current.WriteString(word)
		} else if current.Len()+1+len(word) > maxWidth {
			lines = append(lines, current.String())
			current.Reset()
			current.WriteString(word)
		} else {
			current.WriteByte(' ')
			current.WriteString(word)
		}
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}
