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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/spf13/cobra"
)

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Reverse every change abysslink made, restoring files from backups (dry-run by default)",
		Example: `  # Preview what uninstall would reverse (dry-run — no changes)
  abysslink uninstall

  # Reverse all changes (restore from backups)
  abysslink uninstall --apply

  # Also remove packages and audit log (IRREVERSIBLE — extra confirm required)
  abysslink uninstall --apply --purge`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			purge, _ := cmd.Flags().GetBool("purge")

			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}
			plan, err := audit.PlanReverse(logPath)
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}

			printerInfo(p, styleTitle.Render("abysslink uninstall")+"  "+styleMuted.Render("reverse all changes"))
			printerInfo(p, "")
			printReversePlan(p, plan)
			if !cc.jsonOut {
				printerInfo(p, "")
				printerInfo(p, tui.Note(tui.NoteDanger, "Uninstall reverses every change abysslink made", []string{
					"SSH, firewall, sleep, ntfy and module config are restored from their backups.",
					"With --purge the audit log and backups are also deleted — that is irreversible.",
				}))
			}

			if cc.dryRun {
				printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
				if purge {
					printerInfo(p, styleMuted.Render("--purge would also remove ~/.config/abysslink and the state dir (audit log + backups)."))
				} else {
					printerInfo(p, styleMuted.Render("~/.config/abysslink and the state dir (audit log + backups) would be kept. Use --purge to remove them."))
				}
				return nil
			}

			ok, purgeOK, err := uninstallConfirmSeq(ctx, p, plan, purge, cc.yes)
			if err != nil {
				return err
			}
			if !ok {
				printerInfo(p, "Aborted.")
				return nil
			}

			manifest, err := audit.Reverse(logPath, false)
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}

			// When purge was confirmed, honour it; when --yes bypassed, use the
			// purge flag from the command line (already set).
			if purge && !purgeOK {
				// This branch should not happen in practice: purgeOK is always true
				// when purge=true + yes=true, and false when user declined the
				// second confirm — in which case we still run Reverse but skip purge.
				purge = false
			}

			failures := printReverseManifest(p, manifest) + removeAbysslinkDirs(p, purge)
			if failures > 0 {
				return fmt.Errorf("uninstall: %d action(s) failed", failures)
			}
			printerInfo(p, "")
			printerInfo(p, styleSuccess.Render("Uninstall complete."))
			return nil
		},
	}
	cmd.Flags().Bool("purge", false, "Also remove ~/.config/abysslink and the state dir (audit log + backups)")
	return cmd
}

// printReversePlan lists the planned reverse actions. Actionable actions
// (restore/delete) are printed one per line; skips (targets already absent —
// nothing to reverse) are folded by folder so a flood of transient paths reads
// as a few summary lines instead of one line per file.
func printReversePlan(p Printer, plan []audit.ReverseAction) {
	if len(plan) == 0 {
		printerInfo(p, "  No file mutations recorded in the audit log.")
		printerInfo(p, "")
		return
	}
	var skips []string
	for _, a := range plan {
		if a.Action == "skip" {
			skips = append(skips, a.Target)
			continue
		}
		printerInfo(p, fmt.Sprintf("  %-8s %s", a.Action, a.Target))
	}
	printSkipGroups(p, skips)
	printerInfo(p, "")
}

// printReverseManifest prints the result of each reverse action, including the
// SHA-256 of restored content, and returns the number of failures. Skips are
// folded by folder (see printSkipGroups) so already-absent targets do not flood
// the output.
func printReverseManifest(p Printer, manifest []audit.ReverseAction) int {
	failures := 0
	var skips []string
	for _, a := range manifest {
		if a.Err == nil && a.Action == "skip" {
			skips = append(skips, a.Target)
			continue
		}
		if a.Err != nil {
			failures++
			printerError(p, fmt.Sprintf("  %-8s %s — %v", a.Action, a.Target, a.Err))
			continue
		}
		detail := ""
		if a.Hash != "" {
			detail = styleMuted.Render("sha256:" + a.Hash[:12])
		}
		printerInfo(p, fmt.Sprintf("  %-8s %s  %s", a.Action, a.Target, detail))
	}
	printSkipGroups(p, skips)
	printerInfo(p, "")
	return failures
}

// skipFanout is the maximum number of distinct child folders a directory may
// have before foldSkipDirs collapses its whole subtree into a single summary
// line. A directory that fans out wider than this (e.g. the OS temp root full
// of per-test t.TempDir() fixtures) is almost always machine-generated noise.
const skipFanout = 8

// skipFoldersShown caps how many folded skip folders are listed before the rest
// are summarised as "… and N more folder(s)".
const skipFoldersShown = 12

// printSkipGroups renders skipped (already-absent) targets folded by folder so
// a flood of transient paths reads as a few "<count>  <folder>" lines instead
// of one line per file. Nothing is printed when there are no skips.
func printSkipGroups(p Printer, skips []string) {
	if len(skips) == 0 {
		return
	}
	groups := foldSkipDirs(skips, skipFanout)
	printerInfo(p, fmt.Sprintf("  %-8s %d already-absent target(s) — nothing to reverse, grouped by folder:",
		"skip", len(skips)))
	for i, g := range groups {
		if i == skipFoldersShown {
			printerInfo(p, styleMuted.Render(fmt.Sprintf("           … and %d more folder(s)", len(groups)-skipFoldersShown)))
			break
		}
		printerInfo(p, fmt.Sprintf("           %6d  %s", g.count, g.dir))
	}
}

// dirGroup is a folder and the number of skipped targets folded under it.
type dirGroup struct {
	dir   string
	count int
}

// foldSkipDirs groups skip targets into the fewest folders that still keep
// independent directory subtrees distinct. Single-child directory chains are
// collapsed, and any folder that fans out into more than maxFanout distinct
// child folders is summarised as a single subtree line. This turns a flood of
// unique temp-dir paths (e.g. thousands of t.TempDir() fixtures under the OS
// temp root) into one "<count>  <folder>" line instead of N lines. Results are
// sorted by count (desc) then path.
func foldSkipDirs(targets []string, maxFanout int) []dirGroup {
	type node struct {
		children map[string]*node
		count    int // total files in this subtree
		direct   int // files whose immediate dir is this node
	}
	if len(targets) == 0 {
		return nil
	}
	newNode := func() *node { return &node{children: map[string]*node{}} }

	root := newNode()
	for _, t := range targets {
		dir := filepath.ToSlash(filepath.Dir(t))
		n := root
		n.count++
		for s := range strings.SplitSeq(dir, "/") {
			c := n.children[s]
			if c == nil {
				c = newNode()
				n.children[s] = c
			}
			n = c
			n.count++
		}
		n.direct++
	}

	joinDir := func(segs []string) string {
		if d := strings.Join(segs, "/"); d != "" {
			return d
		}
		return "/"
	}

	var groups []dirGroup
	var walk func(n *node, segs []string)
	walk = func(n *node, segs []string) {
		// Collapse single-child chains that hold no files of their own.
		for len(n.children) == 1 && n.direct == 0 {
			for s, c := range n.children {
				segs = append(segs, s)
				n = c
			}
		}
		// Emit one line for a leaf or a wide, machine-generated fan-out.
		if len(n.children) == 0 || len(n.children) > maxFanout {
			groups = append(groups, dirGroup{dir: joinDir(segs), count: n.count})
			return
		}
		// Files sitting directly in a branching folder get their own line.
		if n.direct > 0 {
			groups = append(groups, dirGroup{dir: joinDir(segs), count: n.direct})
		}
		keys := make([]string, 0, len(n.children))
		for s := range n.children {
			keys = append(keys, s)
		}
		sort.Strings(keys)
		for _, s := range keys {
			walk(n.children[s], append(append([]string{}, segs...), s))
		}
	}
	walk(root, nil)

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].count != groups[j].count {
			return groups[i].count > groups[j].count
		}
		return groups[i].dir < groups[j].dir
	})
	return groups
}

// removeAbysslinkDirs removes the config dir and the state dir (audit log +
// backups) — but ONLY when purge is set (CLI-18): the --purge help and dry-run
// text promise that purge controls directory removal, so a plain --apply keeps
// both ~/.config/abysslink and the state dir. Returns the number of failures.
func removeAbysslinkDirs(p Printer, purge bool) int {
	failures := 0
	if !purge {
		printerInfo(p, styleMuted.Render("  Kept ~/.config/abysslink and the state dir (audit log + backups) for forensics. Use --purge to remove them."))
		return failures
	}
	if cfgDir := abysslinkConfigDir(); cfgDir != "" {
		if err := os.RemoveAll(cfgDir); err != nil {
			printerError(p, fmt.Sprintf("  could not remove %s: %v", cfgDir, err))
			failures++
		} else {
			printerInfo(p, "  removed "+cfgDir)
		}
	}
	if stateDir := abysslinkStateDir(); stateDir != "" {
		if err := os.RemoveAll(stateDir); err != nil {
			printerError(p, fmt.Sprintf("  could not remove %s: %v", stateDir, err))
			failures++
		} else {
			printerInfo(p, "  removed "+stateDir+" (audit log + backups)")
		}
	}
	printerInfo(p, styleMuted.Render("  Third-party packages (tailscale, ntfy, mosh, tmux) are left installed; remove them manually if desired."))
	return failures
}

// uninstallConfirmSeq runs the two-stage confirmation sequence for uninstall --apply.
//
// Stage 1 (always): requires the user to type "UNINSTALL" (ConfirmTyped). Before the
// prompt, a blast-radius summary (count of planned actions) is printed inside a danger
// Note. With --yes the typed gate is bypassed and a slog.Warn records the skip.
//
// Stage 2 (only when purge=true): a second confirm warns that --purge will permanently
// delete the audit log + backups (irreversible). With --yes this second gate is also
// bypassed with a slog.Warn.
//
// Returns (ok, purgeOK, err): ok is false when the UNINSTALL gate is declined (caller
// must abort and not call audit.Reverse). purgeOK is true only when purge=true AND the
// user confirmed the second gate (or --yes was set).
func uninstallConfirmSeq(ctx context.Context, p Printer, plan []audit.ReverseAction, purge, yes bool) (bool, bool, error) {
	// Print blast-radius summary so the user sees the full scope before the prompt.
	nActions := len(plan)
	restores, deletes := 0, 0
	for _, a := range plan {
		switch a.Action {
		case "restore":
			restores++
		case "delete":
			deletes++
		}
	}
	printerInfo(p, fmt.Sprintf(
		"  Blast radius: %d file(s) affected (%d restore, %d delete).",
		nActions, restores, deletes))
	printerInfo(p, "")

	if yes {
		slog.Warn("uninstall --yes: skipping UNINSTALL typed confirmation gate; executing immediately")
	} else if !interactive(false, false) {
		// Non-interactive context (CI, pipe, no TTY): abort without hanging —
		// and exit NON-ZERO so scripts can tell the uninstall did not happen.
		return false, false, errMissingInput("yes")
	}

	// Stage 1: typed UNINSTALL confirm.
	ok, err := tui.ConfirmTyped(ctx,
		"Type UNINSTALL to reverse every change made by abysslink",
		"UNINSTALL",
		yes)
	if err != nil {
		return false, false, err
	}
	if !ok {
		return false, false, nil
	}

	// Stage 2: purge extra confirm.
	if !purge {
		return true, false, nil
	}

	printerInfo(p, "")
	printerInfo(p, styleWarn.Render("  WARNING: --purge will permanently delete the audit log and all backups."))
	printerInfo(p, styleWarn.Render("  This is NOT reversible. There will be no record of changes after this."))
	printerInfo(p, "")

	if yes {
		slog.Warn("uninstall --yes: skipping --purge irreversibility confirmation gate")
		return true, true, nil
	}

	purgeOK, err := tui.Confirm(ctx,
		"--purge permanently deletes the audit log + backups. Proceed?",
		yes)
	if err != nil {
		return true, false, err
	}
	return true, purgeOK, nil
}

// abysslinkConfigDir returns the XDG config dir for abysslink (~/.config/abysslink).
func abysslinkConfigDir() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "abysslink")
}

// abysslinkStateDir returns the XDG state dir for abysslink (~/.local/state/abysslink).
func abysslinkStateDir() string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "abysslink")
}
