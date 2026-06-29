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
	"github.com/abysslink/abysslink/internal/modules"
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
			removeConfigFlag, _ := cmd.Flags().GetBool("remove-config")
			// --purge implies removing the config dir; --remove-config removes the
			// config dir but keeps the state dir. This flag-derived value drives the
			// dry-run preview text; the apply path re-resolves the final scope (config
			// AND state) via the interactive confirm sequence.
			removeConfig := purge || removeConfigFlag

			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}

			// Modules drive surgical reverts (shared files like ~/.claude/settings.json)
			// and resource teardown (the ntfy Docker container). Build them once;
			// their OwnedPaths are excluded from the whole-file reversal so the user's
			// own edits to those shared files are never clobbered.
			mods := uninstallModules(ctx, cc)
			excluded := configRevertPaths(mods)

			plan, err := audit.PlanReverseExcluding(logPath, excluded)
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
					"Shared files you also edited (e.g. ~/.claude/settings.json) keep your changes — only abysslink's additions are removed.",
					"With --purge the audit log and backups are also deleted — that is irreversible.",
				}))
			}

			if cc.dryRun {
				runConfigReverts(ctx, p, mods, true)
				runModuleTeardowns(ctx, p, mods, true)
				printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
				switch {
				case purge:
					printerInfo(p, styleMuted.Render("--purge would also remove ~/.config/abysslink and the state dir (audit log + backups)."))
				case removeConfig:
					printerInfo(p, styleMuted.Render("--remove-config would also remove ~/.config/abysslink (the state dir with audit log + backups is kept)."))
				default:
					printerInfo(p, styleMuted.Render("~/.config/abysslink and the state dir (audit log + backups) would be kept. Use --remove-config or --purge to remove them."))
				}
				return nil
			}

			ok, resolvedConfig, resolvedState, err := uninstallConfirmSeq(ctx, p, plan, purge, removeConfigFlag, cc.yes)
			if err != nil {
				return err
			}
			if !ok {
				printerInfo(p, "Aborted.")
				return nil
			}
			// The confirm sequence resolves the final scope (flags or interactive
			// menu, then the irreversibility gate); use it over the flag-only guess.
			removeConfig = resolvedConfig
			removeState := resolvedState

			manifest, err := audit.ReverseExcluding(logPath, false, excluded)
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}

			failures := printReverseManifest(p, manifest)
			failures += runConfigReverts(ctx, p, mods, false)
			failures += runModuleTeardowns(ctx, p, mods, false)
			failures += removeAbysslinkDirs(p, removeConfig, removeState)
			if failures > 0 {
				return fmt.Errorf("uninstall: %d action(s) failed", failures)
			}
			printerInfo(p, "")
			printerInfo(p, styleSuccess.Render("Uninstall complete."))
			return nil
		},
	}
	cmd.Flags().Bool("purge", false, "Also remove ~/.config/abysslink and the state dir (audit log + backups)")
	cmd.Flags().Bool("remove-config", false, "Also remove ~/.config/abysslink (keeps the state dir: audit log + backups)")
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
		if a.Warning != "" {
			printerInfo(p, styleWarn.Render("           ⚠ "+a.Warning))
		}
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
		if a.Warning != "" {
			printerInfo(p, styleWarn.Render("           ⚠ "+a.Warning))
		}
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

// removeAbysslinkDirs removes the abysslink config dir (~/.config/abysslink) and
// the state dir (audit log + backups). removeConfig and removeState gate each
// independently: a plain --apply keeps both (forensics); --remove-config drops
// the config dir only; --purge drops both. Returns the number of failures.
func removeAbysslinkDirs(p Printer, removeConfig, removeState bool) int {
	failures := 0
	if !removeConfig && !removeState {
		printerInfo(p, styleMuted.Render("  Kept ~/.config/abysslink and the state dir (audit log + backups) for forensics. Use --remove-config or --purge to remove them."))
		return failures
	}
	if removeConfig {
		if cfgDir := abysslinkConfigDir(); cfgDir != "" {
			if err := os.RemoveAll(cfgDir); err != nil {
				printerError(p, fmt.Sprintf("  could not remove %s: %v", cfgDir, err))
				failures++
			} else {
				printerInfo(p, "  removed "+cfgDir+" (config)")
			}
		}
	}
	if removeState {
		if stateDir := abysslinkStateDir(); stateDir != "" {
			if err := os.RemoveAll(stateDir); err != nil {
				printerError(p, fmt.Sprintf("  could not remove %s: %v", stateDir, err))
				failures++
			} else {
				printerInfo(p, "  removed "+stateDir+" (audit log + backups)")
			}
		}
	} else if removeConfig {
		printerInfo(p, styleMuted.Render("  Kept the state dir (audit log + backups) for forensics. Use --purge to remove it too."))
	}
	printerInfo(p, styleMuted.Render("  Third-party packages (tailscale, ntfy, mosh, tmux) are left installed; remove them manually if desired."))
	return failures
}

// uninstallModules builds the module set used for surgical config-reverts and
// resource teardown. Best-effort: returns nil when deps cannot be built (e.g.
// config already removed) so file reversal still proceeds.
func uninstallModules(ctx context.Context, cc *cmdContext) []modules.Module {
	deps, err := buildDeps(ctx, cc)
	if err != nil {
		slog.Warn("uninstall: cannot build module deps; skipping surgical config-revert and resource teardown", "err", err)
		return nil
	}
	return allModules(deps)
}

// configRevertPaths is the set of paths reversed surgically by modules
// (modules.ConfigReverter.OwnedPaths) — e.g. ~/.claude/settings.json. uninstall
// EXCLUDES these from whole-file restore/delete so the user's own edits to those
// shared files are preserved; the module strips only abysslink's additions.
func configRevertPaths(mods []modules.Module) map[string]bool {
	excluded := map[string]bool{}
	for _, mod := range mods {
		if cr, ok := mod.(modules.ConfigReverter); ok {
			for _, path := range cr.OwnedPaths() {
				excluded[path] = true
			}
		}
	}
	return excluded
}

// runConfigReverts runs each module's surgical ReverseConfig — removing only
// abysslink's own additions from shared user files (preserving the rest). With
// dryRun it previews. Best-effort; per-module errors are counted, never fatal.
func runConfigReverts(ctx context.Context, p Printer, mods []modules.Module, dryRun bool) int {
	failures := 0
	for _, mod := range mods {
		cr, ok := mod.(modules.ConfigReverter)
		if !ok {
			continue
		}
		items, err := cr.ReverseConfig(ctx, dryRun)
		if err != nil {
			failures++
			printerError(p, fmt.Sprintf("  config %s: %v", mod.Name(), err))
			continue
		}
		for _, it := range items {
			if dryRun {
				printerInfo(p, "  would remove "+it)
			} else {
				printerInfo(p, "  removed "+it)
			}
		}
	}
	return failures
}

// runModuleTeardowns invokes Teardown on every module that implements
// modules.Teardowner — non-file resources (e.g. the ntfy Docker container) that
// audit-log reversal cannot undo. With dryRun it only previews. Best-effort:
// per-module errors are counted and reported, never fatal to the rest. Returns
// the number of teardown failures.
func runModuleTeardowns(ctx context.Context, p Printer, mods []modules.Module, dryRun bool) int {
	failures := 0
	for _, mod := range mods {
		td, ok := mod.(modules.Teardowner)
		if !ok {
			continue
		}
		items, terr := td.Teardown(ctx, dryRun)
		if terr != nil {
			failures++
			printerError(p, fmt.Sprintf("  teardown %s: %v", mod.Name(), terr))
			continue
		}
		for _, it := range items {
			if dryRun {
				printerInfo(p, "  would remove "+it)
			} else {
				printerInfo(p, "  "+it)
			}
		}
	}
	return failures
}

// Cleanup-scope select labels (shown after the UNINSTALL typed confirm when no
// --purge / --remove-config flag was passed). Discoverability: an interactive
// user never has to know the flag names — they pick from this menu.
const (
	cleanupKeepBoth      = "Keep ~/.config/abysslink and the audit log + backups (recommended)"
	cleanupRemoveConfig  = "Remove ~/.config/abysslink, keep the audit log + backups"
	cleanupRemoveEverything = "Remove everything: config, audit log and backups (IRREVERSIBLE)"
)

// uninstallConfirmSeq runs the confirmation sequence for uninstall --apply and
// resolves what to do with abysslink's own directories.
//
// Stage 1 (always): requires the user to type "UNINSTALL" (ConfirmTyped). Before
// the prompt a blast-radius summary is printed. With --yes the typed gate is
// bypassed (slog.Warn records the skip); a non-interactive run without --yes
// aborts with errMissingInput so scripts exit non-zero.
//
// Stage 2 (cleanup scope): if neither --purge nor --remove-config was passed and
// the session is interactive, the user picks from a menu (keep / remove config /
// remove everything) — so the flags are discoverable without docs. With a flag
// set, or --yes, or a non-interactive run, the scope comes from the flags
// (default: keep both).
//
// Stage 3 (irreversibility gate): when the chosen scope removes the state dir
// (audit log + backups), a final confirm warns it is irreversible; declining
// downgrades to "keep the state dir" rather than aborting. With --yes this gate
// is skipped (slog.Warn).
//
// Returns (ok, removeConfig, removeState, err): ok is false when the UNINSTALL
// gate is declined (caller must abort, not call Reverse).
func uninstallConfirmSeq(ctx context.Context, p Printer, plan []audit.ReverseAction, purgeFlag, removeConfigFlag, yes bool) (bool, bool, bool, error) {
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
		return false, false, false, errMissingInput("yes")
	}

	// Stage 1: typed UNINSTALL confirm.
	ok, err := tui.ConfirmTyped(ctx,
		"Type UNINSTALL to reverse every change made by abysslink",
		"UNINSTALL",
		yes)
	if err != nil {
		return false, false, false, err
	}
	if !ok {
		return false, false, false, nil
	}

	removeConfig, removeState, err := resolveCleanupScope(ctx, p, purgeFlag, removeConfigFlag, yes)
	if err != nil {
		return false, false, false, err
	}
	return true, removeConfig, removeState, nil
}

// resolveCleanupScope decides whether to remove abysslink's config dir and/or
// state dir (audit log + backups). Flags win; otherwise an interactive user
// picks from a menu (so the flags are discoverable). Removing the state dir is
// gated by an irreversibility confirm. Returns (removeConfig, removeState, err).
func resolveCleanupScope(ctx context.Context, p Printer, purgeFlag, removeConfigFlag, yes bool) (bool, bool, error) {
	removeConfig := purgeFlag || removeConfigFlag
	removeState := purgeFlag

	if !purgeFlag && !removeConfigFlag && !yes {
		// Interactive (guaranteed: uninstallConfirmSeq returned for non-TTY).
		choice, err := tui.Select(ctx, "What about abysslink's own config and audit log?",
			[]string{cleanupKeepBoth, cleanupRemoveConfig, cleanupRemoveEverything}, yes)
		if err != nil {
			return false, false, err
		}
		switch choice {
		case cleanupRemoveConfig:
			removeConfig, removeState = true, false
		case cleanupRemoveEverything:
			removeConfig, removeState = true, true
		default:
			removeConfig, removeState = false, false
		}
	}

	if removeState {
		confirmed, err := confirmStateDeletion(ctx, p, yes)
		if err != nil {
			return false, false, err
		}
		removeState = confirmed // declining keeps the state dir; config choice stands
	}
	return removeConfig, removeState, nil
}

// confirmStateDeletion prints the irreversibility warning and asks the user to
// confirm deleting the audit log + backups. With --yes it is auto-confirmed.
func confirmStateDeletion(ctx context.Context, p Printer, yes bool) (bool, error) {
	printerInfo(p, "")
	printerInfo(p, styleWarn.Render("  WARNING: this will permanently delete the audit log and all backups."))
	printerInfo(p, styleWarn.Render("  This is NOT reversible. There will be no record of changes after this."))
	printerInfo(p, "")
	if yes {
		slog.Warn("uninstall --yes: skipping audit-log/backups irreversibility confirmation gate")
		return true, nil
	}
	return tui.Confirm(ctx, "Permanently delete the audit log + backups. Proceed?", yes)
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
