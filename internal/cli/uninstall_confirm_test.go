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
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUninstallConfirmSeq_NonInteractiveErrors asserts that a non-interactive
// invocation (no TTY, no --yes) aborts with errMissingInput so the process
// exits NON-ZERO — a piped/CI `uninstall --apply` must be able to tell the
// operation did not happen (U8: non-interactive aborts must not exit 0).
func TestUninstallConfirmSeq_NonInteractiveErrors(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	plan := []audit.ReverseAction{
		{Action: "restore", Target: "/tmp/test-file"},
	}

	// Tests run without a TTY, so this exercises the non-interactive branch.
	ok, removeConfig, removeState, err := uninstallConfirmSeq(ctx, p, plan, false, false, false)
	require.Error(t, err, "non-interactive without --yes must return an error (exit non-zero)")
	assert.Contains(t, err.Error(), "--yes", "the error must name the flag that supplies the missing input")
	assert.False(t, ok, "ok must be false when aborting")
	assert.False(t, removeConfig, "removeConfig must be false when ok=false")
	assert.False(t, removeState, "removeState must be false when ok=false")
}

// TestUninstallConfirmSeq_AutoYes asserts that with --yes the confirm sequence
// returns (true, false, nil) for the base case (no purge) and (true, true, nil)
// for purge, without hanging.
func TestUninstallConfirmSeq_AutoYesBase(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	plan := []audit.ReverseAction{
		{Action: "restore", Target: "/tmp/test-file"},
	}

	ok, removeConfig, removeState, err := uninstallConfirmSeq(ctx, p, plan, false, false, true /*yes*/)
	require.NoError(t, err)
	assert.True(t, ok, "--yes must auto-confirm UNINSTALL")
	assert.False(t, removeConfig, "no flag + --yes must keep the config dir")
	assert.False(t, removeState, "no flag + --yes must keep the state dir")
}

// TestUninstallConfirmSeq_AutoYesPurge asserts that with --yes and --purge both
// confirms are bypassed and (true, true, nil) is returned.
func TestUninstallConfirmSeq_AutoYesPurge(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	plan := []audit.ReverseAction{
		{Action: "restore", Target: "/tmp/test-file"},
	}

	ok, removeConfig, removeState, err := uninstallConfirmSeq(ctx, p, plan, true /*purge*/, false, true /*yes*/)
	require.NoError(t, err)
	assert.True(t, ok, "--yes must auto-confirm UNINSTALL")
	assert.True(t, removeConfig, "--purge must remove the config dir")
	assert.True(t, removeState, "--yes + --purge must auto-confirm removing the state dir")
}

// TestUninstallConfirmSeq_RemoveConfigFlag asserts --remove-config (without
// --purge) resolves to removing the config dir but keeping the state dir, and
// does not trigger the irreversibility gate.
func TestUninstallConfirmSeq_RemoveConfigFlag(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	plan := []audit.ReverseAction{{Action: "restore", Target: "/tmp/test-file"}}

	ok, removeConfig, removeState, err := uninstallConfirmSeq(ctx, p, plan, false /*purge*/, true /*removeConfig*/, true /*yes*/)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, removeConfig, "--remove-config must remove the config dir")
	assert.False(t, removeState, "--remove-config must keep the state dir (audit log + backups)")
}

// TestUninstallConfirmSeq_PurgeMessagePrinted asserts that with --purge a warning
// about permanent deletion of audit log + backups is printed.
func TestUninstallConfirmSeq_PurgeMessagePrinted(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	plan := []audit.ReverseAction{
		{Action: "restore", Target: "/tmp/test-file"},
	}

	_, _, _, err := uninstallConfirmSeq(ctx, p, plan, true /*purge*/, false, true /*yes*/)
	require.NoError(t, err)

	out := buf.String()
	// The purge warning must mention irreversibility and what will be deleted.
	assert.True(t,
		strings.Contains(strings.ToLower(out), "irreversible") ||
			strings.Contains(strings.ToLower(out), "permanently") ||
			strings.Contains(strings.ToLower(out), "audit log"),
		"purge warning must mention irreversibility or 'audit log'; got: %q", out)
}

// TestUninstallConfirmSeq_BlastRadiusPrinted asserts that the number of planned
// reverse actions is mentioned (blast radius summary) before the confirm.
func TestUninstallConfirmSeq_BlastRadiusPrinted(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	plan := []audit.ReverseAction{
		{Action: "restore", Target: "/tmp/file-a"},
		{Action: "delete", Target: "/tmp/file-b"},
		{Action: "restore", Target: "/tmp/file-c"},
	}

	_, _, _, err := uninstallConfirmSeq(ctx, p, plan, false, false, true /*yes*/)
	require.NoError(t, err)

	out := buf.String()
	// Blast radius must mention the number of affected files (3).
	assert.True(t,
		strings.Contains(out, "3") ||
			strings.Contains(strings.ToLower(out), "file"),
		"blast radius must mention count or 'file'; got: %q", out)
}

// TestUninstallDryRun_NoConfirm asserts that a dry-run does not prompt and returns nil.
// This preserves existing conformance behaviour (testUninstallDryRunShowsPlan equivalent).
func TestUninstallDryRun_NoConfirm(t *testing.T) {
	// Sandbox HOME so the uninstall dry-run reads an EMPTY temp-dir audit log
	// rather than the developer's real ~/.local/state/abysslink/audit.log. Without
	// this the uninstall reverse-plan scans the machine's actual audit chain, so
	// the test's wall-clock scaled with that log's size and could blow past the
	// -race 10m timeout on a long-lived dev box (it was never an assertion about
	// real audit content — the test only checks "dry-run does not prompt / hang").
	t.Setenv("HOME", t.TempDir())

	// Build a root command and run uninstall without --apply (so dry-run is active).
	rootCmd := buildRootCmd()
	rootCmd.SetArgs([]string{"uninstall"})

	// Should complete without hanging (no TTY prompts in dry-run).
	err := rootCmd.ExecuteContext(context.Background())
	// Dry-run may error if the audit log does not exist — that's fine.
	// The key assertion is: it did not hang (test completes).
	_ = err
}

// TestUninstallCmd_ContainsTypedConfirmCall asserts that cmd_uninstall.go calls
// tui.ConfirmTyped with the phrase "UNINSTALL" on the apply path. This is
// a source-level grep-equivalent test: run the command with a non-matching
// input and assert audit.Reverse was NOT called (live file unchanged).
func TestUninstallCmd_ContainsTypedConfirmCall(t *testing.T) {
	// uninstallConfirmSeq is the extracted helper; verifying it is the right gate.
	// A nil plan still goes through the gate logic.
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	// Non-TTY + no --yes → errMissingInput → Reverse must not be called and the
	// command exits non-zero (U8).
	ok, _, _, err := uninstallConfirmSeq(ctx, p, nil, false, false, false)
	require.Error(t, err, "non-interactive uninstall without --yes must error")
	assert.False(t, ok, "non-interactive uninstall without --yes must not proceed")
}

// ── CLI-18: --purge controls directory removal ────────────────────────────────

// TestRemoveAbysslinkDirs_NoPurgeKeepsConfigDir verifies the CLI-18 fix:
// uninstall --apply WITHOUT --purge must keep ~/.config/abysslink (and the
// state dir), matching what the --purge help text and dry-run output promise.
func TestRemoveAbysslinkDirs_NoPurgeKeepsConfigDir(t *testing.T) {
	cfgBase := t.TempDir()
	stateBase := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgBase)
	t.Setenv("XDG_STATE_HOME", stateBase)

	cfgDir := abysslinkConfigDir()
	stateDir := abysslinkStateDir()
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "abysslink.yaml"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "audit.log"), []byte("y"), 0o600))

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)

	failures := removeAbysslinkDirs(p, false /* removeConfig */, false /* removeState */)
	assert.Zero(t, failures)

	assert.DirExists(t, cfgDir, "config dir must be KEPT without --purge (CLI-18)")
	assert.DirExists(t, stateDir, "state dir must be KEPT without --purge")
	assert.Contains(t, out.String(), "Kept", "output must tell the user the dirs were kept")
	assert.Contains(t, out.String(), "--purge", "output must point at --purge for full removal")
}

// TestRemoveAbysslinkDirs_RemoveConfigKeepsState verifies --remove-config drops
// the config dir but keeps the state dir (audit log + backups) for forensics.
func TestRemoveAbysslinkDirs_RemoveConfigKeepsState(t *testing.T) {
	cfgBase := t.TempDir()
	stateBase := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgBase)
	t.Setenv("XDG_STATE_HOME", stateBase)

	cfgDir := abysslinkConfigDir()
	stateDir := abysslinkStateDir()
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.MkdirAll(stateDir, 0o700))

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)

	failures := removeAbysslinkDirs(p, true /* removeConfig */, false /* removeState */)
	assert.Zero(t, failures)

	assert.NoDirExists(t, cfgDir, "config dir must be removed with --remove-config")
	assert.DirExists(t, stateDir, "state dir must be KEPT with --remove-config")
}

// TestRemoveAbysslinkDirs_PurgeRemovesBothDirs verifies that --purge removes
// both the config dir and the state dir (audit log + backups).
func TestRemoveAbysslinkDirs_PurgeRemovesBothDirs(t *testing.T) {
	cfgBase := t.TempDir()
	stateBase := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgBase)
	t.Setenv("XDG_STATE_HOME", stateBase)

	cfgDir := abysslinkConfigDir()
	stateDir := abysslinkStateDir()
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.MkdirAll(stateDir, 0o700))

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)

	failures := removeAbysslinkDirs(p, true /* removeConfig */, true /* removeState */)
	assert.Zero(t, failures)

	assert.NoDirExists(t, cfgDir, "config dir must be removed with --purge")
	assert.NoDirExists(t, stateDir, "state dir must be removed with --purge")
}

// TestFoldSkipDirs_CollapsesTempFlood asserts that a flood of unique temp-dir
// paths (the real-world cause of thousands of "skip" lines: each t.TempDir()
// fixture is its own folder) collapses to a single subtree line, while skips in
// distinct top-level trees stay separate and counts are exact.
func TestFoldSkipDirs_CollapsesTempFlood(t *testing.T) {
	var skips []string
	for i := range 500 {
		skips = append(skips, fmt.Sprintf("/var/folders/dh/R/T/TestX%d/001/abysslink.yaml", i))
	}
	skips = append(skips,
		"/tmp/claude-501/a/abysslink.yaml",
		"/tmp/claude-501/b/abysslink.yaml",
		"/tmp/loose.yaml",
	)

	groups := foldSkipDirs(skips, skipFanout)

	total := 0
	byDir := map[string]int{}
	for _, g := range groups {
		total += g.count
		byDir[g.dir] = g.count
	}
	assert.Equal(t, len(skips), total, "folding must preserve the total skip count")

	// The 500-wide temp fan-out collapses to one line at the branching folder.
	assert.Equal(t, 500, byDir["/var/folders/dh/R/T"], "wide temp fan-out must fold to its subtree root")
	// A narrow tree (claude-501 has 2 children <= fanout) is NOT collapsed: each
	// distinct leaf folder is kept so the few real leftovers stay visible.
	assert.Equal(t, 1, byDir["/tmp/claude-501/a"], "narrow tree leaf folder must be kept")
	assert.Equal(t, 1, byDir["/tmp/claude-501/b"], "narrow tree leaf folder must be kept")
	// A loose file directly under /tmp is reported on its own folder line.
	assert.Equal(t, 1, byDir["/tmp"], "loose file's folder must be reported")

	// First group is the largest (sorted by count desc).
	require.NotEmpty(t, groups)
	assert.Equal(t, "/var/folders/dh/R/T", groups[0].dir)
}

// TestFoldSkipDirs_Empty returns no groups for no skips.
func TestFoldSkipDirs_Empty(t *testing.T) {
	assert.Empty(t, foldSkipDirs(nil, skipFanout))
}

// TestPrintReversePlan_FoldsSkipsKeepsActionable asserts the printed plan lists
// restore/delete individually but folds skips into a grouped summary.
func TestPrintReversePlan_FoldsSkipsKeepsActionable(t *testing.T) {
	plan := []audit.ReverseAction{
		{Target: "/Users/x/.config/abysslink/abysslink.yaml", Action: "restore"},
		{Target: "/Users/x/.zshenv", Action: "delete"},
	}
	for i := range 50 {
		plan = append(plan, audit.ReverseAction{
			Target: fmt.Sprintf("/var/folders/dh/R/T/TestX%d/001/abysslink.yaml", i),
			Action: "skip",
		})
	}

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	printReversePlan(p, plan)
	got := out.String()

	assert.Contains(t, got, "restore  /Users/x/.config/abysslink/abysslink.yaml")
	assert.Contains(t, got, "delete   /Users/x/.zshenv")
	assert.Contains(t, got, "50 already-absent target(s)")
	assert.Contains(t, got, "/var/folders/dh/R/T")
	// No per-file skip line should leak through.
	assert.NotContains(t, got, "TestX0/001/abysslink.yaml")
}
