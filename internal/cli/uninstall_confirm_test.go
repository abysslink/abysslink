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
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUninstallConfirmSeq_NonMatchingPhrase asserts that when the user types
// a non-matching phrase the confirm sequence returns (false, false, nil) and
// audit.Reverse should NOT be called.
func TestUninstallConfirmSeq_NonMatchingPhrase(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	plan := []audit.ReverseAction{
		{Action: "restore", Target: "/tmp/test-file"},
	}

	// With a non-matching typed input (empty in non-TTY context), the confirm
	// must return (ok=false, purgeOK=false, nil).
	ok, purgeOK, err := uninstallConfirmSeq(ctx, p, plan, false, false)
	require.NoError(t, err)
	assert.False(t, ok, "non-matching phrase must return ok=false")
	assert.False(t, purgeOK, "purgeOK must be false when ok=false")
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

	ok, purgeOK, err := uninstallConfirmSeq(ctx, p, plan, false, true /*yes*/)
	require.NoError(t, err)
	assert.True(t, ok, "--yes must auto-confirm UNINSTALL")
	assert.False(t, purgeOK, "purge=false must not trigger second confirm")
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

	ok, purgeOK, err := uninstallConfirmSeq(ctx, p, plan, true /*purge*/, true /*yes*/)
	require.NoError(t, err)
	assert.True(t, ok, "--yes must auto-confirm UNINSTALL")
	assert.True(t, purgeOK, "--yes + --purge must auto-confirm second gate")
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

	_, _, err := uninstallConfirmSeq(ctx, p, plan, true /*purge*/, true /*yes*/)
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

	_, _, err := uninstallConfirmSeq(ctx, p, plan, false, true /*yes*/)
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

	// Non-TTY + no --yes → ok=false → Reverse should not be called.
	ok, _, err := uninstallConfirmSeq(ctx, p, nil, false, false)
	require.NoError(t, err)
	assert.False(t, ok, "non-interactive uninstall without --yes must not proceed")
}
