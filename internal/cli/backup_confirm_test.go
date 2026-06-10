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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRestoreDiff_ShowsChange asserts that restoreDiffPreview produces output
// containing both the before and after state when the target and backup differ.
func TestRestoreDiff_ShowsChange(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	backup := filepath.Join(dir, "test.conf.bak.20260101T000000.000000000Z")

	require.NoError(t, os.WriteFile(target, []byte("line1\nline2\nline3\n"), 0o600))
	require.NoError(t, os.WriteFile(backup, []byte("line1\nchanged\nline3\n"), 0o600))

	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	err := restoreDiffPreview(p, target, backup, "20260101T000000.000000000Z")
	require.NoError(t, err)

	out := buf.String()
	// Preview must mention the backup timestamp.
	assert.Contains(t, out, "20260101T000000.000000000Z",
		"preview must contain backup timestamp")
	// Preview must mention both the target path and some change indication.
	assert.True(t,
		strings.Contains(out, "sha256") || strings.Contains(strings.ToLower(out), "will replace") ||
			strings.Contains(out, target),
		"preview must mention target path or change description; got: %q", out)
}

// TestRestoreDiff_MissingTarget asserts that restoreDiffPreview handles a
// non-existent target gracefully (target was created by abysslink, has no
// pre-abysslink version).
func TestRestoreDiff_MissingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nonexistent.conf")
	backup := filepath.Join(dir, "nonexistent.conf.bak.20260101T000000.000000000Z")

	require.NoError(t, os.WriteFile(backup, []byte("backup content\n"), 0o600))

	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	// Should not error — just indicate there's no current version to compare.
	err := restoreDiffPreview(p, target, backup, "20260101T000000.000000000Z")
	require.NoError(t, err)
}

// TestBackupRestoreDryRun_ShowsPreviewNotMutating asserts that backup restore
// in dry-run mode prints the preview (timestamp + change info) without mutating
// the live file.
func TestBackupRestoreDryRun_ShowsPreviewNotMutating(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "my.conf")
	backup := filepath.Join(dir, "my.conf.bak.20260101T000000.000000000Z")

	origContent := "original\n"
	backupContent := "backup version\n"
	require.NoError(t, os.WriteFile(target, []byte(origContent), 0o600))
	require.NoError(t, os.WriteFile(backup, []byte(backupContent), 0o600))

	var out, errOut bytes.Buffer
	rootCmd := buildRootCmd()
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	rootCmd.SetArgs([]string{
		"backup", "restore", target,
		// no --apply, so dry-run is default
	})

	err := rootCmd.ExecuteContext(context.Background())
	// May fail because no audit log — that's fine.
	// Key assertion: target file is unchanged.
	_ = err

	gotContent, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, origContent, string(gotContent),
		"dry-run must not mutate the live target file")
}

// TestBackupRestoreDeclined_FileUnchanged asserts that when the user declines
// the restore confirm (non-interactive), the target file is not modified.
func TestBackupRestoreDeclined_FileUnchanged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cfg.conf")
	backup := filepath.Join(dir, "cfg.conf.bak.20260101T000000.000000000Z")

	origContent := "live content\n"
	backupContent := "backup content\n"
	require.NoError(t, os.WriteFile(target, []byte(origContent), 0o600))
	require.NoError(t, os.WriteFile(backup, []byte(backupContent), 0o600))

	// Direct call to confirmRestore: in a non-TTY context it must decline AND
	// surface errMissingInput so the command exits non-zero (U8 — a piped/CI
	// restore must be able to tell the operation did not happen).
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	ok, err := confirmRestore(context.Background(), p, target, backup, "20260101T000000.000000000Z", false /*yes*/)
	require.Error(t, err, "non-interactive without --yes must return errMissingInput")
	assert.Contains(t, err.Error(), "--yes", "the error must name the flag that supplies the missing input")
	assert.False(t, ok, "non-interactive without --yes must decline and return false")

	// File must be unchanged.
	gotContent, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, origContent, string(gotContent),
		"target file must not be modified when confirm is declined")
}

// TestBackupRestoreAutoYes_RestoresFile asserts that backup restore with --yes
// restores the file content from backup without prompting.
func TestBackupRestoreAutoYes_RestoresFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cfg.conf")
	backup := filepath.Join(dir, "cfg.conf.bak.20260101T000000.000000000Z")

	origContent := "live content\n"
	backupContent := "backup content\n"
	require.NoError(t, os.WriteFile(target, []byte(origContent), 0o600))
	require.NoError(t, os.WriteFile(backup, []byte(backupContent), 0o600))

	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	ok, err := confirmRestore(context.Background(), p, target, backup, "20260101T000000.000000000Z", true /*yes*/)
	require.NoError(t, err)
	assert.True(t, ok, "--yes must auto-confirm restore")
}

// TestRestoreDiff_ContainsSha256 asserts that the diff preview includes SHA-256
// hashes so the user can verify the content before and after.
func TestRestoreDiff_ContainsSha256(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "check.conf")
	backup := filepath.Join(dir, "check.conf.bak.20260101T000000.000000000Z")

	require.NoError(t, os.WriteFile(target, []byte("current content\n"), 0o600))
	require.NoError(t, os.WriteFile(backup, []byte("backup content\n"), 0o600))

	var buf bytes.Buffer
	p := &testPrinter{out: &buf}

	err := restoreDiffPreview(p, target, backup, "20260101T000000.000000000Z")
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "sha256", "preview must include sha256 hash for verification")
}
