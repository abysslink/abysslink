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

package audit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
)

// TestReverse_RestoresAndDeletes is the core "uninstall leaves nothing broken"
// guarantee: a pre-existing file is restored byte-identically to its original
// content, and a file abysslink created is deleted.
func TestReverse_RestoresAndDeletes(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	a := audit.New(logPath)

	// Pre-existing file abysslink later modifies.
	pre := filepath.Join(dir, "existing.conf")
	require.NoError(t, os.WriteFile(pre, []byte("ORIGINAL"), 0o600))
	require.NoError(t, a.WriteFile(pre, []byte("MODIFIED-v1"), 0o600, false))
	require.NoError(t, a.WriteFile(pre, []byte("MODIFIED-v2"), 0o600, false))

	// File abysslink creates from scratch.
	created := filepath.Join(dir, "created.conf")
	require.NoError(t, a.WriteFile(created, []byte("brand new"), 0o600, false))

	manifest, err := audit.Reverse(logPath, false)
	require.NoError(t, err)
	require.Len(t, manifest, 2)

	// Pre-existing file restored to its ORIGINAL content (not the latest backup).
	got, err := os.ReadFile(pre) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	require.NoError(t, err)
	assert.Equal(t, "ORIGINAL", string(got))

	// Created file removed.
	_, statErr := os.Stat(created)
	assert.True(t, os.IsNotExist(statErr), "abysslink-created file must be deleted")

	// Sidecar backups cleaned up after restore.
	baks, _ := audit.Backups(pre)
	assert.Empty(t, baks)

	// Manifest carries the SHA-256 of the restored content (verification handle).
	for _, act := range manifest {
		assert.NoError(t, act.Err)
		if act.Target == pre {
			assert.Equal(t, "restore", act.Action)
			assert.Equal(t, audit.HashOf([]byte("ORIGINAL")), act.Hash)
		}
		if act.Target == created {
			assert.Equal(t, "delete", act.Action)
		}
	}
}

// TestReverse_IdempotentRerun asserts a second uninstall after a successful one
// is a clean no-op: restored files (whose .bak sidecars were consumed) are
// SKIPPED — never re-restored (which would fail "no such file or directory")
// and never deleted (which would destroy the user's restored original content).
func TestReverse_IdempotentRerun(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	a := audit.New(logPath)

	// Pre-existing file abysslink modifies (gets a backup chain).
	pre := filepath.Join(dir, "existing.conf")
	require.NoError(t, os.WriteFile(pre, []byte("ORIGINAL"), 0o600))
	require.NoError(t, a.WriteFile(pre, []byte("MODIFIED"), 0o600, false))

	// File abysslink creates from scratch (no backup chain).
	created := filepath.Join(dir, "created.conf")
	require.NoError(t, a.WriteFile(created, []byte("brand new"), 0o600, false))

	// First uninstall: restores pre, deletes created, consumes sidecars.
	_, err := audit.Reverse(logPath, false)
	require.NoError(t, err)
	got, err := os.ReadFile(pre) //nolint:gosec // G304: fixture under test temp dir
	require.NoError(t, err)
	require.Equal(t, "ORIGINAL", string(got))
	baks, _ := audit.Backups(pre)
	require.Empty(t, baks, "first uninstall must consume the sidecars")

	// Second uninstall: must be a clean no-op.
	manifest, err := audit.Reverse(logPath, false)
	require.NoError(t, err)
	for _, act := range manifest {
		assert.NoError(t, act.Err, "re-run must not error on %s", act.Target)
		assert.Equal(t, "skip", act.Action, "re-run must skip %s, not %s", act.Target, act.Action)
	}

	// The restored original file must survive the second run untouched.
	got, err = os.ReadFile(pre) //nolint:gosec // G304: fixture under test temp dir
	require.NoError(t, err)
	assert.Equal(t, "ORIGINAL", string(got), "re-run must not delete the restored original")
}

// TestReverse_DriftKeepsUserEdits asserts that a file the user modified AFTER
// abysslink last wrote it is KEPT (action "keep"), never restored or deleted —
// so the user's later changes are not silently lost.
func TestReverse_DriftKeepsUserEdits(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	a := audit.New(logPath)

	// Pre-existing file abysslink modifies (restore candidate).
	pre := filepath.Join(dir, "existing.conf")
	require.NoError(t, os.WriteFile(pre, []byte("ORIGINAL"), 0o600))
	require.NoError(t, a.WriteFile(pre, []byte("ABYSSLINK"), 0o600, false))

	// abysslink-created file (delete candidate).
	created := filepath.Join(dir, "created.conf")
	require.NoError(t, a.WriteFile(created, []byte("abysslink-made"), 0o600, false))

	// The user edits BOTH after install.
	require.NoError(t, os.WriteFile(pre, []byte("USER EDIT"), 0o600))
	require.NoError(t, os.WriteFile(created, []byte("USER EDIT TOO"), 0o600))

	manifest, err := audit.Reverse(logPath, false)
	require.NoError(t, err)
	for _, act := range manifest {
		assert.Equal(t, "keep", act.Action, "drifted %s must be kept, not %s", act.Target, act.Action)
		assert.NotEmpty(t, act.Warning, "kept action must carry a drift warning")
	}

	// Both files must retain the user's edits, untouched.
	got, err := os.ReadFile(pre) //nolint:gosec // G304: fixture under test temp dir
	require.NoError(t, err)
	assert.Equal(t, "USER EDIT", string(got))
	got, err = os.ReadFile(created) //nolint:gosec // G304: fixture under test temp dir
	require.NoError(t, err)
	assert.Equal(t, "USER EDIT TOO", string(got))
}

// TestPlanReverseExcluding_OmitsExcludedTarget asserts excluded targets (those a
// module reverses surgically) never appear in the whole-file plan.
func TestPlanReverseExcluding_OmitsExcludedTarget(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	a := audit.New(logPath)

	shared := filepath.Join(dir, "settings.json")
	owned := filepath.Join(dir, "generated.conf")
	require.NoError(t, a.WriteFile(shared, []byte("{}"), 0o600, false))
	require.NoError(t, a.WriteFile(owned, []byte("x"), 0o600, false))

	plan, err := audit.PlanReverseExcluding(logPath, map[string]bool{shared: true})
	require.NoError(t, err)
	for _, act := range plan {
		assert.NotEqual(t, shared, act.Target, "excluded target must not be in the whole-file plan")
	}
}

func TestReverse_DryRunDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	a := audit.New(logPath)

	target := filepath.Join(dir, "f.conf")
	require.NoError(t, os.WriteFile(target, []byte("ORIGINAL"), 0o600))
	require.NoError(t, a.WriteFile(target, []byte("CHANGED"), 0o600, false))

	manifest, err := audit.Reverse(logPath, true)
	require.NoError(t, err)
	require.Len(t, manifest, 1)
	assert.Equal(t, "restore", manifest[0].Action)
	assert.Equal(t, audit.HashOf([]byte("ORIGINAL")), manifest[0].Hash)

	// Dry-run must not touch the file or its backups.
	got, err := os.ReadFile(target) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	require.NoError(t, err)
	assert.Equal(t, "CHANGED", string(got))
	baks, _ := audit.Backups(target)
	assert.Len(t, baks, 1)
}

func TestMutatedTargets_DedupAndSkipsDryRun(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	a := audit.New(logPath)

	require.NoError(t, a.Append("write", "/a", []byte("1"), false))
	require.NoError(t, a.Append("write", "/a", []byte("2"), false)) // dup target
	require.NoError(t, a.Append("write", "/b", []byte("3"), true))  // dry-run — excluded
	require.NoError(t, a.Append("write", "/c", []byte("4"), false))

	targets, err := audit.MutatedTargets(logPath)
	require.NoError(t, err)
	assert.Equal(t, []string{"/a", "/c"}, targets)
}

func TestReadLog_MissingIsEmpty(t *testing.T) {
	entries, err := audit.ReadLog(filepath.Join(t.TempDir(), "nope.log"))
	require.NoError(t, err)
	assert.Empty(t, entries)
}
