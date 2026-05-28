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

func TestWriteFile_CreatesFileAndLogs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "new.conf")
	a := audit.New(logPath)

	require.NoError(t, a.WriteFile(target, []byte("hello"), 0o600, false))

	got, err := os.ReadFile(target) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	logRaw, err := os.ReadFile(logPath) //nolint:gosec
	require.NoError(t, err)
	assert.Contains(t, string(logRaw), target)
	// The content itself must never appear in the audit log.
	assert.NotContains(t, string(logRaw), "hello")
}

func TestWriteFile_BacksUpExistingBeforeOverwrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing.conf")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))

	a := audit.New(filepath.Join(dir, "audit.log"))
	require.NoError(t, a.WriteFile(target, []byte("new"), 0o600, false))

	got, err := os.ReadFile(target) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "new", string(got))

	// A timestamped backup containing the old content must exist.
	matches, err := filepath.Glob(target + ".bak.*")
	require.NoError(t, err)
	require.Len(t, matches, 1)
	bak, err := os.ReadFile(matches[0]) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "old", string(bak))
}

func TestWriteFile_DryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ghost.conf")
	logPath := filepath.Join(dir, "audit.log")
	a := audit.New(logPath)

	require.NoError(t, a.WriteFile(target, []byte("data"), 0o600, true))

	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr), "dry-run must not create the file")

	// The intended mutation is still recorded, tagged dry-run.
	logRaw, err := os.ReadFile(logPath) //nolint:gosec
	require.NoError(t, err)
	assert.Contains(t, string(logRaw), `"dry_run":true`)
}

func TestWriteFile_NoLeftoverTempOnSuccess(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "x.conf")
	a := audit.New(filepath.Join(dir, "audit.log"))
	require.NoError(t, a.WriteFile(target, []byte("y"), 0o600, false))

	_, statErr := os.Stat(target + ".abysslink.tmp")
	assert.True(t, os.IsNotExist(statErr), "temp file must be renamed away")
}

func TestDefaultLogPath_HonorsXDGStateHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)

	got, err := audit.DefaultLogPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "abysslink", "audit.log"), got)

	// The parent directory must have been created.
	info, err := os.Stat(filepath.Join(dir, "abysslink"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}
