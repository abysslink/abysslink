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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
)

func TestAppend_WritesEntry(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	a := audit.New(logPath)

	content := []byte("hello world")
	err := a.Append("write", "/etc/foo", content, false)
	require.NoError(t, err)

	raw, err := os.ReadFile(logPath) //nolint:gosec
	require.NoError(t, err)

	var entry audit.Entry
	require.NoError(t, json.Unmarshal(raw[:len(raw)-1], &entry))
	assert.Equal(t, "write", entry.Op)
	assert.Equal(t, "/etc/foo", entry.Target)
	assert.Equal(t, audit.HashOf(content), entry.Hash)
	assert.False(t, entry.DryRun)
	assert.False(t, entry.Time.IsZero())
}

func TestAppend_DryRunFlagged(t *testing.T) {
	dir := t.TempDir()
	a := audit.New(filepath.Join(dir, "audit.log"))
	require.NoError(t, a.Append("write", "/foo", []byte("x"), true))

	raw, err := os.ReadFile(filepath.Join(dir, "audit.log")) //nolint:gosec
	require.NoError(t, err)
	var entry audit.Entry
	require.NoError(t, json.Unmarshal(raw[:len(raw)-1], &entry))
	assert.True(t, entry.DryRun)
}

func TestAppend_NoContentInLog(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("my-secret-token")
	a := audit.New(filepath.Join(dir, "audit.log"))
	require.NoError(t, a.Append("write", "/foo", secret, false))

	raw, err := os.ReadFile(filepath.Join(dir, "audit.log")) //nolint:gosec
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "my-secret-token")
}

func TestHashOf_Deterministic(t *testing.T) {
	h1 := audit.HashOf([]byte("abc"))
	h2 := audit.HashOf([]byte("abc"))
	assert.Equal(t, h1, h2)
	assert.NotEqual(t, h1, audit.HashOf([]byte("xyz")))
}

func TestBackupRestore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "config.yaml")
	content := []byte("version: 1\n")
	require.NoError(t, os.WriteFile(original, content, 0o600))

	bakPath, err := audit.Backup(original)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(bakPath, original+".bak."))

	// Overwrite original.
	require.NoError(t, os.WriteFile(original, []byte("corrupted\n"), 0o600))

	// Restore from backup.
	require.NoError(t, audit.Restore(original, bakPath))

	restored, err := os.ReadFile(original) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, content, restored)
}

func TestRestore_RejectsRelativeDst(t *testing.T) {
	dir := t.TempDir()
	bak := filepath.Join(dir, "file.bak.20260101T000000Z")
	require.NoError(t, os.WriteFile(bak, []byte("x"), 0o600))

	err := audit.Restore("relative/path", bak)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestRestore_RejectsCrossDirectoryTraversal(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o700))
	bak := filepath.Join(sub, "evil.bak.20260101T000000Z")
	require.NoError(t, os.WriteFile(bak, []byte("x"), 0o600))

	dst := filepath.Join(dir, "target")
	err := audit.Restore(dst, bak)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same directory")
}
