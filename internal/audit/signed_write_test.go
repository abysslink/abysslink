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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
)

// SignedAudit must satisfy the AuditWriter interface (drop-in for *Audit).
var _ audit.AuditWriter = (*audit.SignedAudit)(nil)

func TestSignedWriteFile_LogsThenWrites(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "new.conf")
	kc := secrets.NewMockStore()
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	require.NoError(t, sa.WriteFile(target, []byte("secret-body"), 0o600, false))

	got, err := os.ReadFile(target) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "secret-body", string(got))

	logRaw, err := os.ReadFile(logPath) //nolint:gosec
	require.NoError(t, err)
	// One signed entry recorded; content body must never appear.
	assert.Contains(t, string(logRaw), target)
	assert.NotContains(t, string(logRaw), "secret-body")
	assert.Contains(t, string(logRaw), `"sig":`)
	assert.Contains(t, string(logRaw), `"prev_hash":`)

	// The chain (including the HMAC sig) must verify cleanly after WriteFile.
	res, err := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, err)
	assert.True(t, res.OK)
}

func TestSignedWriteFile_DryRunLogsButNoWrite(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "new.conf")
	sa, err := audit.NewSigned(logPath, secrets.NewMockStore())
	require.NoError(t, err)

	require.NoError(t, sa.WriteFile(target, []byte("body"), 0o600, true))

	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr), "dry-run must not create the file")

	entries, err := audit.ReadLog(logPath)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, entries[0].DryRun)
}
