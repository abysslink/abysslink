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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seededAuditStore returns a MockStore pre-seeded with the HMAC key used by
// internal/audit. The key is 32 bytes of 0x01 (matches seededStore in signed_test.go).
func seededAuditStore(t *testing.T) *secrets.MockStore {
	t.Helper()
	kc := secrets.NewMockStore()
	require.NoError(t, kc.Set(context.Background(), "abysslink", "audit-hmac",
		hex.EncodeToString(bytes.Repeat([]byte{1}, 32))))
	return kc
}

// --- Task 1: BackupWithChain and BackupsFromChain ---

// TestBackupWithChain_AppendsChainEntry verifies that BackupWithChain creates a
// .bak file on disk AND records a signed chain entry with Op="backup", Target=dst,
// Hash=hex(sha256(content)).
func TestBackupWithChain_AppendsChainEntry(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededAuditStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	src := filepath.Join(dir, "config.yaml")
	content := []byte("original content")
	require.NoError(t, os.WriteFile(src, content, 0o600))

	dst, err := audit.BackupWithChain(context.Background(), src, sa)
	require.NoError(t, err)
	assert.NotEmpty(t, dst)

	// .bak file must exist on disk.
	_, statErr := os.Stat(dst)
	require.NoError(t, statErr, "backup file must exist on disk")

	// Audit log must contain exactly one entry with the expected fields.
	entries, lerr := audit.ReadLog(logPath)
	require.NoError(t, lerr)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "backup", e.Op)
	assert.Equal(t, dst, e.Target)
	expectedHash := sha256.Sum256(content)
	assert.Equal(t, hex.EncodeToString(expectedHash[:]), e.Hash)
}

// keySetFailStore is an empty keychain whose Set always fails: the HMAC key is
// definitively absent (Get wraps ErrNotFound via the embedded MockStore) but
// lazy first-use key generation cannot store it, so any signed Append fails
// closed. Used to drive BackupWithChain's rollback path now that key creation
// is lazy (R2-12) — simply deleting the key would just trigger regeneration.
type keySetFailStore struct {
	*secrets.MockStore
}

func (s keySetFailStore) Set(context.Context, string, string, string) error {
	return errors.New("simulated keychain write failure")
}

// TestBackupWithChain_RollbackOnAppendFail verifies that if the chain Append
// fails, BackupWithChain removes the .bak file (rollback) and returns an error.
func TestBackupWithChain_RollbackOnAppendFail(t *testing.T) {
	dir := t.TempDir()

	src := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(src, []byte("data"), 0o600))

	logPath := filepath.Join(dir, "audit.log")
	kc := keySetFailStore{secrets.NewMockStore()}
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err, "construction succeeds — key generation is lazy (R2-12)")

	bakPath, backupErr := audit.BackupWithChain(context.Background(), src, sa)
	assert.Error(t, backupErr, "BackupWithChain must return an error when Append fails")
	assert.Empty(t, bakPath, "BackupWithChain must return empty dst on error")

	// The .bak file must NOT exist (rollback succeeded).
	// We know dst starts with src + ".bak." so glob to check none exist.
	baks, _ := filepath.Glob(src + ".bak.*")
	assert.Empty(t, baks, "rolled-back .bak file must not remain on disk")
}

// TestBackupsFromChain_FiltersCorrectEntries verifies that BackupsFromChain
// returns only entries with Op="backup" matching the target prefix, filtering
// out entries with different Op values.
func TestBackupsFromChain_FiltersCorrectEntries(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededAuditStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	ctx := context.Background()
	targetA := filepath.Join(dir, "a.yaml")
	bakA := targetA + ".bak.20260101T120000.000000000Z"

	// Append a "backup" entry for targetA (the .bak path).
	diffHashBackup := sha256.Sum256([]byte("a content"))
	require.NoError(t, sa.Append(ctx, audit.SignInput{Title: "backup", DiffHash: diffHashBackup}, bakA, false))

	// Append a "write" entry for targetA (same target prefix but different Op).
	diffHashWrite := sha256.Sum256([]byte("a written"))
	require.NoError(t, sa.Append(ctx, audit.SignInput{Title: "write", DiffHash: diffHashWrite}, targetA, false))

	// BackupsFromChain must return only the "backup" entry.
	backupEntries, err := audit.BackupsFromChain(logPath, targetA)
	require.NoError(t, err)
	require.Len(t, backupEntries, 1, "must return exactly one backup entry")
	assert.Equal(t, "backup", backupEntries[0].Op)
	assert.Equal(t, bakA, backupEntries[0].Target)
}

// --- Task 2: RestoreGated ---

// TestRestore_RefusesUnchained verifies that RestoreGated refuses to restore a
// .bak file that has no matching chain entry when acceptUnverified=false.
func TestRestore_RefusesUnchained(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededAuditStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	// Create a .bak file without any chain entry.
	dst := filepath.Join(dir, "config.yaml")
	bak := dst + ".bak.20260101T120000.000000000Z"
	require.NoError(t, os.WriteFile(dst, []byte("current"), 0o600))
	require.NoError(t, os.WriteFile(bak, []byte("original"), 0o600))

	restoreErr := audit.RestoreGated(context.Background(), dst, bak, sa, false)
	assert.Error(t, restoreErr, "RestoreGated must refuse an unchained backup by default")

	// dst must remain unchanged.
	got, rerr := os.ReadFile(dst) //nolint:gosec // test reads tmp dir path
	require.NoError(t, rerr)
	assert.Equal(t, "current", string(got), "dst must not be overwritten")
}

// TestRestore_AcceptUnverified_NonOKEntry verifies that RestoreGated with
// acceptUnverified=true restores the file AND records a non-OK audit entry.
func TestRestore_AcceptUnverified_NonOKEntry(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededAuditStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	dst := filepath.Join(dir, "config.yaml")
	bak := dst + ".bak.20260101T120000.000000000Z"
	require.NoError(t, os.WriteFile(dst, []byte("current"), 0o600))
	require.NoError(t, os.WriteFile(bak, []byte("original"), 0o600))

	restoreErr := audit.RestoreGated(context.Background(), dst, bak, sa, true)
	require.NoError(t, restoreErr, "RestoreGated with acceptUnverified=true must succeed")

	// dst must now contain the backup content.
	got, rerr := os.ReadFile(dst) //nolint:gosec // test reads tmp dir path
	require.NoError(t, rerr)
	assert.Equal(t, "original", string(got))

	// Audit log must contain an entry recording the unverified restore.
	entries, lerr := audit.ReadLog(logPath)
	require.NoError(t, lerr)
	require.NotEmpty(t, entries, "audit log must have an entry for the unverified restore")

	// Find the non-OK marker entry.
	var foundNonOK bool
	for _, e := range entries {
		if e.Op == "restore-unverified" {
			foundNonOK = true
			break
		}
	}
	assert.True(t, foundNonOK, "must record a 'restore-unverified' entry in the audit chain")
}

// TestRestore_ChainWalkSelectsBackup verifies that RestoreGated uses the
// chain-recorded backup (not filename order) for selection, proving the D-02
// anti-spoofing guarantee.
func TestRestore_ChainWalkSelectsBackup(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededAuditStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	ctx := context.Background()
	dst := filepath.Join(dir, "config.yaml")

	// Create two .bak files. The chain-recorded one is the one we want.
	bakChained := dst + ".bak.20260101T110000.000000000Z"
	bakUnchained := dst + ".bak.20260101T120000.000000000Z" // lexically later
	chainedContent := []byte("chain-backed original")
	unchainedContent := []byte("unchained possibly-attacker content")

	require.NoError(t, os.WriteFile(dst, []byte("current"), 0o600))
	require.NoError(t, os.WriteFile(bakChained, chainedContent, 0o600))
	require.NoError(t, os.WriteFile(bakUnchained, unchainedContent, 0o600))

	// Record a chain entry only for bakChained.
	diffHash := sha256.Sum256(chainedContent)
	require.NoError(t, sa.Append(ctx, audit.SignInput{Title: "backup", DiffHash: diffHash}, bakChained, false))

	// RestoreGated should use bakChained (chain-recorded), ignoring the lexically
	// later bakUnchained which has no chain entry.
	restoreErr := audit.RestoreGated(ctx, dst, bakChained, sa, false)
	require.NoError(t, restoreErr)

	got, rerr := os.ReadFile(dst) //nolint:gosec // test reads tmp dir path
	require.NoError(t, rerr)
	assert.Equal(t, string(chainedContent), string(got), "must restore from chain-recorded backup")

	// Attempting to restore from the unchained one must fail.
	restoreErrUnchained := audit.RestoreGated(ctx, dst, bakUnchained, sa, false)
	assert.Error(t, restoreErrUnchained, "must refuse to restore from unchained backup")
	_ = errors.New("unused") // keep errors import used
}
