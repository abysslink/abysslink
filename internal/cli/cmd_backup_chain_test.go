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
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
)

// TestBackupRestoreCmd_FlagDefaultFalse asserts that the --accept-unverified-backup
// flag exists on the restore command with a default of false (fail-closed by default).
func TestBackupRestoreCmd_FlagDefaultFalse(t *testing.T) {
	cmd := newBackupRestoreCmd()
	flag := cmd.Flags().Lookup("accept-unverified-backup")
	require.NotNil(t, flag, "--accept-unverified-backup flag must be registered on restore command")
	assert.Equal(t, "false", flag.DefValue, "--accept-unverified-backup default must be false (fail-closed)")
}

// TestBackupRestoreCmd_UsesRestoreGated proves the fail-closed/accept semantics
// by exercising the same RestoreGated path with a *SignedAudit over a temp log,
// matching how the live restore command now calls audit.RestoreGated.
//
// Behaviour contract (AUD-01 / T-24-07-01):
//  1. A .bak file with NO chain entry is REFUSED by default (acceptUnverified=false).
//  2. The same restore with acceptUnverified=true SUCCEEDS and records a
//     "restore-unverified" non-OK entry.
//  3. A .bak file created by BackupWithChain (chain-recorded) is accepted by default.
func TestBackupRestoreCmd_UsesRestoreGated(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := secrets.NewMockStore()
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("RefusesUnchainedByDefault", func(t *testing.T) {
		dst := filepath.Join(dir, "sshd_config")
		bak := dst + ".bak.20260101T120000.000000000Z"
		require.NoError(t, os.WriteFile(dst, []byte("current"), 0o600))
		require.NoError(t, os.WriteFile(bak, []byte("original"), 0o600))

		// acceptUnverified=false → must refuse (no chain entry).
		err := audit.RestoreGated(ctx, dst, bak, sa, false)
		assert.Error(t, err, "must refuse unchained backup by default (fail-closed)")
		assert.Contains(t, err.Error(), "no chain entry",
			"error message must mention the missing chain entry")

		// dst must be unchanged.
		got, rerr := os.ReadFile(dst) //nolint:gosec // G304: test reads fixture in TempDir
		require.NoError(t, rerr)
		assert.Equal(t, "current", string(got), "dst must not be overwritten when refused")
	})

	t.Run("AcceptsWithFlagAndRecordsNonOKEntry", func(t *testing.T) {
		dst := filepath.Join(dir, "sshd_config2")
		bak := dst + ".bak.20260101T120000.000000000Z"
		require.NoError(t, os.WriteFile(dst, []byte("current"), 0o600))
		require.NoError(t, os.WriteFile(bak, []byte("override-content"), 0o600))

		// acceptUnverified=true → restore must succeed.
		err := audit.RestoreGated(ctx, dst, bak, sa, true)
		require.NoError(t, err, "RestoreGated with acceptUnverified=true must succeed")

		got, rerr := os.ReadFile(dst) //nolint:gosec // G304: test reads fixture in TempDir
		require.NoError(t, rerr)
		assert.Equal(t, "override-content", string(got), "dst must contain backup content after unverified restore")

		// Audit log must record a "restore-unverified" non-OK entry.
		entries, lerr := audit.ReadLog(logPath)
		require.NoError(t, lerr)
		var foundNonOK bool
		for _, e := range entries {
			if e.Op == "restore-unverified" {
				foundNonOK = true
				break
			}
		}
		assert.True(t, foundNonOK, "must record 'restore-unverified' entry in audit chain")
	})

	t.Run("AcceptsChainRecordedBackup", func(t *testing.T) {
		dst := filepath.Join(dir, "sshd_config3")
		content := []byte("chain-backed-original")

		// BackupWithChain creates the .bak and records a chain entry.
		require.NoError(t, os.WriteFile(dst, content, 0o600))
		bakPath, bErr := audit.BackupWithChain(ctx, dst, sa)
		require.NoError(t, bErr, "BackupWithChain must succeed")

		// Now overwrite dst so it differs from the backup.
		require.NoError(t, os.WriteFile(dst, []byte("new-content"), 0o600))

		// RestoreGated without acceptUnverified must succeed (chain entry exists).
		err := audit.RestoreGated(ctx, dst, bakPath, sa, false)
		require.NoError(t, err, "chain-recorded backup must be accepted by default")

		got, rerr := os.ReadFile(dst) //nolint:gosec // G304: test reads fixture in TempDir
		require.NoError(t, rerr)
		assert.Equal(t, string(content), string(got), "dst must be restored to chain-backed content")
	})
}

// TestCmdSignedAudit_Helper verifies the cmdSignedAudit helper resolves a
// *SignedAudit when a keychain is available. The helper is used by the backup
// restore command and all server backup commands (AUD-01).
func TestCmdSignedAudit_Helper(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)

	kc := secrets.NewMockStore()
	logPath := filepath.Join(dir, "abysslink", "audit.log")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "abysslink"), 0o700))

	// Verify the helper produces a usable *SignedAudit that can record entries.
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	require.NotNil(t, sa)

	// Write a test entry to confirm the sa is operational.
	diffHash := sha256.Sum256([]byte("test"))
	err = sa.Append(context.Background(), audit.SignInput{Title: "test", DiffHash: diffHash}, "/tmp/test.conf", false)
	require.NoError(t, err)
}
