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
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
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

	got, err := os.ReadFile(target) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	require.NoError(t, err)
	assert.Equal(t, "secret-body", string(got))

	logRaw, err := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
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

// TestSignedWriteFile_DryRunWritesNothing proves CORE-05: a dry-run signed
// WriteFile mutates NOTHING — no target file, no .bak, no chain entries, no
// keychain counter bump.
func TestSignedWriteFile_DryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "existing.conf")
	kc := secrets.NewMockStore()
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	// Pre-existing file: the overwrite path is the one that used to create a
	// .bak and bump the counter even under dry-run.
	require.NoError(t, os.WriteFile(target, []byte("original"), 0o600)) //nolint:gosec // G306: test fixture under temp dir

	require.NoError(t, sa.WriteFile(target, []byte("body"), 0o600, true))

	// Target untouched.
	got, err := os.ReadFile(target) //nolint:gosec // G304: test reads its own temp fixture
	require.NoError(t, err)
	assert.Equal(t, "original", string(got), "dry-run must not modify the target")

	// No .bak created.
	baks, err := filepath.Glob(target + ".bak.*")
	require.NoError(t, err)
	assert.Empty(t, baks, "dry-run must not create a backup")

	// No chain entries recorded.
	entries, err := audit.ReadLog(logPath)
	require.NoError(t, err)
	assert.Empty(t, entries, "dry-run must not append chain entries")

	// Keychain counter untouched (never initialised).
	n, found, err := audit.ReadCounter(context.Background(), kc)
	require.NoError(t, err)
	assert.False(t, found, "dry-run must not initialise the keychain counter")
	assert.Zero(t, n)
}

// TestSignedWriteFile_OverwriteAttestedBackup proves CR-01: the .bak recorded in
// the chain is the byte-identical file actually on disk, and the chain entry's
// Target names the file that exists. A single overwrite must produce exactly one
// attested .bak whose stored content matches its chain-recorded SHA-256.
func TestSignedWriteFile_OverwriteAttestedBackup(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "cfg.conf")
	kc := secrets.NewMockStore()
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	original := []byte("original-content")
	require.NoError(t, os.WriteFile(target, original, 0o600)) //nolint:gosec // G306: test fixture under temp dir

	require.NoError(t, sa.WriteFile(target, []byte("new-content"), 0o600, false))

	// Exactly one backup chain entry for this overwrite.
	backups, err := audit.BackupsFromChain(logPath, target)
	require.NoError(t, err)
	require.Len(t, backups, 1, "exactly one attested .bak per overwrite")

	// The .bak named in the chain must exist on disk...
	bakPath := backups[0].Target
	bakContent, err := os.ReadFile(bakPath) //nolint:gosec // G304: bakPath is read from the chain entry under the test temp dir
	require.NoError(t, err, "chain-recorded .bak must exist on disk (no path mismatch)")

	// ...and hold exactly the bytes whose hash the chain attested (no TOCTOU).
	assert.Equal(t, original, bakContent, "physical .bak content matches pre-overwrite content")
	sum := sha256.Sum256(bakContent)
	assert.Equal(t, hex.EncodeToString(sum[:]), backups[0].Hash,
		"physical .bak hash matches chain-recorded hash")

	// Exactly one .bak.* file on disk for this overwrite.
	globbed, err := filepath.Glob(target + ".bak.*")
	require.NoError(t, err)
	assert.Len(t, globbed, 1, "exactly one physical .bak per overwrite")

	res, err := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, err)
	assert.True(t, res.OK)
}

// TestSignedWriteFile_ConcurrentSameTarget proves CR-02: concurrent WriteFile
// calls to the SAME target serialise under the mutex+flock instead of racing on
// a shared temp path. The final file must be one of the written intents in full
// (never a torn mix), and the chain must verify. Run with -race.
func TestSignedWriteFile_ConcurrentSameTarget(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	target := filepath.Join(dir, "shared.conf")
	kc := secrets.NewMockStore()
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	const writers = 8
	// Each writer writes a distinct, large payload so a torn write would be
	// detectable as a non-uniform buffer.
	payloads := make([][]byte, writers)
	valid := make(map[string]struct{}, writers)
	for i := range payloads {
		b := make([]byte, 64*1024)
		for j := range b {
			b[j] = byte('A' + i)
		}
		payloads[i] = b
		sum := sha256.Sum256(b)
		valid[hex.EncodeToString(sum[:])] = struct{}{}
	}

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(p []byte) {
			defer wg.Done()
			assert.NoError(t, sa.WriteFile(target, p, 0o600, false))
		}(payloads[i])
	}
	wg.Wait()

	// The landed file must be exactly one of the payloads (no torn mix).
	got, err := os.ReadFile(target) //nolint:gosec // G304: test reads its own temp fixture
	require.NoError(t, err)
	sum := sha256.Sum256(got)
	_, ok := valid[hex.EncodeToString(sum[:])]
	assert.True(t, ok, "landed file must equal one writer's full payload (no torn write)")

	// No stray temp files left behind.
	tmps, err := filepath.Glob(target + ".*.abysslink.tmp")
	require.NoError(t, err)
	assert.Empty(t, tmps, "no leftover temp files after concurrent writes")

	// The hash chain must verify after concurrent same-target writes.
	res, err := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, err)
	assert.True(t, res.OK, "chain must verify after concurrent same-target writes")
}
