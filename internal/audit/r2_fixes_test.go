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

// R2 review-fix regression tests: mixed signed/unsigned writers (C1), anchor
// bypass attacks (C2), WriteFilePath contract (W1), signed symlink refusal
// (W2), restore hardening (W3), HMAC key generation race (W5), and reversal
// audit entries (fix 9).
package audit_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
)

// ─── R2-C1: unsigned writers on a signed chain must not brick Verify ─────────

// TestMixedWriters_UnsignedAppendKeepsChainVerifiable is THE C1 regression:
// a signed append followed by an unsigned-API append (the config.Write /
// claudecode / platform-service / journey production path) must leave the log
// fully verifiable — previously the unsigned writer appended a bare legacy
// entry and walkChain reported "CHAIN BROKEN (tamper)" forever.
func TestMixedWriters_UnsignedAppendKeepsChainVerifiable(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	ctx := context.Background()

	// 1. Signed write (the normal `up` path).
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	require.NoError(t, sa.Append(ctx, audit.SignInput{
		Title: "write", DiffHash: sha256.Sum256([]byte("signed")),
	}, "/etc/signed", false))

	// 2. Unsigned-API write with the same keychain (e.g. config.Write).
	w := audit.NewWithKeychain(logPath, kc)
	require.NoError(t, w.Append("write", "/etc/unsigned-api", []byte("cfg"), false))

	// The unsigned-API entry must be FULLY signed (chain link + HMAC sig).
	entries, rerr := audit.ReadLog(logPath)
	require.NoError(t, rerr)
	require.Len(t, entries, 2)
	assert.NotEmpty(t, entries[1].PrevHash, "chain-aware unsigned append must carry the chain link")
	assert.NotEmpty(t, entries[1].Sig, "chain-aware unsigned append must be HMAC-signed when the key is reachable")

	// 3. Verify: chain intact, both sigs verified, counter in step.
	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "mixed signed + unsigned-API writers must verify: %s", res.Reason)
	assert.Equal(t, 2, res.SigsVerified)
	assert.Equal(t, "verified", res.CounterStatus, "the unsigned-API signed append must also bump the counter")

	// 4. A later signed append still links cleanly on top.
	require.NoError(t, sa.Append(ctx, audit.SignInput{
		Title: "write", DiffHash: sha256.Sum256([]byte("more")),
	}, "/etc/more", false))
	res2, verr2 := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr2)
	assert.True(t, res2.OK)
	assert.Equal(t, 3, res2.SigsVerified)
}

// TestMixedWriters_KeychainlessFallbackKeepsChainIntact: when the unsigned
// writer cannot reach the HMAC key (here: audit.New in a test binary, whose
// platform-keychain probe is disabled), it must append a CHAINED-unsigned
// entry (prev_hash set, no sig) — Verify reports a skipped signature, never
// CHAIN BROKEN.
func TestMixedWriters_KeychainlessFallbackKeepsChainIntact(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	ctx := context.Background()

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 2)

	// Unsigned writer with NO keychain access (default New under `go test`).
	w := audit.New(logPath)
	require.NoError(t, w.Append("write", "/etc/fallback", []byte("x"), false))

	entries, rerr := audit.ReadLog(logPath)
	require.NoError(t, rerr)
	require.Len(t, entries, 3)
	assert.NotEmpty(t, entries[2].PrevHash, "fallback entry must keep the chain link")
	assert.Empty(t, entries[2].Sig, "fallback entry cannot be signed without the key")

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "chained-unsigned fallback must not break the chain: %s", res.Reason)
	assert.Equal(t, 2, res.SigsVerified)
	assert.Equal(t, 1, res.SigsSkipped)
	// The anchor lags (the fallback writer cannot re-sign it) — that is the
	// legitimate prefix-lag case the R2-C2 fix must keep accepting.
	assert.False(t, res.TruncationDetected)

	// And a later signed append heals the tail: everything verifies again.
	require.NoError(t, sa.Append(ctx, audit.SignInput{
		Title: "write", DiffHash: sha256.Sum256([]byte("heal")),
	}, "/etc/heal", false))
	res2, verr2 := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr2)
	assert.True(t, res2.OK)
}

// TestMixedWriters_UnsignedWriteFileOnActiveChain: the AuditWriter WriteFile
// path (used via modules.Deps fallback wiring) must also participate in the
// chain.
func TestMixedWriters_UnsignedWriteFileOnActiveChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	ctx := context.Background()

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 1)

	w := audit.NewWithKeychain(logPath, kc)
	target := filepath.Join(dir, "cfg.yaml")
	require.NoError(t, w.WriteFile(target, []byte("v: 1"), 0o600, false))

	got, rerr := os.ReadFile(target) //nolint:gosec // test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "v: 1", string(got))

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "unsigned WriteFile on an active chain must keep the log verifiable: %s", res.Reason)
}

// TestLegacyLog_UnsignedAppendStaysLegacy: a log with no chain must keep the
// exact v1/v2 behaviour — no prev_hash, no sig, no keychain interaction.
func TestLegacyLog_UnsignedAppendStaysLegacy(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	w := audit.New(logPath)
	require.NoError(t, w.Append("write", "/etc/a", []byte("a"), false))
	require.NoError(t, w.Append("write", "/etc/b", []byte("b"), false))

	entries, err := audit.ReadLog(logPath)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, e := range entries {
		assert.Empty(t, e.PrevHash)
		assert.Empty(t, e.Sig)
	}
}

// ─── R2-C2: anchor bypass attacks ─────────────────────────────────────────────

// legacyLine builds a raw legacy (unsigned, unchained) JSONL line.
func legacyLine(t *testing.T, op, target, content string) []byte {
	t.Helper()
	e := audit.Entry{
		Time:   time.Now().UTC(),
		Op:     op,
		Target: target,
		Hash:   audit.HashOf([]byte(content)),
	}
	b, err := json.Marshal(e)
	require.NoError(t, err)
	return append(b, '\n')
}

// TestVerify_AnchorDeletionWithKeyFails is C2 attack (a): replace the signed
// log with unsigned "legacy" entries and DELETE the anchor. The HMAC key still
// in the keychain proves a chain existed, so the missing anchor must FAIL —
// previously this combination returned OK with only SigsSkipped as a hint.
func TestVerify_AnchorDeletionWithKeyFails(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	ctx := context.Background()

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)

	// Attacker (filesystem-only): replace the log with legacy entries and
	// delete the anchor.
	forged := append(legacyLine(t, "write", "/etc/a", "a"), legacyLine(t, "write", "/etc/b", "b")...)
	forged = append(forged, legacyLine(t, "write", "/etc/c", "c")...)
	require.NoError(t, os.WriteFile(logPath, forged, 0o600))
	require.NoError(t, os.Remove(filepath.Join(dir, "audit.anchor.json")))

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK, "anchor deletion with the HMAC key present must FAIL verification")
	assert.Contains(t, res.Reason, "anchor missing")
}

// TestVerify_BareAnchorDeletionFails: even without touching the log, deleting
// only the anchor file must fail once a chain exists.
func TestVerify_BareAnchorDeletionFails(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 2)
	require.NoError(t, os.Remove(filepath.Join(dir, "audit.anchor.json")))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK, "deleting the anchor must be a verification failure, not 'no anchor yet'")
	assert.Contains(t, res.Reason, "anchor missing")
}

// TestVerify_AnchoredPrefixRewriteFails is C2 attack (b): replace the log with
// MORE legacy entries than the anchor records. The old equality-only LastHash
// check skipped this case entirely; the anchored PREFIX must now end in the
// recorded LastHash.
func TestVerify_AnchoredPrefixRewriteFails(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 2) // anchor records EntryCount=2

	// Attacker: replace the whole log with 3 legacy entries (>= counter and
	// > anchor count, so neither the counter nor the count check fires).
	forged := append(legacyLine(t, "write", "/etc/x", "x"), legacyLine(t, "write", "/etc/y", "y")...)
	forged = append(forged, legacyLine(t, "write", "/etc/z", "z")...)
	require.NoError(t, os.WriteFile(logPath, forged, 0o600))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.False(t, res.OK, "a rewritten anchored prefix must FAIL even when the log outgrew the anchor")
	assert.Contains(t, res.Reason, "anchor last_hash mismatch")
}

// ─── R2-W1: WriteFilePath contract ───────────────────────────────────────────

// TestWriteFilePath_DryRunMutatesNothing: --dry-run must not append chain
// entries, refresh the anchor, bump the counter, or write dst (CORE-05 parity;
// previously the entry+anchor+counter all landed BEFORE the dryRun check).
func TestWriteFilePath_DryRunMutatesNothing(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	require.NoError(t, os.WriteFile(src, []byte("payload"), 0o600))

	ctx := context.Background()
	require.NoError(t, sa.WriteFilePath(ctx, src, dst, 0o755, true))

	_, statErr := os.Stat(dst)
	assert.True(t, os.IsNotExist(statErr), "dry-run must not write dst")

	entries, rerr := audit.ReadLog(logPath)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "dry-run must not append chain entries")

	_, found, cerr := audit.ReadCounter(ctx, kc)
	require.NoError(t, cerr)
	assert.False(t, found, "dry-run must not initialise the keychain counter")

	a, aerr := audit.ReadAnchor(logPath)
	require.NoError(t, aerr)
	assert.Nil(t, a, "dry-run must not write an anchor")
}

// TestWriteFilePath_BacksUpExistingDst: rule 8 — replacing an existing binary
// must leave a chain-attested .bak of the old content (previously the old
// file was destroyed with no backup).
func TestWriteFilePath_BacksUpExistingDst(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	src := filepath.Join(dir, "new-binary")
	dst := filepath.Join(dir, "installed-binary")
	require.NoError(t, os.WriteFile(src, []byte("NEW-BINARY"), 0o755)) //nolint:gosec // test fixture
	require.NoError(t, os.WriteFile(dst, []byte("OLD-BINARY"), 0o755)) //nolint:gosec // test fixture

	ctx := context.Background()
	require.NoError(t, sa.WriteFilePath(ctx, src, dst, 0o755, false))

	got, rerr := os.ReadFile(dst) //nolint:gosec // test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "NEW-BINARY", string(got))

	// Chain-attested backup of the OLD content must exist.
	baks, berr := audit.BackupsFromChain(logPath, dst)
	require.NoError(t, berr)
	require.Len(t, baks, 1, "the binary swap must record a chain-attested backup")
	bakContent, rerr2 := os.ReadFile(baks[0].Target) //nolint:gosec // path from the chain entry under the test temp dir
	require.NoError(t, rerr2)
	assert.Equal(t, "OLD-BINARY", string(bakContent))
	assert.Equal(t, audit.HashOf(bakContent), baks[0].Hash, "the .bak bytes must match the chain-attested hash")

	// Write-intent hash must match the installed bytes (single-read TeeReader
	// hash — no hash-then-reopen window).
	entries, lerr := audit.ReadLog(logPath)
	require.NoError(t, lerr)
	require.Len(t, entries, 2)
	assert.Equal(t, "write", entries[1].Op)
	assert.Equal(t, audit.HashOf([]byte("NEW-BINARY")), entries[1].Hash)

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK)
	assert.Equal(t, "verified", res.CounterStatus, "counter must equal entries after the batched backup+write")
}

// TestWriteFilePath_RefusesSymlinkDst: parity with WriteFile's CORE-03 check.
func TestWriteFilePath_RefusesSymlinkDst(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	victim := filepath.Join(dir, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("untouchable"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(victim, link))
	src := filepath.Join(dir, "src")
	require.NoError(t, os.WriteFile(src, []byte("attack"), 0o600))

	werr := sa.WriteFilePath(context.Background(), src, link, 0o600, false)
	require.Error(t, werr)
	assert.Contains(t, werr.Error(), "symlink")

	got, rerr := os.ReadFile(victim) //nolint:gosec // test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "untouchable", string(got))
}

// ─── R2-W2: signed WriteFile symlink refusal ─────────────────────────────────

func TestSignedWriteFile_RefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	victim := filepath.Join(dir, "victim.conf")
	require.NoError(t, os.WriteFile(victim, []byte("untouchable"), 0o600))
	link := filepath.Join(dir, "link.conf")
	require.NoError(t, os.Symlink(victim, link))

	werr := sa.WriteFile(link, []byte("attack"), 0o600, false)
	require.Error(t, werr, "signed WriteFile must refuse a symlink target (parity with the unsigned path)")
	assert.Contains(t, werr.Error(), "symlink")

	got, rerr := os.ReadFile(victim) //nolint:gosec // test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "untouchable", string(got), "the symlink target must be untouched")

	entries, lerr := audit.ReadLog(logPath)
	require.NoError(t, lerr)
	assert.Empty(t, entries, "a refused write must not record chain entries")
}

// ─── R2-W3: restore hardening ────────────────────────────────────────────────

// TestRestore_DoesNotFollowPlantedTmpSymlink: the old restore wrote to the
// PREDICTABLE dst+".tmp" via os.WriteFile (O_CREATE|O_TRUNC follows a
// pre-planted symlink). The unique os.CreateTemp temp must never write through
// the planted link.
func TestRestore_DoesNotFollowPlantedTmpSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("untouchable"), 0o600))

	dst := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(dst, []byte("current"), 0o600))
	bak := dst + ".bak.20260101T000000.000000000Z"
	require.NoError(t, os.WriteFile(bak, []byte("original"), 0o600))

	// Attacker pre-plants the predictable temp path as a symlink to the victim.
	require.NoError(t, os.Symlink(victim, dst+".tmp"))

	require.NoError(t, audit.Restore(dst, bak))

	got, rerr := os.ReadFile(victim) //nolint:gosec // test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "untouchable", string(got), "restore must never write through a planted dst+.tmp symlink")

	restored, rerr2 := os.ReadFile(dst) //nolint:gosec // test reads its own temp fixture
	require.NoError(t, rerr2)
	assert.Equal(t, "original", string(restored))
}

// TestBackupRestore_PreservesMode: a 0644 original must come back 0644 after a
// backup+restore round trip (previously restores forced 0600 onto everything).
func TestBackupRestore_PreservesMode(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "unit.service")
	require.NoError(t, os.WriteFile(original, []byte("[Unit]"), 0o644)) //nolint:gosec // 0644 is the point of this test

	bakPath, err := audit.Backup(original)
	require.NoError(t, err)
	bfi, serr := os.Stat(bakPath)
	require.NoError(t, serr)
	assert.Equal(t, os.FileMode(0o644), bfi.Mode().Perm(), "backup must record the original's mode")

	// Clobber the original with different content and mode.
	require.NoError(t, os.WriteFile(original, []byte("corrupted"), 0o600))
	require.NoError(t, os.Chmod(original, 0o600))

	require.NoError(t, audit.Restore(original, bakPath))
	fi, serr2 := os.Stat(original)
	require.NoError(t, serr2)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "restore must reinstate the recorded mode, not force 0600")
	got, rerr := os.ReadFile(original) //nolint:gosec // test reads its own temp fixture
	require.NoError(t, rerr)
	assert.Equal(t, "[Unit]", string(got))
}

// TestSignedWriteFile_BackupPreservesMode: the signed overwrite path's .bak
// (backupNoRefresh) must also carry the original's permission bits so a later
// chain-verified Reverse can put them back.
func TestSignedWriteFile_BackupPreservesMode(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	target := filepath.Join(dir, "unit.service")
	require.NoError(t, os.WriteFile(target, []byte("ORIGINAL"), 0o644)) //nolint:gosec // 0644 is the point of this test
	require.NoError(t, sa.WriteFile(target, []byte("MODIFIED"), 0o644, false))

	baks, berr := audit.BackupsFromChain(logPath, target)
	require.NoError(t, berr)
	require.Len(t, baks, 1)
	bfi, serr := os.Stat(baks[0].Target)
	require.NoError(t, serr)
	assert.Equal(t, os.FileMode(0o644), bfi.Mode().Perm())

	// Reverse restores the original content AND mode.
	manifest, rerr := audit.Reverse(logPath, false)
	require.NoError(t, rerr)
	require.Len(t, manifest, 1)
	require.NoError(t, manifest[0].Err)
	fi, serr2 := os.Stat(target)
	require.NoError(t, serr2)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "Reverse must restore the original 0644, not 0600")
}

// ─── R2-W5/12: HMAC key generation is lazy and race-free ─────────────────────

// TestLazyKeyGeneration_ConcurrentFirstAppend: two SignedAudit instances (the
// CLI + daemon first-run shape) sharing one keychain and one log must converge
// on a SINGLE key — generation happens under the audit flock, so every signed
// entry verifies afterwards.
func TestLazyKeyGeneration_ConcurrentFirstAppend(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := secrets.NewMockStore() // empty: both instances see ErrNotFound
	ctx := context.Background()

	sa1, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	sa2, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	const perWriter = 10
	var wg sync.WaitGroup
	for i := range perWriter {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			assert.NoError(t, sa1.Append(ctx, audit.SignInput{
				Title: "write", DiffHash: sha256.Sum256([]byte(fmt.Sprintf("a%d", i))),
			}, fmt.Sprintf("/etc/a%d", i), false))
		}(i)
		go func(i int) {
			defer wg.Done()
			assert.NoError(t, sa2.Append(ctx, audit.SignInput{
				Title: "write", DiffHash: sha256.Sum256([]byte(fmt.Sprintf("b%d", i))),
			}, fmt.Sprintf("/etc/b%d", i), false))
		}(i)
	}
	wg.Wait()

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "every entry must verify under the single surviving key: %s", res.Reason)
	assert.Equal(t, 2*perWriter, res.SigsVerified,
		"all entries must be signed with the one key both writers converged on")
}

// ─── R2 fix 9: reversal mutations get audit entries ──────────────────────────

func TestReverse_RecordsRestoreAndDeleteEntries(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	pre := filepath.Join(dir, "existing.conf")
	require.NoError(t, os.WriteFile(pre, []byte("ORIGINAL"), 0o600))
	require.NoError(t, sa.WriteFile(pre, []byte("MODIFIED"), 0o600, false))
	created := filepath.Join(dir, "created.conf")
	require.NoError(t, sa.WriteFile(created, []byte("new"), 0o600, false))

	manifest, rerr := audit.Reverse(logPath, false)
	require.NoError(t, rerr)
	require.Len(t, manifest, 2)
	for _, act := range manifest {
		require.NoError(t, act.Err)
	}

	// Rule 8: the restore and the deletion must each have an audit entry.
	entries, lerr := audit.ReadLog(logPath)
	require.NoError(t, lerr)
	ops := map[string][]string{}
	for _, e := range entries {
		ops[e.Op] = append(ops[e.Op], e.Target)
	}
	assert.Contains(t, ops["restore"], pre, "the reversal restore must be recorded")
	assert.Contains(t, ops["delete"], created, "the reversal deletion must be recorded")

	// And the log must still verify (the reversal writer is chain-aware).
	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK, "reversal entries must not break the chain: %s", res.Reason)
}

func TestRestoreGated_ChainVerifiedRestoreIsRecorded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	ctx := context.Background()

	dst := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(dst, []byte("ORIGINAL"), 0o600))
	require.NoError(t, sa.WriteFile(dst, []byte("MODIFIED"), 0o600, false))

	baks, berr := audit.BackupsFromChain(logPath, dst)
	require.NoError(t, berr)
	require.Len(t, baks, 1)

	require.NoError(t, audit.RestoreGated(ctx, dst, baks[0].Target, sa, false))

	entries, lerr := audit.ReadLog(logPath)
	require.NoError(t, lerr)
	var restoreRecorded bool
	for _, e := range entries {
		if e.Op == "restore" && e.Target == dst {
			restoreRecorded = true
			assert.Equal(t, audit.HashOf([]byte("ORIGINAL")), e.Hash)
		}
	}
	assert.True(t, restoreRecorded, "a chain-verified RestoreGated must record a 'restore' entry (rule 8)")

	res, verr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.OK)
}

// ─── R2-I1: BackupsFromChain sibling-prefix footgun ──────────────────────────

func TestBackupsFromChain_DoesNotClaimSiblingTargets(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	ctx := context.Background()

	target := filepath.Join(dir, "b")
	sibling := filepath.Join(dir, "b2")
	bakSibling := sibling + ".bak.20260101T000000.000000000Z"
	require.NoError(t, sa.Append(ctx, audit.SignInput{
		Title: "backup", DiffHash: sha256.Sum256([]byte("sib")),
	}, bakSibling, false))

	got, berr := audit.BackupsFromChain(logPath, target)
	require.NoError(t, berr)
	assert.Empty(t, got, "a backup of /a/b2 must never be claimed for target /a/b")

	gotSibling, berr2 := audit.BackupsFromChain(logPath, sibling)
	require.NoError(t, berr2)
	assert.Len(t, gotSibling, 1, "the sibling's own backup must still match")
}
