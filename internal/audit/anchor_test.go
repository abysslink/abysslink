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
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSomeEntries appends n signed entries to logPath via SignedAudit.
func writeSomeEntries(t *testing.T, sa *audit.SignedAudit, n int) {
	t.Helper()
	for i := range n {
		require.NoError(t, sa.Append(context.Background(), audit.SignInput{
			Title:    "write",
			DiffHash: sha256.Sum256([]byte{byte(i)}),
		}, "/etc/x", false))
	}
}

func TestWriteAnchor_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)

	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	anchorFile := filepath.Join(dir, "audit.anchor.json")
	info, serr := os.Stat(anchorFile)
	require.NoError(t, serr)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	a, rerr := audit.ReadAnchor(logPath)
	require.NoError(t, rerr)
	require.NotNil(t, a)
	assert.Equal(t, int64(3), a.EntryCount)
	assert.NotEmpty(t, a.LastHash)
	assert.NotEmpty(t, a.Time)
	assert.NotEmpty(t, a.HMAC)
}

func TestReadAnchor_Missing(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	a, err := audit.ReadAnchor(logPath)
	require.NoError(t, err)
	assert.Nil(t, a)
}

func TestVerifyAnchor_CleanAndTampered(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 2)
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	ok, verr := audit.VerifyAnchor(logPath, kc)
	require.NoError(t, verr)
	assert.True(t, ok, "unmodified anchor must verify")

	// Tamper: bump EntryCount without re-signing.
	anchorFile := filepath.Join(dir, "audit.anchor.json")
	data, _ := os.ReadFile(anchorFile) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	var a audit.Anchor
	require.NoError(t, json.Unmarshal(data, &a))
	a.EntryCount = 9999
	bad, _ := json.Marshal(a)
	require.NoError(t, os.WriteFile(anchorFile, bad, 0o600))

	ok, verr = audit.VerifyAnchor(logPath, kc)
	require.NoError(t, verr)
	assert.False(t, ok, "tampered anchor HMAC must not verify")
}

func TestVerifyAnchor_MissingIsNotViolation(t *testing.T) {
	kc := seededStore(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	ok, err := audit.VerifyAnchor(logPath, kc)
	require.NoError(t, err)
	assert.True(t, ok)
}

// ─── AUD-02: ReadCounter / WriteCounter / incrementCounter ───────────────────

// TestReadCounter_Absent: a fresh MockKeychain has no counter; ReadCounter must
// return (0, false, nil) — absent is first use, not an error.
func TestReadCounter_Absent(t *testing.T) {
	kc := secrets.NewMockStore() // no counter key set
	n, found, err := audit.ReadCounter(context.Background(), kc)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, int64(0), n)
}

// TestReadCounter_Present: after WriteCounter(42), ReadCounter must return
// (42, true, nil).
func TestReadCounter_Present(t *testing.T) {
	kc := secrets.NewMockStore()
	require.NoError(t, audit.WriteCounter(context.Background(), kc, 42))
	n, found, err := audit.ReadCounter(context.Background(), kc)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(42), n)
}

// TestIncrementCounter_FirstUse: incrementCounter on a fresh store must write
// counter=1 (0 base + 1 increment).
func TestIncrementCounter_FirstUse(t *testing.T) {
	kc := secrets.NewMockStore()
	require.NoError(t, audit.IncrementCounter(context.Background(), kc))
	n, found, err := audit.ReadCounter(context.Background(), kc)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(1), n)
}

// TestIncrementCounter_Existing: increment counter from 7 → must produce 8.
func TestIncrementCounter_Existing(t *testing.T) {
	kc := secrets.NewMockStore()
	require.NoError(t, audit.WriteCounter(context.Background(), kc, 7))
	require.NoError(t, audit.IncrementCounter(context.Background(), kc))
	n, found, err := audit.ReadCounter(context.Background(), kc)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(8), n)
}

// ─── AUD-02: Append anchor-every-entry / anchor-fail-aborts / Verify tri-state ─

// TestAppend_AnchorEveryEntry: WriteAnchor is called after EVERY Append call
// (not every 100). After two Appends the anchor file must exist and record
// entry_count=2.
func TestAppend_AnchorEveryEntry(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	// Append entry 1 — anchor must exist with count=1.
	require.NoError(t, sa.Append(context.Background(), audit.SignInput{
		Title:    "write",
		DiffHash: sha256.Sum256([]byte("a")),
	}, "/etc/a", false))

	a1, rerr := audit.ReadAnchor(logPath)
	require.NoError(t, rerr)
	require.NotNil(t, a1, "anchor must exist after first Append")
	assert.Equal(t, int64(1), a1.EntryCount, "anchor entry_count must be 1 after first Append")

	// Append entry 2 — anchor must update to count=2.
	require.NoError(t, sa.Append(context.Background(), audit.SignInput{
		Title:    "write",
		DiffHash: sha256.Sum256([]byte("b")),
	}, "/etc/b", false))

	a2, rerr2 := audit.ReadAnchor(logPath)
	require.NoError(t, rerr2)
	require.NotNil(t, a2, "anchor must exist after second Append")
	assert.Equal(t, int64(2), a2.EntryCount, "anchor entry_count must be 2 after second Append")
}

// TestAppend_FailsOnAnchorWriteError: when the anchor cannot be written, the
// mutation must abort — WriteFile returns an error containing "anchor write
// failed (mutation aborted)" and must NOT write the physical file.
//
// Since R2-12 the HMAC key is cached in memory, so a keychain outage can no
// longer fail the anchor write; the failure is modelled at the filesystem
// level instead (the log directory becomes unwritable, so the anchor's temp
// file cannot be created — appends to the EXISTING log file still succeed).
func TestAppend_FailsOnAnchorWriteError(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "state")
	require.NoError(t, os.Mkdir(logDir, 0o700))
	kc := seededStore(t)
	logPath := filepath.Join(logDir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	// Prime: one successful append creates the log, the lock file and the anchor.
	writeSomeEntries(t, sa, 1)

	// Make the log directory unwritable: the next anchor refresh cannot create
	// its temp file, while the JSONL append (existing 0600 file) still works.
	require.NoError(t, os.Chmod(logDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(logDir, 0o700) })

	targetFile := filepath.Join(dir, "target.txt") // separate, writable dir
	werr := sa.WriteFile(targetFile, []byte("content"), 0o600, false)
	require.Error(t, werr, "WriteFile must fail when anchor write fails")
	assert.Contains(t, werr.Error(), "anchor write failed (mutation aborted)")

	// Physical file must NOT have been written.
	_, serr := os.Stat(targetFile)
	assert.True(t, os.IsNotExist(serr), "target file must not exist when anchor write aborts the mutation")
}

// TestVerify_CounterAbsent_Unknown: a signed log with entries but no keychain
// counter must produce CounterStatus="unknown" (never coerced to PASS).
func TestVerify_CounterAbsent_Unknown(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t) // has HMAC key; counter key is absent
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 3)

	// Manually delete the counter key if it was set (by Append's incrementCounter).
	// In a pre-AUD-02 scenario, the counter does not exist; here we clear it to
	// simulate that.
	_ = kc.Delete(context.Background(), "abysslink", "audit-counter")

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.Equal(t, "unknown", res.CounterStatus,
		"absent keychain counter must produce CounterStatus=unknown, never PASS")
	assert.False(t, res.TruncationDetected,
		"absent counter must not falsely set TruncationDetected")
}

// TestVerify_CounterMismatch_TruncationDetected: keychain counter=7 but log has
// 5 entries → TruncationDetected=true and CounterStatus="mismatch". Genuine tail
// truncation is modeled as counter > entries: the tamper-resistant keychain
// counter retains the original (higher) count while the on-disk log loses tail
// entries. counter < entries is the OPPOSITE direction (the benign append-before-
// write window) and must NOT be flagged — see TestVerify_CounterLagging_NotMismatch.
func TestVerify_CounterMismatch_TruncationDetected(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 5) // writes 5 entries + sets counter=5

	// Simulate tail-deletion: counter records 7 appends but only 5 entries remain
	// on disk (2 tail entries were stripped by an attacker who cannot touch the
	// keychain counter). counter(7) > entries(5) → genuine truncation.
	require.NoError(t, audit.WriteCounter(context.Background(), kc, 7))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.TruncationDetected,
		"counter > entries must set TruncationDetected=true")
	assert.Equal(t, "mismatch", res.CounterStatus)
}

// TestVerify_CounterLagging_NotMismatch is the automated coverage for the
// append-before-write crash window (25-VERIFICATION human item #1). When the
// keychain counter LAGS the on-disk entry count — counter < entries — it means
// a process died between appending chain-valid JSONL entries under the flock and
// bumping the keychain counter. Every entry is HMAC-chain-verified by the walk,
// so a log-only attacker cannot have forged the extra entries; this is therefore
// never truncation. Verify MUST report CounterStatus="unknown" (honest tri-state)
// and MUST NOT set TruncationDetected — a false "mismatch" tamper alarm here would
// fire on every interrupted WriteFile.
func TestVerify_CounterLagging_NotMismatch(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 5) // 5 chain-valid entries + counter=5

	// Roll the counter back below the entry count to model a crash that landed
	// the entries but not the counter bump (counter=3 < entries=5).
	require.NoError(t, audit.WriteCounter(context.Background(), kc, 3))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.Equal(t, "unknown", res.CounterStatus,
		"counter lagging entries (append-before-write window) must be unknown, never mismatch")
	assert.False(t, res.TruncationDetected,
		"a lagging counter must never set TruncationDetected (no genuine truncation)")
	assert.True(t, res.OK,
		"chain is intact; only the counter is behind — overall result stays OK")
}

// TestVerify_CounterVerified: 5 entries appended normally → counter=5;
// Verify must produce CounterStatus="verified" and TruncationDetected=false.
func TestVerify_CounterVerified(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 5)

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.Equal(t, "verified", res.CounterStatus,
		"counter matching log entry count must produce CounterStatus=verified")
	assert.False(t, res.TruncationDetected)
}

// ─────────────────────────────────────────────────────────────────────────────

func TestWriteAnchor_AtomicUnderConcurrentRead(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 5)
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = audit.WriteAnchor(context.Background(), logPath, kc)
		}()
		go func() {
			defer wg.Done()
			// Reader never sees a partial file (temp+rename atomicity).
			if a, rerr := audit.ReadAnchor(logPath); rerr == nil && a != nil {
				assert.NotEmpty(t, a.HMAC)
			}
		}()
	}
	wg.Wait()
}
