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
	"fmt"
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

// errAfterNStore wraps MockStore and makes kc.Get fail after N successful calls.
// Used to simulate a keychain becoming unavailable after SignedAudit construction.
type errAfterNStore struct {
	inner    *secrets.MockStore
	limit    int
	getCalls int
}

func (e *errAfterNStore) Set(ctx context.Context, service, account, secret string) error {
	return e.inner.Set(ctx, service, account, secret)
}
func (e *errAfterNStore) Get(ctx context.Context, service, account string) (string, error) {
	e.getCalls++
	if e.getCalls > e.limit {
		return "", fmt.Errorf("keychain unavailable (simulated)")
	}
	return e.inner.Get(ctx, service, account)
}
func (e *errAfterNStore) Delete(ctx context.Context, service, account string) error {
	return e.inner.Delete(ctx, service, account)
}

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

// TestAppend_FailsOnAnchorWriteError: when WriteAnchor fails (keychain becomes
// unavailable after construction), Append must return an error containing
// "anchor write failed (mutation aborted)" and WriteFile must NOT write the
// physical file.
func TestAppend_FailsOnAnchorWriteError(t *testing.T) {
	dir := t.TempDir()
	inner := seededStore(t)
	// Allow exactly 2 Get calls: one for NewSigned (key existence check) and
	// one for Append's hmacKey call. The third Get (inside WriteAnchor's
	// fetchHMACKey) will fail, triggering anchor write failure.
	kc := &errAfterNStore{inner: inner, limit: 2}
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	targetFile := filepath.Join(dir, "target.txt")
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

// TestVerify_CounterMismatch_TruncationDetected: keychain counter=3 but log
// has 5 entries → TruncationDetected=true and CounterStatus="mismatch".
func TestVerify_CounterMismatch_TruncationDetected(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	writeSomeEntries(t, sa, 5) // writes 5 entries + sets counter=5

	// Simulate tail-deletion: reset counter to 3 (as if 2 tail entries deleted).
	require.NoError(t, audit.WriteCounter(context.Background(), kc, 3))

	res, verr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verr)
	assert.True(t, res.TruncationDetected,
		"counter mismatch must set TruncationDetected=true")
	assert.Equal(t, "mismatch", res.CounterStatus)
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
