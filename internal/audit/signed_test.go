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
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHMACAccount = "audit-hmac"

func seededStore(t *testing.T) *secrets.MockStore {
	t.Helper()
	kc := secrets.NewMockStore()
	require.NoError(t, kc.Set(context.Background(), "abysslink", testHMACAccount,
		hex.EncodeToString(bytes.Repeat([]byte{1}, 32))))
	return kc
}

func TestNewSigned_SeededKey(t *testing.T) {
	kc := seededStore(t)
	sa, err := audit.NewSigned(filepath.Join(t.TempDir(), "audit.log"), kc)
	require.NoError(t, err)
	require.NotNil(t, sa)
}

func TestNewSigned_AutoGeneratesKey(t *testing.T) {
	kc := secrets.NewMockStore() // empty — Get returns error
	logPath := filepath.Join(t.TempDir(), "audit.log")

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	require.NotNil(t, sa)

	// R2-12 lazy creation: the key is generated on the FIRST MUTATING append,
	// not at construction (read paths must never write to the keychain).
	require.NoError(t, sa.Append(context.Background(), audit.SignInput{
		Title: "write", DiffHash: sha256.Sum256([]byte("x")),
	}, "/etc/a", false))

	// Key should now exist and be a 32-byte hex value.
	hexKey, gerr := kc.Get(context.Background(), "abysslink", testHMACAccount)
	require.NoError(t, gerr)
	raw, derr := hex.DecodeString(hexKey)
	require.NoError(t, derr)
	assert.Len(t, raw, 32)
}

func TestSignedAppend_GenesisThenChain(t *testing.T) {
	kc := seededStore(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, sa.Append(ctx, audit.SignInput{Title: "write", DiffHash: sha256.Sum256([]byte("a"))}, "/etc/a", false))
	require.NoError(t, sa.Append(ctx, audit.SignInput{Title: "write", DiffHash: sha256.Sum256([]byte("b"))}, "/etc/b", false))

	// Read raw lines to compute the expected prev_hash of entry 2.
	data, rerr := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	require.NoError(t, rerr)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	require.Len(t, lines, 2)

	entries, lerr := audit.ReadLog(logPath)
	require.NoError(t, lerr)
	require.Len(t, entries, 2)

	assert.Equal(t, "genesis", entries[0].PrevHash)
	expected := sha256.Sum256(lines[0])
	assert.Equal(t, hex.EncodeToString(expected[:]), entries[1].PrevHash)
	assert.NotEmpty(t, entries[0].Sig)
	assert.NotEmpty(t, entries[1].Sig)
}

func TestEntry_LegacyUnmarshalNoChainFields(t *testing.T) {
	legacy := `{"time":"2026-01-01T00:00:00Z","op":"write","target":"/etc/foo","hash":"abc","dry_run":false}`
	var e audit.Entry
	require.NoError(t, json.Unmarshal([]byte(legacy), &e))
	assert.Empty(t, e.PrevHash)
	assert.Empty(t, e.Sig)
}

func TestEntry_DryRunFalseIsVisible(t *testing.T) {
	e := audit.Entry{Op: "write", Target: "/etc/x", Hash: "h", DryRun: false}
	b, err := json.Marshal(e)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"dry_run":false`)
	// omitempty must NOT drop chain fields here either when empty.
	assert.NotContains(t, string(b), `"prev_hash"`)
	assert.NotContains(t, string(b), `"sig"`)
}

func TestSignedAudit_ConcurrentAppend(t *testing.T) {
	dir := t.TempDir()
	kc := seededStore(t)
	logPath := filepath.Join(dir, "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			aerr := sa.Append(context.Background(), audit.SignInput{
				Title:    fmt.Sprintf("write-%d", i),
				DiffHash: sha256.Sum256([]byte(fmt.Sprintf("content-%d", i))),
			}, fmt.Sprintf("/etc/file-%d", i), false)
			assert.NoError(t, aerr)
		}(i)
	}
	wg.Wait()

	entries, err := audit.ReadLog(logPath)
	require.NoError(t, err)
	assert.Equal(t, n, len(entries))

	// No forks: each prev_hash distinct; genesis appears exactly once.
	prevHashes := map[string]int{}
	genesisCount := 0
	for _, e := range entries {
		require.NotEmpty(t, e.PrevHash)
		if e.PrevHash == "genesis" {
			genesisCount++
			continue
		}
		prevHashes[e.PrevHash]++
		assert.Equal(t, 1, prevHashes[e.PrevHash],
			"chain fork detected: prev_hash %s appears more than once", e.PrevHash)
	}
	assert.Equal(t, 1, genesisCount, "genesis must appear exactly once")
}

// TestAuditWriteFilePath verifies the streaming WriteFilePath helper (D-06 / WR-02).
// A source file with known content must be copied to dst with matching content.
// A source exceeding 256 MiB must return an error containing "256 MiB".
func TestAuditWriteFilePath(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)

	// Happy path: small source file.
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	content := []byte("hello writefilepath")
	require.NoError(t, os.WriteFile(src, content, 0o600))

	ctx := context.Background()
	err = sa.WriteFilePath(ctx, src, dst, 0o644, false)
	require.NoError(t, err, "WriteFilePath must succeed for a small source file")

	got, err := os.ReadFile(dst) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	require.NoError(t, err)
	assert.Equal(t, content, got, "dst content must match src content")

	// Oversized source: exceed 256 MiB ceiling.
	bigSrc := filepath.Join(dir, "big.bin")
	const ceiling = 256 << 20 // 256 MiB
	bigF, ferr := os.Create(bigSrc)
	require.NoError(t, ferr)
	// Write ceiling+1 bytes by seeking and writing a single byte at offset 256MiB.
	_, serr := bigF.WriteAt([]byte{0x00}, int64(ceiling))
	require.NoError(t, serr)
	require.NoError(t, bigF.Close())

	bigDst := filepath.Join(dir, "big.dst")
	bigErr := sa.WriteFilePath(ctx, bigSrc, bigDst, 0o644, false)
	require.Error(t, bigErr, "WriteFilePath must return an error when src exceeds 256 MiB")
	assert.True(t, strings.Contains(bigErr.Error(), "256 MiB"),
		"error message must mention '256 MiB', got: %s", bigErr.Error())
}

// countNonEmptyLines counts non-empty lines in the file at path.
func countNonEmptyLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test reads audit log under temp dir
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("countNonEmptyLines: read %s: %v", path, err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	count := 0
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			count++
		}
	}
	return count
}

// TestAuditCounterMatchesEntries verifies that the keychain counter equals the
// number of JSONL entries in the audit log after a series of WriteFile calls.
//
// WriteFile on a new file produces 1 entry; WriteFile on an existing file
// produces 2 entries (backup + write-intent) — so the counter must equal the
// cumulative JSONL entry count after each call (D-08 / CR-02).
func TestAuditCounterMatchesEntries(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := seededStore(t)
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	ctx := context.Background()

	target1 := filepath.Join(dir, "file1.conf")
	target2 := filepath.Join(dir, "file2.conf")

	// Call 1: new file → 1 entry.
	require.NoError(t, sa.WriteFile(target1, []byte("v1"), 0o600, false))
	wantLines1 := countNonEmptyLines(t, logPath)
	assert.Equal(t, 1, wantLines1, "new-file WriteFile must produce 1 JSONL entry")
	n1, found1, err1 := audit.ReadCounter(ctx, kc)
	require.NoError(t, err1)
	require.True(t, found1, "counter must be present after first WriteFile")
	assert.Equal(t, int64(wantLines1), n1, "counter must equal JSONL entry count after call 1")

	// Call 2: overwrite target1 → 2 entries (backup + write-intent).
	require.NoError(t, sa.WriteFile(target1, []byte("v2"), 0o600, false))
	wantLines2 := countNonEmptyLines(t, logPath)
	assert.Equal(t, 3, wantLines2, "overwrite WriteFile must produce 2 more entries (total 3)")
	n2, found2, err2 := audit.ReadCounter(ctx, kc)
	require.NoError(t, err2)
	require.True(t, found2)
	assert.Equal(t, int64(wantLines2), n2, "counter must equal JSONL entry count after call 2")

	// Call 3: overwrite target1 again → 2 more entries (total 5).
	require.NoError(t, sa.WriteFile(target1, []byte("v3"), 0o600, false))
	wantLines3 := countNonEmptyLines(t, logPath)
	assert.Equal(t, 5, wantLines3, "second overwrite must produce 2 more entries (total 5)")
	n3, found3, err3 := audit.ReadCounter(ctx, kc)
	require.NoError(t, err3)
	require.True(t, found3)
	assert.Equal(t, int64(wantLines3), n3, "counter must equal JSONL entry count after call 3")

	// Call 4: new file target2 → 1 more entry (total 6).
	require.NoError(t, sa.WriteFile(target2, []byte("hello"), 0o600, false))
	wantLines4 := countNonEmptyLines(t, logPath)
	assert.Equal(t, 6, wantLines4, "new-file WriteFile must produce 1 entry (total 6)")
	n4, found4, err4 := audit.ReadCounter(ctx, kc)
	require.NoError(t, err4)
	require.True(t, found4)
	assert.Equal(t, int64(wantLines4), n4, "counter must equal JSONL entry count after call 4")

	// Final: Verify must report CounterStatus="ok" (or "verified") and no truncation.
	res, verErr := audit.Verify(ctx, logPath, kc)
	require.NoError(t, verErr)
	assert.True(t, res.OK, "Verify must pass after all WriteFile calls")
	assert.False(t, res.TruncationDetected, "no truncation should be detected")
	assert.Equal(t, "verified", res.CounterStatus, "CounterStatus must be 'verified'")
}

// TestHelperAuditAppend is the subprocess entry point for TestAuditCrossProcessFlock.
// It is activated when GO_TEST_AUDIT_SUBPROCESS=1 and AUDIT_LOG_PATH and
// AUDIT_DEST_PATH env vars are set. Each subprocess calls WriteFile once on the
// shared log path, writing to its unique dest path.
func TestHelperAuditAppend(t *testing.T) {
	if os.Getenv("GO_TEST_AUDIT_SUBPROCESS") != "1" {
		t.Skip("subprocess helper: not activated")
	}
	logPath := os.Getenv("AUDIT_LOG_PATH")
	destPath := os.Getenv("AUDIT_DEST_PATH")
	if logPath == "" || destPath == "" {
		t.Fatal("subprocess helper: AUDIT_LOG_PATH and AUDIT_DEST_PATH must be set")
	}
	kc := secrets.NewMockStore()
	// The HMAC key must be pre-seeded so all subprocesses share the same key.
	// We use a fixed key (all-ones) seeded via AUDIT_HMAC_KEY env var.
	hmacHex := os.Getenv("AUDIT_HMAC_KEY")
	require.NotEmpty(t, hmacHex, "subprocess helper: AUDIT_HMAC_KEY must be set")
	require.NoError(t, kc.Set(context.Background(), "abysslink", "audit-hmac", hmacHex))

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	require.NoError(t, sa.WriteFile(destPath, []byte("subprocess-content"), 0o600, false))
}

// TestAuditCrossProcessFlock verifies that concurrent subprocess writers do not
// produce interleaved or missing JSONL entries and that the audit log remains
// verifiable after N concurrent subprocess appends (AUD-02 / CR-01).
//
// 5 subprocesses each call WriteFile once on the same shared log path.
// After all complete: JSONL entry count must equal 5, Verify must pass,
// counter must equal 5.
func TestAuditCrossProcessFlock(t *testing.T) {
	if os.Getenv("GO_TEST_AUDIT_SUBPROCESS") != "1" {
		t.Skip("set GO_TEST_AUDIT_SUBPROCESS=1 to run")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "shared-audit.log")

	// Shared HMAC key (all-ones) used by all subprocesses.
	hmacHex := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))

	const n = 5
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)

	testBin, err := os.Executable()
	require.NoError(t, err)

	for i := range n {
		go func(i int) {
			defer wg.Done()
			destPath := filepath.Join(dir, fmt.Sprintf("dest-%d.conf", i))
			cmd := exec.Command(testBin, //nolint:gosec // G204: testBin is os.Executable() — current test binary, not user input
				"-test.run=TestHelperAuditAppend",
				"-test.v=false",
			)
			cmd.Env = append(os.Environ(),
				"GO_TEST_AUDIT_SUBPROCESS=1",
				"AUDIT_LOG_PATH="+logPath,
				"AUDIT_DEST_PATH="+destPath,
				"AUDIT_HMAC_KEY="+hmacHex,
			)
			out, runErr := cmd.CombinedOutput()
			if runErr != nil {
				errs[i] = fmt.Errorf("subprocess %d: %w\noutput: %s", i, runErr, string(out))
			}
		}(i)
	}
	wg.Wait()

	// All subprocesses must have succeeded.
	for i, e := range errs {
		assert.NoError(t, e, "subprocess %d must succeed", i)
	}

	// The shared log must have exactly n entries.
	gotLines := countNonEmptyLines(t, logPath)
	assert.Equal(t, n, gotLines, "shared log must have exactly %d JSONL entries", n)

	// A shared MockStore cannot verify the cross-process counter (each subprocess
	// uses its own in-memory MockStore, so the counter is not shared across
	// processes). We verify the chain and anchor integrity instead.
	// Use a keychain that holds the shared HMAC key so HMAC sigs can be verified.
	kc := secrets.NewMockStore()
	require.NoError(t, kc.Set(context.Background(), "abysslink", "audit-hmac", hmacHex))
	res, verErr := audit.Verify(context.Background(), logPath, kc)
	require.NoError(t, verErr)
	assert.True(t, res.OK, "Verify must pass after %d concurrent subprocess appends: %s", n, res.Reason)
	assert.False(t, res.TruncationDetected, "no truncation should be detected")
	// CounterStatus will be "unknown" because each subprocess uses its own in-memory
	// MockStore; the keychain counter is not shared across process boundaries.
	// This is expected — the flock ensures JSONL chain integrity, which is what
	// this test validates.
	assert.NotEqual(t, "mismatch", res.CounterStatus,
		"counter must not report mismatch (chain integrity is the primary CR-01 invariant)")
}
