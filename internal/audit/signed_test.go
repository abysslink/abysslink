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
	"encoding/json"
	"fmt"
	"os"
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

// TestAuditCounterMatchesEntries verifies that the keychain counter equals the
// number of JSONL entries in the audit log after a series of WriteFile calls.
//
// Wave 2: implementation in 25-04.
func TestAuditCounterMatchesEntries(t *testing.T) {
	t.Skip("Wave 2: implementation pending (plan 25-04)")
}

// TestAuditCrossProcessFlock verifies that concurrent subprocess writers do not
// interleave JSONL entries and that the audit log remains verifiable after N
// concurrent subprocess appends (AUD-02 / CR-01).
//
// Wave 2: subprocess-gated. Set GO_TEST_AUDIT_SUBPROCESS=1 to run.
func TestAuditCrossProcessFlock(t *testing.T) {
	if os.Getenv("GO_TEST_AUDIT_SUBPROCESS") != "1" {
		t.Skip("set GO_TEST_AUDIT_SUBPROCESS=1 to run")
	}
	t.Error("TestAuditCrossProcessFlock: Wave 2 implementation pending (plan 25-04)")
}
