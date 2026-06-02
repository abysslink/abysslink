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
