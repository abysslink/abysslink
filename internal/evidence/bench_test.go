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

package evidence_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/evidence"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/require"
)

// P-C2 performance-budget benchmarks for the evidence-bundle hot paths
// (MEASUREMENT ONLY — no regression gate). Each bundle is built from an
// in-memory secrets.MockStore over a temp-file audit chain; no live keychain is
// ever touched. See docs/testing/perf-budget.md for the baseline + soft budget.

// benchEvidenceEntries is the audit-chain length backing the evidence
// benchmarks — a representative bundle size for a warm rig.
const benchEvidenceEntries = 100

// benchSeededLog writes an n-entry signed audit chain under a fresh temp dir and
// returns its path + keychain (mirrors seededLog in evidence_test.go but takes a
// testing.TB so benchmarks can reuse it).
func benchSeededLog(tb testing.TB, n int) (string, *secrets.MockStore) {
	tb.Helper()
	kc := secrets.NewMockStore()
	logPath := filepath.Join(tb.TempDir(), "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(tb, err)
	ctx := context.Background()
	for i := 0; i < n; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("content-%d", i)))
		require.NoError(tb, sa.Append(ctx, audit.SignInput{Title: "write", DiffHash: sum},
			fmt.Sprintf("/tmp/target-%d", i), false))
	}
	return logPath, kc
}

func benchCreateOpts(logPath string) evidence.CreateOptions {
	return evidence.CreateOptions{
		LogPath:          logPath,
		Hostname:         "rig-bench",
		AbysslinkVersion: "v0.0.0-bench",
		Now:              time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
	}
}

// BenchmarkEvidenceCreate measures the .alevidence Create half — verify the
// audit chain, render the report, pin content hashes, ed25519-sign the manifest,
// and stream the tar.gz. Output is discarded so only the build cost is timed.
func BenchmarkEvidenceCreate(b *testing.B) {
	logPath, kc := benchSeededLog(b, benchEvidenceEntries)
	opts := benchCreateOpts(logPath)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := evidence.Create(ctx, kc, opts, io.Discard); err != nil {
			b.Fatalf("create: %v", err)
		}
	}
}

// BenchmarkEvidenceVerify measures the .alevidence Verify half — un-gzip the
// bundle, check the ed25519 signature over the manifest, and confirm every
// pinned content hash. The bundle is built once, outside the timed loop.
func BenchmarkEvidenceVerify(b *testing.B) {
	logPath, kc := benchSeededLog(b, benchEvidenceEntries)
	var buf bytes.Buffer
	_, err := evidence.Create(context.Background(), kc, benchCreateOpts(logPath), &buf)
	require.NoError(b, err)
	bundle := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, verr := evidence.Verify(bytes.NewReader(bundle))
		if verr != nil {
			b.Fatalf("verify: %v", verr)
		}
		if !res.Valid {
			b.Fatalf("verify: bundle not valid: %s", res.Reason)
		}
	}
}
