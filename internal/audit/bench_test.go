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
	"fmt"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/require"
)

// P-C2 performance-budget benchmarks for the audit hot paths. These are
// MEASUREMENT ONLY — no regression gate, no timing assertions. See
// docs/testing/perf-budget.md for the captured baseline and the soft budget.
//
// They never touch a live keychain: every SignedAudit is built from an
// in-memory secrets.MockStore seeded with a synthetic (all-ones) HMAC key, and
// every log lives under the benchmark's own b.TempDir(), so each run is
// hermetic.

// benchSeededStore returns a MockStore pre-seeded with a synthetic, non-secret
// 32-byte HMAC key (all 0x01 bytes) under the same account the audit signer
// reads (testHMACAccount, defined in signed_test.go). The key is computed at
// runtime, never a checked-in literal, so it is gitleaks-safe.
func benchSeededStore(tb testing.TB) *secrets.MockStore {
	tb.Helper()
	kc := secrets.NewMockStore()
	require.NoError(tb, kc.Set(context.Background(), "abysslink", testHMACAccount,
		hex.EncodeToString(bytes.Repeat([]byte{1}, 32))))
	return kc
}

// benchBuildChain appends n signed entries to a fresh temp-file SignedAudit and
// returns the log path plus its keychain. Used to pre-build a chain OUTSIDE the
// timed region of the verify benchmark.
func benchBuildChain(tb testing.TB, n int) (string, *secrets.MockStore) {
	tb.Helper()
	kc := benchSeededStore(tb)
	logPath := filepath.Join(tb.TempDir(), "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(tb, err)
	ctx := context.Background()
	for i := 0; i < n; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("content-%d", i)))
		require.NoError(tb, sa.Append(ctx, audit.SignInput{Title: "write", DiffHash: sum},
			fmt.Sprintf("/etc/file-%d", i), false))
	}
	return logPath, kc
}

// BenchmarkAuditAppend measures a single signed Append — HMAC sign + fsync'd
// JSONL append + anchor rewrite (the anchor-every-append behaviour) — to a
// temp-file SignedAudit. The append path also rescans the log tail to compute
// prev_hash, so per-op cost grows with log size; keep the run short (bounded
// benchtime) to measure the near-empty-log cost.
func BenchmarkAuditAppend(b *testing.B) {
	kc := benchSeededStore(b)
	logPath := filepath.Join(b.TempDir(), "audit.log")
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(b, err)
	ctx := context.Background()
	// Fixed digest — we are timing the signer + writer, not sha256.
	digest := sha256.Sum256([]byte("bench-content"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if aerr := sa.Append(ctx, audit.SignInput{Title: "write", DiffHash: digest},
			"/etc/bench-target", false); aerr != nil {
			b.Fatalf("append: %v", aerr)
		}
	}
}

// BenchmarkChainVerify measures a full read-only chain walk (hash links + HMAC
// signatures + anchor) over a pre-built chain of N entries. Sub-benchmarks for
// N in {100, 1000} make the O(N) cost visible. The chain is built once, outside
// the timed loop (b.ResetTimer), so only Verify is measured.
func BenchmarkChainVerify(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			logPath, kc := benchBuildChain(b, n)
			ctx := context.Background()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, verr := audit.Verify(ctx, logPath, kc)
				if verr != nil {
					b.Fatalf("verify: %v", verr)
				}
				if !res.OK {
					b.Fatalf("verify: chain not OK: %s", res.Reason)
				}
			}
		})
	}
}
