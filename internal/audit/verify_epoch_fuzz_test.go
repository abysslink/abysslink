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

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/secrets"
)

// FuzzVerifyEpochChain feeds arbitrary/mutated JSONL chain bytes to the
// file-based audit.Verify and asserts it (a) NEVER panics and (b) NEVER returns
// a golden-strength OK verdict for a chain that is not a faithful re-encoding of
// a validly-signed chain (P-C1, ROT-03).
//
// SETUP: a KNOWN-GOOD 3-epoch (2-rotation) signed chain is built once from the
// real audit writers (NewSigned/Append/RotateHMACKey). Every epoch key, the
// epoch pointer and the entry counter come from crypto/rand and live ONLY in an
// in-memory secrets.MockStore — never a live OS keychain, and never a static key
// literal on disk or in the corpus, so gitleaks stays clean. The golden log
// bytes, the golden anchor bytes and that live MockStore are captured in the
// closure; Verify is read-only w.r.t. the keychain, so the same store is reused
// unchanged across every iteration. Because the keys are random per run, no
// static committed chain could ever match this keychain — the one VALID seed is
// therefore registered at runtime via f.Add(golden). Committed testdata seeds
// under testdata/fuzz/FuzzVerifyEpochChain/ hold only key-independent malformed
// inputs.
//
// SOUND FALSE-OK ORACLE: for every input b we rebuild a temp dir with the
// UNCHANGED golden anchor beside a log file containing b, then Verify(ctx, log,
// kc). When the verdict is at least as strong as golden's — OK, not
// indeterminate, not truncated, and the SAME number of verified HMAC sigs
// (goldenSigs) — the input MUST be a faithful re-encoding of the golden chain
// (equal modulo blank lines, which scanRawAndEntries ignores). This is sound
// with ZERO false failures: every earlier line's exact bytes are pinned by the
// next entry's prev_hash (sha256 of the raw line), the last line's bytes are
// pinned by the golden anchor's LastHash, and the multi-epoch keychain pointer
// forces the tail to reach the final epoch. Any single-byte change to any line
// breaks a prev_hash link, the anchor hash or an HMAC sig, dropping OK or
// SigsVerified below goldenSigs — so the equality guard only ever fires on
// chains logically identical to golden. It CATCHES a real regression: were
// Verify to accept a stripped/reordered/downgraded/resealed chain as fully-OK,
// normalizeJSONL(b) would differ from golden and the guard would fire. The
// SigsVerified==goldenSigs gate deliberately excludes weaker OK verdicts (an
// empty or pure-legacy log verifies OK with SigsVerified==0) so those never trip
// the oracle.
//
// Note on cross-process replay: Go re-runs this setup in each worker process
// with fresh random keys. A golden chain from another process replayed under
// THIS process's keychain fails closed (foreign HMAC sigs → OK=false), so the
// oracle's OK-branch is only ever reached by the local golden, where b matches
// the closure's golden. The oracle is therefore process-independent.
func FuzzVerifyEpochChain(f *testing.F) {
	golden, goldenAnchor, kc, goldenSigs := buildGoldenEpochChain(f)

	// Seeds: the two valid chains (multi-epoch golden + an independent
	// single-epoch chain whose own random key is discarded), an empty file, a
	// bare token, and key-independent malformed derivatives of golden.
	f.Add(golden)
	f.Add(buildSingleEpochChain(f))
	f.Add([]byte(""))
	f.Add([]byte("x"))
	f.Add(truncateLastLine(golden))
	f.Add(tamperFirstLine(golden))
	f.Add(breakPrevHash(golden))

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			return // guard against CI OOM -- MUST be the first statement
		}
		runEpochVerifyOracle(t, kc, goldenAnchor, golden, goldenSigs, b)
	})
}

// buildGoldenEpochChain constructs the known-good 3-epoch signed chain and
// returns its log bytes, its anchor bytes, the live MockStore holding all epoch
// keys/pointer/counter, and the golden SigsVerified count.
func buildGoldenEpochChain(f *testing.F) (golden, anchor []byte, kc *secrets.MockStore, goldenSigs int) {
	f.Helper()
	ctx := context.Background()
	kc = secrets.NewMockStore()
	dir := f.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	sa, err := NewSigned(logPath, kc)
	if err != nil {
		f.Fatal(err)
	}
	const epochs, perEpoch = 3, 4
	for e := 1; e <= epochs; e++ {
		for i := 0; i < perEpoch; i++ {
			sum := sha256.Sum256([]byte(fmt.Sprintf("epoch-%d-entry-%d", e, i)))
			if aerr := sa.Append(ctx, SignInput{Title: "write", DiffHash: sum},
				fmt.Sprintf("/tmp/target-%d-%d", e, i), false); aerr != nil {
				f.Fatal(aerr)
			}
		}
		if e < epochs {
			if _, rerr := sa.RotateHMACKey(ctx); rerr != nil {
				f.Fatal(rerr)
			}
		}
	}
	golden, err = os.ReadFile(logPath)
	if err != nil {
		f.Fatal(err)
	}
	anchor, err = os.ReadFile(filepath.Join(dir, "audit.anchor.json"))
	if err != nil {
		f.Fatal(err)
	}
	base, berr := Verify(ctx, logPath, kc)
	if berr != nil || !base.OK {
		f.Fatalf("golden chain must verify OK at init: err=%v result=%+v", berr, base)
	}
	return golden, anchor, kc, base.SigsVerified
}

// runEpochVerifyOracle materialises b next to the unchanged golden anchor,
// verifies it under the golden keychain, and asserts the fail-closed invariants
// plus the sound false-OK oracle.
func runEpochVerifyOracle(t *testing.T, kc *secrets.MockStore, goldenAnchor, golden []byte, goldenSigs int, b []byte) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if werr := os.WriteFile(filepath.Join(dir, "audit.anchor.json"), goldenAnchor, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if werr := os.WriteFile(logPath, b, 0o600); werr != nil {
		t.Fatal(werr)
	}

	res, verr := Verify(context.Background(), logPath, kc)
	if verr != nil {
		return // a malformed JSON line is an expected error, not a crash
	}

	// Fail-closed structural invariants.
	if res.Indeterminate && res.OK {
		t.Fatalf("indeterminate verdict must never be OK: %+v", res)
	}
	if res.OK && res.At != -1 {
		t.Fatalf("OK verdict must have At==-1, got At=%d (%s)", res.At, res.Reason)
	}

	// Sound false-OK oracle (see FuzzVerifyEpochChain doc): a golden-strength
	// verdict forces byte-identity of every non-empty JSONL line.
	//
	// CounterStatus=="verified" is part of the conjunction so the oracle is
	// provably COMPLETE, not just sound: without it, an appended UNSIGNED
	// epoch-3 entry carrying a correct prev_hash link keeps OK=true with
	// SigsVerified==goldenSigs but degrades CounterStatus to "unknown"
	// (verify.go tri-state), which would otherwise slip past the guard on a
	// non-identical chain. Random fuzzing cannot forge the 64-hex link so it
	// never reaches this branch, but pinning CounterStatus closes the gap for
	// free — the golden chain always verifies with CounterStatus=="verified".
	goldenStrength := res.OK && !res.Indeterminate && !res.TruncationDetected &&
		res.SigsVerified == goldenSigs && res.CounterStatus == "verified"
	if goldenStrength && normalizeJSONL(b) != normalizeJSONL(golden) {
		t.Fatal("Verify returned a golden-strength OK for a chain that is NOT a faithful re-encoding of the golden chain")
	}
}

// buildSingleEpochChain builds a second, independent single-epoch signed chain
// with its own random keychain (discarded). Its bytes are a valid chain on their
// own but do NOT authenticate under golden's keychain, so it exercises the
// fail-closed sig-mismatch path when replayed under the golden store.
func buildSingleEpochChain(f *testing.F) []byte {
	f.Helper()
	kc := secrets.NewMockStore()
	logPath := filepath.Join(f.TempDir(), "audit.log")
	sa, err := NewSigned(logPath, kc)
	if err != nil {
		f.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("single-%d", i)))
		if aerr := sa.Append(ctx, SignInput{Title: "write", DiffHash: sum},
			fmt.Sprintf("/tmp/single-%d", i), false); aerr != nil {
			f.Fatal(aerr)
		}
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// nonEmptyLines splits b on newlines and drops empty lines — exactly what
// scanRawAndEntries ignores.
func nonEmptyLines(b []byte) []string {
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

// normalizeJSONL is the canonical (blank-line-insensitive) form used by the
// false-OK oracle for logical equality.
func normalizeJSONL(b []byte) string {
	return strings.Join(nonEmptyLines(b), "\n")
}

func joinLines(lines []string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

// truncateLastLine chops the final JSONL line in half, yielding an entry that no
// longer parses as JSON (Verify returns an error, which the harness treats as an
// expected non-crash).
func truncateLastLine(b []byte) []byte {
	lines := nonEmptyLines(b)
	if len(lines) == 0 {
		return b
	}
	last := lines[len(lines)-1]
	lines[len(lines)-1] = last[:len(last)/2]
	return joinLines(lines)
}

// tamperFirstLine rewrites the first entry's target without re-signing, breaking
// both its HMAC sig and the next entry's prev_hash link.
func tamperFirstLine(b []byte) []byte {
	lines := nonEmptyLines(b)
	if len(lines) == 0 {
		return b
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		return b
	}
	e.Target += "-tampered"
	nb, err := json.Marshal(e)
	if err != nil {
		return b
	}
	lines[0] = string(nb)
	return joinLines(lines)
}

// breakPrevHash corrupts the second entry's prev_hash link.
func breakPrevHash(b []byte) []byte {
	lines := nonEmptyLines(b)
	if len(lines) < 2 {
		return b
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
		return b
	}
	e.PrevHash = "deadbeef"
	nb, err := json.Marshal(e)
	if err != nil {
		return b
	}
	lines[1] = string(nb)
	return joinLines(lines)
}
