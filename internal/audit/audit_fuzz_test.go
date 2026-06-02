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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// FuzzHMACVerify exercises the entry-unmarshal -> verifyHMAC path against
// arbitrary bytes. verifyHMAC must fail closed (return false, never panic) on
// any malformed input -- that is the property under test (AUD-08, T-17-16).
//
// WR-02 (iteration 2): the harness reconstructs the FULL SignInput from the
// parsed Entry (Title/Target/Time/DryRun/PrevHash + the hex-decoded DiffHash),
// not just Title+DiffHash, so the corpus drives every signed field -- including
// the new length-prefixed framing surface (WR-01) -- through signBytes.
//
// The fixed test key is a non-secret, synthetic 32-byte value; gitleaks must
// not flag it.
func FuzzHMACVerify(f *testing.F) {
	// nulEsc is the literal six-character JSON escape for a NUL byte. Building
	// it from bytes avoids embedding a raw NUL (illegal in Go source) while
	// still feeding a NUL through json.Unmarshal -> op/target/prev_hash ->
	// signBytes, exercising the length-prefixed separator (WR-01/WR-02).
	nulEsc := string([]byte{'\\', 'u', '0', '0', '0', '0'})

	// Seed corpus -- mirrors the files in testdata/fuzz/FuzzHMACVerify/.
	f.Add([]byte(""))
	f.Add([]byte("x"))
	f.Add([]byte(`{"time":"2026-01-01T00:00:00Z","op":"write","target":"/etc/foo","hash":"abc","dry_run":false}`))
	f.Add([]byte(`{"time":"bad","op":"","target":"","hash":"","dry_run":false,"prev_hash":"genesis","sig":"gg"}`))
	f.Add([]byte(`{"op":"a` + nulEsc + `b","target":"c","prev_hash":"genesis","sig":"00"}`))
	f.Add([]byte(`{"op":"a","target":"b` + nulEsc + `c","time":"2026-01-01T00:00:00Z","dry_run":true,"prev_hash":"a` + nulEsc + `b","hash":"deadbeef","sig":"ff"}`))

	// testKey is 32 bytes of 0x01 -- deterministic, non-secret, never panics.
	testKey := bytes.Repeat([]byte{1}, 32)

	f.Fuzz(func(_ *testing.T, b []byte) {
		if len(b) > 4096 {
			return // guard against CI OOM -- MUST be the first statement
		}
		var entry Entry
		if err := json.Unmarshal(b, &entry); err != nil {
			return // invalid JSON is expected, not a crash
		}
		// Reconstruct the full signing input the same way verifyEntrySig does,
		// so every field (incl. attacker-controlled Target/PrevHash and NUL
		// bytes) flows through signBytes. verifyHMAC must never panic.
		in := SignInput{
			Title:    entry.Op,
			Target:   entry.Target,
			Time:     entry.Time.UTC().Format(time.RFC3339),
			DryRun:   entry.DryRun,
			PrevHash: entry.PrevHash,
		}
		if raw, derr := hex.DecodeString(entry.Hash); derr == nil && len(raw) == len(in.DiffHash) {
			copy(in.DiffHash[:], raw)
		}
		_ = verifyHMAC(testKey, in, entry.Sig)
	})
}
