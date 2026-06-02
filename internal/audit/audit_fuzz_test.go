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
	"crypto/sha256"
	"encoding/json"
	"testing"
)

// FuzzHMACVerify exercises the entry-unmarshal → verifyHMAC path against
// arbitrary bytes. verifyHMAC must fail closed (return false, never panic) on
// any malformed input — that is the property under test (AUD-08, T-17-16).
//
// The fixed test key is a non-secret, synthetic 32-byte value; gitleaks must
// not flag it.
func FuzzHMACVerify(f *testing.F) {
	// Seed corpus — mirrors the files in testdata/fuzz/FuzzHMACVerify/.
	f.Add([]byte(""))
	f.Add([]byte("x"))
	f.Add([]byte(`{"time":"2026-01-01T00:00:00Z","op":"write","target":"/etc/foo","hash":"abc","dry_run":false}`))
	f.Add([]byte(`{"time":"bad","op":"","target":"","hash":"","dry_run":false,"prev_hash":"genesis","sig":"gg"}`))

	// testKey is 32 bytes of 0x01 — deterministic, non-secret, never panics.
	testKey := bytes.Repeat([]byte{1}, 32)

	f.Fuzz(func(_ *testing.T, b []byte) {
		if len(b) > 4096 {
			return // guard against CI OOM — MUST be the first statement
		}
		var entry Entry
		if err := json.Unmarshal(b, &entry); err != nil {
			return // invalid JSON is expected, not a crash
		}
		// verifyHMAC must never panic, regardless of entry contents.
		_ = verifyHMAC(testKey, SignInput{
			Title:    entry.Op,
			DiffHash: sha256.Sum256([]byte(entry.Hash)),
		}, entry.Sig)
	})
}
