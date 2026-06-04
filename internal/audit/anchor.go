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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Anchor is the external truncation/tamper checkpoint written beside the log.
// It is itself HMAC-signed (HMAC covers EntryCount + LastHash + Time) so that a
// local attacker cannot forge a smaller EntryCount to hide truncation.
//
// AUD-04: this struct carries no Body, Content, Data, Raw, or Payload field.
type Anchor struct {
	EntryCount int64  `json:"entry_count"`
	LastHash   string `json:"last_hash"` // hex(sha256(last raw JSONL line)), "" for empty log
	Time       string `json:"time"`      // RFC3339 UTC
	HMAC       string `json:"hmac"`      // hex HMAC-SHA256 over anchorSignBytes
}

// anchorPath returns the canonical anchor path beside logPath.
func anchorPath(logPath string) string {
	return filepath.Join(filepath.Dir(logPath), "audit.anchor.json")
}

// anchorSignBytes is the canonical, deterministic serialisation the anchor HMAC
// covers: entry_count + 0x00 + last_hash + 0x00 + time.
func anchorSignBytes(a Anchor) []byte {
	return []byte(fmt.Sprintf("%d\x00%s\x00%s", a.EntryCount, a.LastHash, a.Time))
}

// WriteAnchor writes an HMAC-signed anchor beside logPath, atomically (temp +
// rename, mode 0600). It fetches the HMAC key via the package-private
// fetchHMACKey helper — it MUST NOT construct a *SignedAudit, which would
// auto-generate/rotate the key and break the chain.
func WriteAnchor(ctx context.Context, logPath string, kc KeychainStore) error {
	key, err := fetchHMACKey(ctx, kc)
	if err != nil {
		return err
	}

	entries, err := ReadLog(logPath)
	if err != nil {
		return err
	}
	last, err := readLastNonEmptyLine(logPath)
	if err != nil {
		return err
	}
	lastHash := ""
	if len(last) > 0 {
		sum := sha256.Sum256(last)
		lastHash = hex.EncodeToString(sum[:])
	}

	a := Anchor{
		EntryCount: int64(len(entries)),
		LastHash:   lastHash,
		Time:       time.Now().UTC().Format(time.RFC3339),
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(anchorSignBytes(a))
	a.HMAC = hex.EncodeToString(mac.Sum(nil))

	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("audit: marshal anchor: %w", err)
	}

	path := anchorPath(logPath)
	// Use os.CreateTemp for a unique tmp path per concurrent caller — a shared
	// static ".abysslink.tmp" suffix races when two goroutines both call
	// WriteAnchor (AUD-02 per-Append anchor makes this routine now). The tmp
	// file is created in the same directory as the anchor so the rename is
	// always within the same filesystem (cross-device rename would fail).
	f, ferr := os.CreateTemp(filepath.Dir(path), "audit.anchor.*.tmp")
	if ferr != nil {
		return fmt.Errorf("audit: create temp anchor: %w", ferr)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: write temp anchor %s: %w", tmp, werr)
	}
	if err := os.Chmod(tmp, 0o600); err != nil { //nolint:gosec // G304: tmp is derived from os.CreateTemp; path is app-controlled
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: chmod temp anchor %s: %w", tmp, err)
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: rename anchor %s → %s: %w", tmp, path, rerr)
	}
	return nil
}

// ReadAnchor reads and parses the anchor beside logPath. A missing anchor is not
// an error — it returns (nil, nil).
func ReadAnchor(logPath string) (*Anchor, error) {
	data, err := os.ReadFile(anchorPath(logPath)) //nolint:gosec // app-controlled path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read anchor: %w", err)
	}
	var a Anchor
	if uerr := json.Unmarshal(data, &a); uerr != nil {
		return nil, fmt.Errorf("audit: parse anchor: %w", uerr)
	}
	return &a, nil
}

// AUD-02: keychain counter constants — service/account mirror the HMAC key
// naming convention in signed.go (hmacKeyService/hmacKeyAccount).
const (
	counterKeyService = "abysslink"
	counterKeyAccount = "audit-counter" // full keychain id: abysslink-audit-counter
)

// ReadCounter reads the monotonic entry counter from the keychain.
// It returns (n, true, nil) when the counter is present and parseable,
// (0, false, nil) when the counter key is absent (first use — not an error),
// and (0, false, err) when the keychain is unavailable or corrupt.
//
// The "not found" sentinel is detected by the error message substring
// "secret not found", which is the shared convention used by MockStore,
// DarwinStore, and LinuxStore in internal/secrets.
func ReadCounter(ctx context.Context, kc KeychainStore) (n int64, found bool, err error) {
	val, kerr := kc.Get(ctx, counterKeyService, counterKeyAccount)
	if kerr != nil {
		// Distinguish "key absent" from "keychain unavailable/error".
		// All KeychainStore implementations return an error containing
		// "secret not found" when the key does not exist — absent counter
		// means first use, not a failure.
		if strings.Contains(kerr.Error(), "secret not found") {
			return 0, false, nil
		}
		return 0, false, kerr
	}
	n, perr := strconv.ParseInt(val, 10, 64)
	if perr != nil {
		return 0, false, fmt.Errorf("audit: parse counter %q: %w", val, perr)
	}
	return n, true, nil
}

// WriteCounter writes the monotonic entry counter to the keychain as a decimal
// string. Any error is returned wrapped with an "audit: write counter:" prefix.
func WriteCounter(ctx context.Context, kc KeychainStore, n int64) error {
	if err := kc.Set(ctx, counterKeyService, counterKeyAccount, strconv.FormatInt(n, 10)); err != nil {
		return fmt.Errorf("audit: write counter: %w", err)
	}
	return nil
}

// IncrementCounter reads the counter, increments it by 1, and writes it back.
// A missing counter (found=false) initialises to 1 (0 base + 1 increment).
// A genuine keychain error (kerr != nil and !found) is returned; absent key is
// treated as first use.
//
// Exported so the external audit_test package can exercise it directly.
// The production call site in signed.go uses this function.
func IncrementCounter(ctx context.Context, kc KeychainStore) error {
	n, found, err := ReadCounter(ctx, kc)
	if err != nil && !found {
		// Genuine keychain error (not "not found").
		return err
	}
	if !found {
		n = 0 // first use — will write 1
	}
	return WriteCounter(ctx, kc, n+1)
}

// addCounter reads the current counter and increments it by delta (>= 1).
// Used by WriteFile's batched path to add exactly entryCount (2 for overwrite,
// 1 for new-file) so the keychain counter always equals the JSONL entry count
// at any process-kill point (D-08 / CR-02).
// A missing counter (found=false) initialises to 0 base before adding delta.
func addCounter(ctx context.Context, kc KeychainStore, delta int64) error {
	n, found, err := ReadCounter(ctx, kc)
	if err != nil && !found {
		return err
	}
	if !found {
		n = 0 // first use
	}
	return WriteCounter(ctx, kc, n+delta)
}

// VerifyAnchor returns true when the anchor's HMAC matches its contents. A
// missing anchor is not a violation (returns true, nil — no anchor yet).
func VerifyAnchor(logPath string, kc KeychainStore) (bool, error) {
	a, err := ReadAnchor(logPath)
	if err != nil {
		return false, err
	}
	if a == nil {
		return true, nil
	}
	key, err := fetchHMACKey(context.Background(), kc)
	if err != nil {
		return false, err
	}
	gotBytes, err := hex.DecodeString(a.HMAC)
	if err != nil || len(gotBytes) != sha256.Size {
		return false, nil
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(anchorSignBytes(*a))
	return hmac.Equal(mac.Sum(nil), gotBytes), nil
}
