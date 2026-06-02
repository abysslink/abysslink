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
	tmp := path + ".abysslink.tmp"
	if werr := os.WriteFile(tmp, data, 0o600); werr != nil {
		return fmt.Errorf("audit: write temp anchor %s: %w", tmp, werr)
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
