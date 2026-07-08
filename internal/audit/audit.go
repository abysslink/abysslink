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
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

// Entry is a single immutable audit-log record. Hash is the SHA-256 of the
// content at mutation time — the content itself is never stored here.
type Entry struct {
	Time     time.Time `json:"time"`
	Op       string    `json:"op"`
	Target   string    `json:"target"`
	Hash     string    `json:"hash"` // hex-encoded SHA-256 of mutated content
	DryRun   bool      `json:"dry_run"`
	PrevHash string    `json:"prev_hash,omitempty"` // genesis or hex(sha256(prior raw JSONL line))
	Sig      string    `json:"sig,omitempty"`       // hex HMAC-SHA256 of the signing input
	// KeyEpoch is the HMAC key epoch that signed this entry (ROT-01). Zero /
	// absent means epoch 1 — every pre-rotation entry. For epoch >= 2 the value
	// is also covered by the HMAC input (signBytesEpoch), so it cannot be
	// stripped or altered without breaking the signature.
	KeyEpoch uint32 `json:"key_epoch,omitempty"`
}

// Audit writes append-only audit-log entries and is the sole authorised path
// for any operation that records file mutations.
//
// CHAIN AWARENESS (R2-C1): when the log already carries an HMAC-signed hash
// chain (the SignedAudit format), a plain *Audit MUST NOT append bare legacy
// entries — an empty prev_hash after the chain has started is indistinguishable
// from a downgrade/strip attack, so walkChain would flag the log as tampered
// FOREVER. Instead, Append detects an active chain and:
//
//  1. signs the entry exactly like SignedAudit (same code path) when the HMAC
//     key is reachable in the platform keychain, refreshing anchor+counter; or
//  2. falls back to a CHAINED-UNSIGNED entry (prev_hash set, no sig) when the
//     keychain is unavailable — the chain link stays intact and Verify counts
//     it as a skipped signature instead of a tamper alarm.
//
// A log that has never started a chain keeps the legacy v1/v2 behaviour
// (no prev_hash, no sig, no keychain access at all).
type Audit struct {
	logPath string

	mu            sync.Mutex
	delegate      *SignedAudit // lazily-built signed writer for chain-active logs
	delegateReady bool
	kc            KeychainStore // optional injected keychain (NewWithKeychain)
}

// New returns an Audit that appends to logPath. The file is created if it does
// not exist; intermediate directories must already exist. When the log carries
// an active signed chain, entries are signed via the platform keychain (see the
// Audit doc comment).
func New(logPath string) *Audit {
	return &Audit{logPath: logPath}
}

// NewWithKeychain returns an Audit that uses kc — instead of probing the
// platform keychain — to sign entries when the log carries an active signed
// chain. Callers that already hold a KeychainStore should prefer this over New
// so the chain-aware path shares their keychain handle.
func NewWithKeychain(logPath string, kc KeychainStore) *Audit {
	return &Audit{logPath: logPath, kc: kc}
}

// openPlatformKeychain opens the platform keychain store for the chain-aware
// unsigned writer. It is a variable so the package's own tests can stub it.
//
// Under `go test` it returns (nil, nil): a test binary must NEVER touch the
// developer's real keychain (signing test entries with the real HMAC key and
// bumping the real audit counter would corrupt genuine audit state). The
// chain-aware writer then falls back to chained-unsigned entries, which keeps
// the chain intact for Verify. Tests that want full signing inject a mock via
// NewWithKeychain.
var openPlatformKeychain = func(ctx context.Context) (KeychainStore, error) {
	if testing.Testing() {
		return nil, nil
	}
	return secrets.NewStore(ctx, &shell.ExecRunner{})
}

// Append writes a new Entry to the audit log. content is hashed; it is never
// written to disk. If dryRun is true the entry is still logged but tagged.
// The append runs under the shared cross-process audit flock so the chain
// state it observes cannot change before the write lands.
func (a *Audit) Append(op, target string, content []byte, dryRun bool) error {
	lockFD, err := acquireAuditLock(a.logPath)
	if err != nil {
		return fmt.Errorf("audit: acquire process lock: %w", err)
	}
	defer releaseAuditLock(lockFD)
	return a.appendLocked(op, target, content, dryRun)
}

// appendLocked is Append without lock acquisition. It MUST be called with the
// audit flock already held (Append and *Audit.WriteFile both guarantee this).
func (a *Audit) appendLocked(op, target string, content []byte, dryRun bool) error {
	sum := sha256.Sum256(content)

	active, err := chainActive(a.logPath)
	if err != nil {
		return err
	}
	if !active {
		// Legacy log (or empty log): keep the exact v1/v2 entry shape and never
		// touch the keychain.
		return a.writeEntryLocked(Entry{
			Time:   time.Now().UTC(),
			Op:     op,
			Target: target,
			Hash:   fmt.Sprintf("%x", sum),
			DryRun: dryRun,
		})
	}

	// A signed chain is active: sign exactly like SignedAudit when possible.
	ctx := context.Background()
	if sa := a.signedDelegate(ctx); sa != nil {
		if _, _, kerr := sa.hmacKey(ctx); kerr == nil {
			return sa.appendAndRefreshLocked(ctx, SignInput{Title: op, DiffHash: sum}, target, dryRun)
		}
		// Key unreachable (absent or keychain unavailable). NEVER generate a key
		// from the unsigned path — fall through to the chained-unsigned entry.
		slog.Warn("audit: hmac key unreachable; appending chained-unsigned entry",
			"log", a.logPath, "target", target)
	}

	// Chained-unsigned fallback: the prev_hash link keeps the chain walkable so
	// Verify reports a skipped signature, not CHAIN BROKEN.
	prevHash, err := computePrevHash(a.logPath)
	if err != nil {
		return err
	}
	return a.writeEntryLocked(Entry{
		Time:     time.Now().UTC(),
		Op:       op,
		Target:   target,
		Hash:     fmt.Sprintf("%x", sum),
		DryRun:   dryRun,
		PrevHash: prevHash,
	})
}

// signedDelegate lazily builds (and caches) the SignedAudit used to sign
// chain-active appends. Returns nil when no keychain is reachable; a transient
// open failure is NOT cached so a later append can retry.
func (a *Audit) signedDelegate(ctx context.Context) *SignedAudit {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.delegateReady {
		return a.delegate
	}
	kc := a.kc
	if kc == nil {
		store, err := openPlatformKeychain(ctx)
		if err != nil {
			slog.Warn("audit: platform keychain unavailable; appending chained-unsigned entries", "err", err)
			return nil // not cached — retry on the next append
		}
		if store == nil {
			// Test mode (openPlatformKeychain opted out): cache the decision.
			a.delegateReady = true
			return nil
		}
		kc = store
	}
	a.delegate = &SignedAudit{logPath: a.logPath, kc: kc}
	a.delegateReady = true
	return a.delegate
}

// writeEntryLocked marshals and appends one entry with an fsync before close
// (R2-W4: the append-before-write protocol is only crash-safe if the intent
// entry is durable before the subsequent rename can be).
func (a *Audit) writeEntryLocked(entry Entry) error {
	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	line = append(line, '\n')
	return appendLineSynced(a.logPath, line)
}

// chainActive reports whether the log's last entry carries a chain link
// (prev_hash) — i.e. whether a SignedAudit-format chain is in effect.
func chainActive(logPath string) (bool, error) {
	last, err := readLastNonEmptyLine(logPath)
	if err != nil {
		return false, err
	}
	if len(last) == 0 {
		return false, nil
	}
	var e Entry
	if uerr := json.Unmarshal(last, &e); uerr != nil {
		return false, fmt.Errorf("audit: parse log line: %w", uerr)
	}
	return e.PrevHash != "", nil
}

// HashOf returns the hex-encoded SHA-256 of content. Useful for callers that
// want to record a hash without appending a full entry.
func HashOf(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum)
}
