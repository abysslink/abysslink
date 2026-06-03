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
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// KeychainStore is satisfied by internal/secrets.KeychainStore; redeclared here
// to avoid an import cycle (audit→secrets→…→audit). The real injection happens
// via interface assignment at the call site.
type KeychainStore interface {
	Set(ctx context.Context, service, account, secret string) error
	Get(ctx context.Context, service, account string) (string, error)
	Delete(ctx context.Context, service, account string) error
}

const (
	hmacKeyService = "abysslink"
	hmacKeyAccount = "audit-hmac" // full keychain id: abysslink-audit-hmac
	hmacKeyBytes   = 32
	genesisMarker  = "genesis"
)

// SignInput is the ONLY permitted input to the HMAC signer.
//
// AUD-04: the signer covers ONLY audit-metadata fields — Title, Target, Time,
// DryRun, PrevHash, and the DiffHash digest. No Body, Content, Data, Raw, or
// Payload field may ever be added; the [32]byte type for DiffHash prevents
// slicing tricks that could smuggle extra data into the signed payload, and the
// forbidigo lint rule in .golangci.yml rejects any future field with a
// forbidden name. The expansion (CR-03) authenticates the tamper-sensitive
// metadata of the tail entry — which has no successor and is therefore not
// protected by the hash chain — so Target/Time/DryRun cannot be rewritten
// undetected. Title maps to Entry.Op, Time is the RFC3339 UTC timestamp, and
// PrevHash is the chain link; none of these carry file content.
type SignInput struct {
	Title    string
	Target   string
	Time     string // RFC3339 UTC, must match Entry.Time serialisation
	DryRun   bool
	PrevHash string
	DiffHash [32]byte
}

// signBytes serialises a SignInput to the canonical HMAC input using
// LENGTH-PREFIXED framing (WR-01): every variable-length field is preceded by
// its byte length as a fixed-width big-endian uint32. This makes the field
// boundaries unambiguous regardless of field contents — unlike a single-byte
// separator, no value (even one containing NUL bytes) can shift content across
// a field boundary while keeping the HMAC valid. The fixed-width dryRun byte and
// the fixed-size 32-byte DiffHash need no length prefix.
//
//	len(title) title len(target) target len(time) time dryRun(1) len(prevHash) prevHash 32 DiffHash bytes
//
// Append and Verify both call signBytes, so they produce identical bytes.
//
// AUD-04: every field here is audit metadata; no body/content is ever signed.
func signBytes(in SignInput) []byte {
	dryRun := byte(0)
	if in.DryRun {
		dryRun = 1
	}
	// Capacity: 4 four-byte length prefixes (title, target, time, prevHash) +
	// the field bytes + 1 dryRun byte + the 32-byte DiffHash.
	b := make([]byte, 0, 4*4+len(in.Title)+len(in.Target)+len(in.Time)+len(in.PrevHash)+1+len(in.DiffHash))
	b = appendLenPrefixed(b, in.Title)
	b = appendLenPrefixed(b, in.Target)
	b = appendLenPrefixed(b, in.Time)
	b = append(b, dryRun)
	b = appendLenPrefixed(b, in.PrevHash)
	b = append(b, in.DiffHash[:]...)
	return b
}

// appendLenPrefixed writes s's length as a big-endian uint32 followed by s's
// bytes, giving unambiguous field framing for the HMAC input (WR-01). Audit
// metadata fields (Op/Target/Time/PrevHash) are far below the uint32 ceiling;
// the explicit guard keeps the conversion overflow-safe (gosec G115) without
// silently truncating a length prefix should that invariant ever be violated.
func appendLenPrefixed(b []byte, s string) []byte {
	if uint64(len(s)) > math.MaxUint32 {
		// Defensive: a field this large is never produced by the audit writer.
		// Truncating the prefix would desync framing, so refuse by clamping the
		// signed length to the max — Append and Verify clamp identically, so the
		// HMAC still matches and the (impossible) case fails closed elsewhere.
		s = s[:math.MaxUint32]
	}
	var lenBuf [4]byte
	// #nosec G115 -- len(s) clamped to math.MaxUint32 above; conversion cannot overflow
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s))) //nolint:gosec // G115: len(s) clamped to math.MaxUint32 above; conversion cannot overflow
	b = append(b, lenBuf[:]...)
	b = append(b, []byte(s)...)
	return b
}

// SignedAudit appends HMAC-signed, hash-chained entries to logPath. It is
// goroutine-safe: the mutex spans the entire read-compute-write sequence so two
// concurrent appends can never observe the same prev_hash (which would fork the
// chain). Multiple SignedAudit instances for different paths do not contend.
type SignedAudit struct {
	logPath string
	kc      KeychainStore
	mu      sync.Mutex
	count   int64 // atomic — entries appended by this instance
}

// NewSigned returns a SignedAudit. If the HMAC key is absent from the keychain
// it is auto-generated (32 random bytes, hex-encoded) and stored. Returns an
// error when the keychain is unavailable — callers MUST fail closed (AUD-02).
func NewSigned(logPath string, kc KeychainStore) (*SignedAudit, error) {
	ctx := context.Background()
	if _, err := kc.Get(ctx, hmacKeyService, hmacKeyAccount); err != nil {
		key := make([]byte, hmacKeyBytes)
		if _, rerr := io.ReadFull(rand.Reader, key); rerr != nil {
			return nil, fmt.Errorf("audit: generate hmac key: %w", rerr)
		}
		if serr := kc.Set(ctx, hmacKeyService, hmacKeyAccount, hex.EncodeToString(key)); serr != nil {
			return nil, fmt.Errorf("audit: store hmac key: %w", serr)
		}
	}
	return &SignedAudit{logPath: logPath, kc: kc}, nil
}

// LogPath returns the path this SignedAudit appends to.
func (a *SignedAudit) LogPath() string { return a.logPath }

// WriteFile is the signed-path equivalent of *Audit.WriteFile and satisfies the
// AuditWriter interface. It records the intended mutation as an HMAC-signed,
// hash-chained entry FIRST (recording only the SHA-256 of content, never the
// content), then performs the physical write. This append-before-write ordering
// matches *Audit.WriteFile and the project's audit-then-write convention
// (T-17-14): if the process crashes between the log append and the write, an
// operator sees the recorded intent without the effect.
//
// It uses context.Background() internally — justified by the AuditWriter
// interface omitting ctx for drop-in *Audit compatibility (WriteFile is a
// convenience wrapper over Append, not a hot path; see interface.go).
func (a *SignedAudit) WriteFile(path string, content []byte, perm os.FileMode, dryRun bool) error {
	ctx := context.Background()

	// Record intent in the signed chain FIRST (audit-then-write ordering).
	diffHash := sha256.Sum256(content)
	if err := a.Append(ctx, SignInput{Title: "write", DiffHash: diffHash}, path, dryRun); err != nil {
		return err
	}

	if dryRun {
		return nil
	}

	// Back up an existing file before overwriting it so the change is reversible.
	if _, statErr := os.Stat(path); statErr == nil {
		if _, bErr := Backup(path); bErr != nil {
			return fmt.Errorf("audit: backup before write %s: %w", path, bErr)
		}
	}

	tmp := path + ".abysslink.tmp"
	if err := os.WriteFile(tmp, content, perm); err != nil { //nolint:gosec // perm supplied by caller; tmp is path-derived
		return fmt.Errorf("audit: write temp %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// hmacKey fetches and hex-decodes the stored HMAC key for this instance.
func (a *SignedAudit) hmacKey(ctx context.Context) ([]byte, error) {
	return fetchHMACKey(ctx, a.kc)
}

// fetchHMACKey fetches and hex-decodes the stored HMAC key. It is a
// package-private FUNCTION (not a method) so WriteAnchor and Verify can read
// the key WITHOUT constructing a *SignedAudit — constructing one would
// auto-generate/rotate the key on first use and break the existing chain.
func fetchHMACKey(ctx context.Context, kc KeychainStore) ([]byte, error) {
	hexKey, err := kc.Get(ctx, hmacKeyService, hmacKeyAccount)
	if err != nil {
		return nil, fmt.Errorf("audit: fetch hmac key: %w", err)
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("audit: decode hmac key: %w", err)
	}
	return key, nil
}

// computeSig returns the hex-encoded HMAC-SHA256 of in under key.
func computeSig(key []byte, in SignInput) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(signBytes(in))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyHMAC is a constant-time HMAC check. It returns false (never panics) on
// any malformed input — wrong key, bad hex, truncated sig, or empty sig. It uses
// hmac.Equal to avoid a timing side-channel (never bytes.Equal).
func verifyHMAC(key []byte, in SignInput, sigHex string) bool {
	gotBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(gotBytes) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(signBytes(in))
	return hmac.Equal(mac.Sum(nil), gotBytes)
}

// readLastNonEmptyLine returns the last non-empty line of the log as bytes
// WITHOUT the trailing newline. A missing file yields (nil, nil).
//
// O(N) scan — acceptable for Phase 17; see RESEARCH.md Pitfall 3 for the future
// seek-backward optimisation. This runs under the SignedAudit mutex.
func readLastNonEmptyLine(logPath string) ([]byte, error) {
	f, err := os.Open(logPath) //nolint:gosec // logPath is an internal, app-controlled path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open log %s: %w", logPath, err)
	}
	defer f.Close() //nolint:errcheck // errcheck: close error on read-only/append file handle is non-actionable; data durability handled by explicit Sync where required

	var last []byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// scanner.Bytes() is only valid until the next Scan; copy it.
		last = append(last[:0], line...)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: read log %s: %w", logPath, err)
	}
	return last, nil
}

// computePrevHash returns genesisMarker when the log is empty, otherwise
// hex(sha256(last raw JSONL line)).
func computePrevHash(logPath string) (string, error) {
	last, err := readLastNonEmptyLine(logPath)
	if err != nil {
		return "", err
	}
	if len(last) == 0 {
		return genesisMarker, nil
	}
	sum := sha256.Sum256(last)
	return hex.EncodeToString(sum[:]), nil
}

// Append writes one HMAC-signed, hash-chained Entry to the log. The content is
// never written — only its DiffHash digest and the HMAC sig. dryRun tags the
// entry without changing the chain.
//
// CRITICAL MUTEX SCOPE: mu is held across the entire read→compute→write
// sequence. mu.Unlock() is called EXPLICITLY (not via defer) before the
// best-effort anchor write, so the anchor write never happens under the mutex.
func (a *SignedAudit) Append(ctx context.Context, in SignInput, target string, dryRun bool) error {
	a.mu.Lock()

	key, err := a.hmacKey(ctx)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	prevHash, err := computePrevHash(a.logPath)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	now := time.Now().UTC()
	// Build the FULL signing input so the HMAC authenticates every
	// tamper-sensitive metadata field (CR-03). Verify reconstructs the
	// identical input from the parsed Entry, so the two must agree byte-for-byte
	// — in particular Time must serialise to the same RFC3339 form Verify reads
	// back from the JSON entry.
	in.Target = target
	in.Time = now.Format(time.RFC3339)
	in.DryRun = dryRun
	in.PrevHash = prevHash
	entry := Entry{
		Time:     now,
		Op:       in.Title,
		Target:   target,
		Hash:     hex.EncodeToString(in.DiffHash[:]),
		DryRun:   dryRun,
		PrevHash: prevHash,
		Sig:      computeSig(key, in),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		a.mu.Unlock()
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: a.logPath is the internal audit-log path set at construction, not user-controlled
	if err != nil {
		a.mu.Unlock()
		return fmt.Errorf("audit: open log %s: %w", a.logPath, err)
	}
	if _, werr := f.Write(line); werr != nil {
		_ = f.Close()
		a.mu.Unlock()
		return fmt.Errorf("audit: write log: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		a.mu.Unlock()
		return fmt.Errorf("audit: close log: %w", cerr)
	}

	a.mu.Unlock() // explicit — must precede the post-lock anchor write below.

	// AUD-02: anchor refreshed on EVERY append (not cadenced).
	// Failure hard-fails Append; WriteFile callers abort before physical write
	// because Append returns error first (D-03 write-ordering correctness).
	atomic.AddInt64(&a.count, 1)
	if aerr := WriteAnchor(ctx, a.logPath, a.kc); aerr != nil {
		return fmt.Errorf("audit: anchor write failed (mutation aborted): %w", aerr)
	}
	// AUD-02: keychain counter incremented after successful anchor write.
	// Counter failure does NOT abort — anchor is already written; Verify
	// will report CounterStatus="unknown" on the next run.
	if cerr := IncrementCounter(ctx, a.kc); cerr != nil {
		slog.Warn("audit: keychain counter increment failed", "err", cerr, "log", a.logPath)
	}
	return nil
}
