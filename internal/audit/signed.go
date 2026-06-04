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
	"path/filepath"
	"sync"
	"time"
)

const writeFilePathCeiling = 256 << 20 // 256 MiB — D-06 WR-02 streaming ceiling

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
// Pre-overwrite backups are recorded as signed chain entries via backupNoRefresh
// (AUD-01 / D-08) so RestoreGated can later locate and verify them. The backup
// entry, the write-intent entry, the WriteAnchor+addCounter refresh, AND the
// physical target write+rename ALL run under a SINGLE mutex+OS-flock critical
// section (D-07 / D-08 / CR-01 / CR-02): the keychain counter always equals the
// JSONL entry count at any process-kill point, the chain-attested .bak is the
// byte-identical file on disk, and concurrent same-target writers serialise on
// the physical write (each using a unique os.CreateTemp temp path) instead of
// racing on a shared temp suffix.
//
// It uses context.Background() internally — justified by the AuditWriter
// interface omitting ctx for drop-in *Audit compatibility (WriteFile is a
// convenience wrapper over Append, not a hot path; see interface.go).
func (a *SignedAudit) WriteFile(path string, content []byte, perm os.FileMode, dryRun bool) error {
	ctx := context.Background()

	// Check whether a pre-existing file must be backed up (before acquiring mu).
	// os.Stat is idempotent and lock-free; the result is rechecked inside the
	// critical section only if needed. A race here is safe: if the file disappears
	// between Stat and the flock acquisition, backupNoRefresh will return an error
	// and WriteFile aborts — the correct outcome.
	_, existErr := os.Stat(path)
	fileExists := existErr == nil

	// D-08: Acquire in-process mutex, then OS flock — mutex-then-flock ordering
	// is strictly enforced (RESEARCH.md RQ-1 / PATTERNS.md pitfall 7).
	a.mu.Lock()
	lockFD, err := acquireAuditLock(a.logPath)
	if err != nil {
		a.mu.Unlock()
		return fmt.Errorf("audit: acquire process lock: %w", err)
	}

	// CR-01 / CR-02: EVERYTHING below — the backup .bak, the JSONL chain entries,
	// the anchor+counter refresh, AND the physical target write+rename — happens
	// under the SAME mutex+flock. The lock is released exactly once, on every exit
	// path, via the deferred unlock. This is what guarantees:
	//   * the .bak attested in the chain is the byte-identical file on disk
	//     (no unlocked re-read that a concurrent writer could change — CR-01), and
	//   * two WriteFile calls to the same target serialise their physical writes
	//     instead of racing on a shared temp path (CR-02).
	unlocked := false
	unlock := func() {
		if unlocked {
			return
		}
		unlocked = true
		releaseAuditLock(lockFD)
		a.mu.Unlock()
	}
	defer unlock()

	// D-08: entryCount tracks the number of JSONL entries appended under this flock
	// so the keychain counter can be advanced by the exact batch size.
	var entryCount int64

	if fileExists {
		// AUD-01: record the backup as a signed chain entry without triggering a
		// per-entry anchor/counter refresh (backupNoRefresh). backupNoRefresh ALSO
		// creates the physical .bak under this flock with the exact stamp recorded
		// in the chain entry — there is no separate unlocked backup write (CR-01).
		if bErr := a.backupNoRefresh(ctx, path, dryRun); bErr != nil {
			return fmt.Errorf("audit: backup before write %s: %w", path, bErr)
		}
		entryCount++
	}

	// Record write-intent entry without per-entry anchor/counter refresh.
	diffHash := sha256.Sum256(content)
	if wErr := a.appendNoRefresh(ctx, SignInput{Title: "write", DiffHash: diffHash}, path, dryRun); wErr != nil {
		return wErr
	}
	entryCount++

	// Refresh anchor and counter while STILL holding the flock (CR-02). Doing this
	// under the lock keeps the keychain counter and the JSONL entry count in step
	// at every process-kill point: a crash can leave recorded intent without the
	// physical effect (the documented append-before-write window), but never a
	// "counter behind entries" state that audit-count-vs-anchor reads as a false
	// truncation alarm.
	if aerr := WriteAnchor(ctx, a.logPath, a.kc); aerr != nil {
		return fmt.Errorf("audit: anchor write failed (mutation aborted): %w", aerr)
	}
	if cerr := addCounter(ctx, a.kc, entryCount); cerr != nil {
		_ = a.kc.Delete(ctx, counterKeyService, counterKeyAccount)
		slog.Warn("audit: keychain counter increment failed; counter key cleared to prevent false mismatch alarm",
			"err", cerr, "log", a.logPath)
	}

	if dryRun {
		return nil
	}

	// Physical write of the target, still under the flock. Use os.CreateTemp for a
	// unique temp name per call so concurrent same-target writers cannot clobber
	// each other's temp file (CR-02) — mirrors the WriteAnchor fix in anchor.go.
	// The temp lives in the target's directory so the rename stays on one device.
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmpFile, err := os.CreateTemp(dir, base+".*.abysslink.tmp")
	if err != nil {
		return fmt.Errorf("audit: create temp for %s: %w", path, err)
	}
	tmp := tmpFile.Name()
	_, werr := tmpFile.Write(content)
	if cerr := tmpFile.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: write temp %s: %w", tmp, werr)
	}
	if cerr := os.Chmod(tmp, perm); cerr != nil { //nolint:gosec // perm supplied by caller; tmp is os.CreateTemp-derived, app-controlled
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: chmod temp %s: %w", tmp, cerr)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// appendNoRefresh appends one HMAC-signed, hash-chained entry to the log WITHOUT
// triggering WriteAnchor or IncrementCounter. It is the internal batch-write
// primitive used by WriteFile so both the backup and write-intent JSONL entries
// share a single flock and a single subsequent anchor/counter refresh (D-08).
//
// MUST be called with a.mu already held and flock already acquired by the caller.
// Does not refresh anchor or counter.
func (a *SignedAudit) appendNoRefresh(ctx context.Context, in SignInput, target string, dryRun bool) error {
	key, err := a.hmacKey(ctx)
	if err != nil {
		return err
	}
	prevHash, err := computePrevHash(a.logPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
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
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: a.logPath is the internal audit-log path set at construction, not user-controlled
	if err != nil {
		return fmt.Errorf("audit: open log %s: %w", a.logPath, err)
	}
	if _, werr := f.Write(line); werr != nil {
		_ = f.Close()
		return fmt.Errorf("audit: write log: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("audit: close log: %w", cerr)
	}
	return nil
}

// backupNoRefresh records a backup chain entry for targetPath WITHOUT triggering
// WriteAnchor or IncrementCounter. It reads targetPath to compute the SHA-256
// hash, writes the .bak file, then appends the signed chain entry via
// appendNoRefresh. Used by WriteFile's batched path (D-08).
//
// MUST be called with a.mu already held and flock already acquired by the caller.
// Does not refresh anchor or counter.
func (a *SignedAudit) backupNoRefresh(ctx context.Context, targetPath string, dryRun bool) error {
	content, err := os.ReadFile(targetPath) //nolint:gosec // G304: targetPath is an audit-controlled path, not user input
	if err != nil {
		return fmt.Errorf("audit: backup read %s: %w", targetPath, err)
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	bakPath := fmt.Sprintf("%s.bak.%s", targetPath, stamp)
	if err := os.WriteFile(bakPath, content, 0o600); err != nil { //nolint:gosec // G304: bakPath is derived from targetPath, not user input; 0o600 enforces owner-only perms
		return fmt.Errorf("audit: backup write %s: %w", bakPath, err)
	}
	diffHash := sha256.Sum256(content)
	if aerr := a.appendNoRefresh(ctx, SignInput{Title: "backup", DiffHash: diffHash}, bakPath, dryRun); aerr != nil {
		_ = os.Remove(bakPath) // rollback: remove orphaned .bak on chain-append failure
		return fmt.Errorf("audit: backup chain-entry failed (backup rolled back): %w", aerr)
	}
	return nil
}

// WriteFilePath is the streaming equivalent of WriteFile for large binary
// installs (D-06 / WR-02). It reads src via io.Copy with a 256 MiB ceiling,
// never loading the file into memory. If src exceeds 256 MiB the function
// returns an error and cleans up any temp file before returning.
//
// This is the SOLE definition of WriteFilePath on *SignedAudit.
func (a *SignedAudit) WriteFilePath(ctx context.Context, src, dst string, perm os.FileMode, dryRun bool) error {
	// Step 1: compute SHA-256 of src via a streaming hasher — N+1 sentinel detects
	// overflow at exactly writeFilePathCeiling bytes without silent truncation.
	srcFile, err := os.Open(src) //nolint:gosec // G304: src is a caller-supplied binary path; callers in internal/cli supply installer-derived paths, not user-controlled paths
	if err != nil {
		return fmt.Errorf("audit: WriteFilePath open src %s: %w", src, err)
	}

	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(srcFile, writeFilePathCeiling+1))
	_ = srcFile.Close()
	if err != nil {
		return fmt.Errorf("audit: WriteFilePath hash src %s: %w", src, err)
	}
	if n > writeFilePathCeiling {
		return fmt.Errorf("audit: WriteFilePath: src %s exceeds 256 MiB ceiling", src)
	}

	// Step 2: record audit intent entry with the hash.
	var diffHash [32]byte
	copy(diffHash[:], hasher.Sum(nil))
	if aerr := a.Append(ctx, SignInput{Title: "write", DiffHash: diffHash}, dst, dryRun); aerr != nil {
		return aerr
	}

	if dryRun {
		return nil
	}

	// Step 3: stream src to a temp file via io.Copy+LimitReader, then rename.
	srcFile2, err := os.Open(src) //nolint:gosec // G304: same path as above; see note on step 1
	if err != nil {
		return fmt.Errorf("audit: WriteFilePath reopen src %s: %w", src, err)
	}
	defer func() { _ = srcFile2.Close() }()

	// CR-02 (parity with WriteFile): use os.CreateTemp for a unique temp name per
	// call so two concurrent same-target callers cannot clobber each other's temp
	// file. The temp lives in dst's directory so the rename stays on one device.
	tmpFile, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".*.abysslink.tmp")
	if err != nil {
		return fmt.Errorf("audit: WriteFilePath create temp for %s: %w", dst, err)
	}
	tmp := tmpFile.Name()

	if _, cerr := io.Copy(tmpFile, io.LimitReader(srcFile2, writeFilePathCeiling)); cerr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: WriteFilePath copy to temp: %w", cerr)
	}
	if cerr := tmpFile.Close(); cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: WriteFilePath close temp: %w", cerr)
	}
	if cerr := os.Chmod(tmp, perm); cerr != nil { //nolint:gosec // perm supplied by caller; tmp is os.CreateTemp-derived, app-controlled
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: WriteFilePath chmod temp %s: %w", tmp, cerr)
	}

	if rerr := os.Rename(tmp, dst); rerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: WriteFilePath rename %s → %s: %w", tmp, dst, rerr)
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
// CRITICAL LOCK SCOPE: the in-process mutex AND the cross-process OS flock are
// both held across the entire read→compute→write→anchor sequence (WR-01 / WR-06).
// WriteFilePath→Append and the daemon's hourly anchor path run in DIFFERENT
// processes; the in-process mutex alone does nothing across that boundary, so
// without the flock two processes could computePrevHash off the same tail and
// fork the chain. Holding the flock through WriteAnchor also keeps the anchor's
// EntryCount/LastHash consistent with the log a concurrent appender cannot mutate
// mid-read. Both locks are released exactly once, on every exit, via the deferred
// unlock — so the keychain counter step below also runs under the lock.
func (a *SignedAudit) Append(ctx context.Context, in SignInput, target string, dryRun bool) error {
	// WR-01: mutex-then-flock ordering, identical to WriteFile.
	a.mu.Lock()
	lockFD, lerr := acquireAuditLock(a.logPath)
	if lerr != nil {
		a.mu.Unlock()
		return fmt.Errorf("audit: acquire process lock: %w", lerr)
	}
	unlocked := false
	unlock := func() {
		if unlocked {
			return
		}
		unlocked = true
		releaseAuditLock(lockFD)
		a.mu.Unlock()
	}
	defer unlock()

	key, err := a.hmacKey(ctx)
	if err != nil {
		return err
	}
	prevHash, err := computePrevHash(a.logPath)
	if err != nil {
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
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: a.logPath is the internal audit-log path set at construction, not user-controlled
	if err != nil {
		return fmt.Errorf("audit: open log %s: %w", a.logPath, err)
	}
	if _, werr := f.Write(line); werr != nil {
		_ = f.Close()
		return fmt.Errorf("audit: write log: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("audit: close log: %w", cerr)
	}

	// AUD-02: anchor refreshed on EVERY append (not cadenced), under the SAME
	// flock as the append (WR-06) so EntryCount/LastHash describe a log state no
	// concurrent appender can change between the two reads inside WriteAnchor.
	// Failure hard-fails Append; WriteFile callers abort before physical write
	// because Append returns error first (D-03 write-ordering correctness).
	if aerr := WriteAnchor(ctx, a.logPath, a.kc); aerr != nil {
		return fmt.Errorf("audit: anchor write failed (mutation aborted): %w", aerr)
	}
	// AUD-02: keychain counter incremented after successful anchor write.
	// Counter failure does NOT abort — anchor is already written (fail-soft
	// contract). On failure the counter key is DELETED so the next ReadCounter
	// returns found=false and verifyCounter reports CounterStatus="unknown"
	// (honest tri-state: "cannot check") rather than leaving the stale value in
	// place and causing a permanent false "mismatch"/TruncationDetected alarm on
	// every subsequent Verify.
	if cerr := IncrementCounter(ctx, a.kc); cerr != nil {
		_ = a.kc.Delete(ctx, counterKeyService, counterKeyAccount) // best-effort: clear stale counter to avoid false mismatch
		slog.Warn("audit: keychain counter increment failed; counter key cleared to prevent false mismatch alarm",
			"err", cerr, "log", a.logPath)
	}
	return nil
}
