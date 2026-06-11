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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/abysslink/abysslink/internal/secrets"
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
//
// The HMAC key is cached in memory for the SignedAudit's lifetime (R2-12):
// fetching it from the OS keychain spawns a `security`/`secret-tool`
// subprocess per call, and an in-process copy is no weaker than the trusted
// process memory already holding signed material.
type SignedAudit struct {
	logPath string
	kc      KeychainStore
	mu      sync.Mutex

	keyMu sync.Mutex
	key   []byte // cached HMAC key; nil until fetched or generated
}

// NewSigned returns a SignedAudit. The keychain is probed READ-ONLY: if the
// HMAC key exists it is cached; if the keychain is unavailable an error is
// returned — callers MUST fail closed (AUD-02). If the key is definitively
// absent (errors.Is(err, secrets.ErrNotFound)) construction still succeeds and
// key GENERATION is deferred to the first mutating Append (R2-12): read-only
// paths (doctor, status, verify wiring) must never write to the keychain, and
// generation happens under the audit flock so two first-run processes cannot
// race Get→Set and overwrite each other's key (R2-W5).
//
// CORE-04: a new key is generated ONLY when the keychain definitively reports
// the key absent. Any other Get failure (keychain locked, denied, dbus down)
// propagates as an error WITHOUT writing: overwriting the existing key on a
// transient hiccup would permanently break verification of the entire
// tamper-evident chain.
func NewSigned(logPath string, kc KeychainStore) (*SignedAudit, error) {
	sa := &SignedAudit{logPath: logPath, kc: kc}
	key, err := fetchHMACKey(context.Background(), kc)
	switch {
	case err == nil:
		sa.key = key
	case errors.Is(err, secrets.ErrNotFound):
		// Lazy creation: generated on the first mutating Append (ensureKeyLocked).
	default:
		return nil, fmt.Errorf("audit: keychain unavailable, refusing to (re)generate hmac key (fail closed): %w", err)
	}
	return sa, nil
}

// LogPath returns the path this SignedAudit appends to.
func (a *SignedAudit) LogPath() string { return a.logPath }

// hmacKey returns the cached HMAC key, fetching (and caching) it from the
// keychain on first use. It NEVER generates a key — see ensureKeyLocked.
func (a *SignedAudit) hmacKey(ctx context.Context) ([]byte, error) {
	a.keyMu.Lock()
	if a.key != nil {
		k := a.key
		a.keyMu.Unlock()
		return k, nil
	}
	a.keyMu.Unlock()
	key, err := fetchHMACKey(ctx, a.kc)
	if err != nil {
		return nil, err
	}
	a.keyMu.Lock()
	a.key = key
	a.keyMu.Unlock()
	return key, nil
}

// ensureKeyLocked returns the HMAC key, generating and storing a fresh one when
// the keychain definitively reports it absent (lazy first-run creation).
//
// MUST be called with the audit flock held: the flock serialises concurrent
// first-run initialisation across processes (CLI vs abysslinkd), so two
// processes cannot both see ErrNotFound and overwrite each other's key —
// which would make entries signed under the lost key permanently unverifiable
// (R2-W5).
func (a *SignedAudit) ensureKeyLocked(ctx context.Context) ([]byte, error) {
	key, err := a.hmacKey(ctx)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		return nil, fmt.Errorf("audit: keychain unavailable, refusing to (re)generate hmac key (fail closed): %w", err)
	}
	fresh := make([]byte, hmacKeyBytes)
	if _, rerr := io.ReadFull(rand.Reader, fresh); rerr != nil {
		return nil, fmt.Errorf("audit: generate hmac key: %w", rerr)
	}
	if serr := a.kc.Set(ctx, hmacKeyService, hmacKeyAccount, hex.EncodeToString(fresh)); serr != nil {
		return nil, fmt.Errorf("audit: store hmac key: %w", serr)
	}
	a.keyMu.Lock()
	a.key = fresh
	a.keyMu.Unlock()
	return fresh, nil
}

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
	// CORE-05: dry-run writes NOTHING — no .bak file, no chain entries, no
	// anchor refresh, no keychain counter bump. Recording chain entries under
	// dry-run would mutate disk and keychain state, violating the --dry-run
	// contract; recording entries WITHOUT bumping the counter would desync
	// counter-vs-entry-count and trip a false truncation alarm. So the signed
	// path records nothing at all for a dry run (unlike the legacy unsigned
	// *Audit, which appends a DryRun-tagged plain entry).
	if dryRun {
		return nil
	}

	ctx := context.Background()

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

	return a.writeFileLocked(ctx, path, content, perm)
}

// Update performs a lost-update-free, cross-process read-modify-write of path
// for the signed writer — the SignedAudit counterpart of *Audit.Update. It
// acquires a.mu then the OS flock (the SAME mutex-then-flock order WriteFile
// uses, so no ABBA deadlock can form between a concurrent WriteFile and an
// Update in the same process), calls content() under both locks — which MUST
// read the CURRENT on-disk state of path and return the full new bytes — then
// records the signed chain entry (backup + write-intent), refreshes the
// anchor/counter, and atomically writes, all under the held locks.
//
// content may return (nil, nil) for "no change": Update then writes and records
// nothing, having still held the lock across the freshness read. A non-nil
// error aborts with no write. Dry runs are NOT supported here — the device
// store only calls Update for real mutations.
func (a *SignedAudit) Update(_ context.Context, path string, perm os.FileMode, content func() ([]byte, error)) error {
	ctx := context.Background()

	a.mu.Lock()
	lockFD, err := acquireAuditLock(a.logPath)
	if err != nil {
		a.mu.Unlock()
		return fmt.Errorf("audit: acquire process lock: %w", err)
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

	data, derr := content()
	if derr != nil {
		return derr
	}
	if data == nil {
		return nil // caller signalled no change
	}
	return a.writeFileLocked(ctx, path, data, perm)
}

// writeFileLocked is the signed backup+append+anchor+write body of WriteFile
// WITHOUT lock acquisition. It MUST be called with a.mu AND the OS flock held
// (WriteFile and Update both establish that before calling). It records the
// backup and write-intent chain entries, refreshes the anchor/counter, and
// atomically writes content to path.
func (a *SignedAudit) writeFileLocked(ctx context.Context, path string, content []byte, perm os.FileMode) error {
	// R2-W5/R2-12: the key is fetched (or lazily generated) under the flock.
	key, kerr := a.ensureKeyLocked(ctx)
	if kerr != nil {
		return kerr
	}

	// CORE-03 parity (R2-W2): refuse a symlink target, checked INSIDE the flock
	// — the unsigned path documents the residual check-then-act window; running
	// the Lstat under the lock shrinks it for the signed path.
	fi, statErr := os.Lstat(path)
	fileExists := statErr == nil
	if fileExists && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("audit: refusing to write %s: target is a symlink", path)
	}

	// D-08: entryCount tracks the number of JSONL entries appended under this flock
	// so the keychain counter can be advanced by the exact batch size.
	var entryCount int64

	if fileExists {
		// AUD-01: record the backup as a signed chain entry without triggering a
		// per-entry anchor/counter refresh (backupNoRefresh). backupNoRefresh ALSO
		// creates the physical .bak under this flock with the exact stamp recorded
		// in the chain entry — there is no separate unlocked backup write (CR-01).
		// dryRun is always false here: WriteFile short-circuits dry runs before
		// locking, and Update is only called for real mutations.
		if bErr := a.backupNoRefresh(ctx, path, false); bErr != nil {
			return fmt.Errorf("audit: backup before write %s: %w", path, bErr)
		}
		entryCount++
	}

	// Record write-intent entry without per-entry anchor/counter refresh.
	diffHash := sha256.Sum256(content)
	if wErr := a.appendNoRefresh(ctx, SignInput{Title: "write", DiffHash: diffHash}, path, false); wErr != nil {
		return wErr
	}
	entryCount++

	// Refresh anchor and counter while STILL holding the flock (CR-02). Doing this
	// under the lock keeps the keychain counter and the JSONL entry count in step
	// at every process-kill point: a crash can leave recorded intent without the
	// physical effect (the documented append-before-write window), but never a
	// "counter behind entries" state that audit-count-vs-anchor reads as a false
	// truncation alarm.
	if aerr := writeAnchorWithKey(ctx, a.logPath, key); aerr != nil {
		return fmt.Errorf("audit: anchor write failed (mutation aborted): %w", aerr)
	}
	if cerr := addCounter(ctx, a.kc, entryCount); cerr != nil {
		// R2-I2: do NOT delete the counter key on a transient Set failure — the
		// stale (lagging) counter degrades to CounterStatus="unknown" on the next
		// Verify, while deleting it would let an attacker who can wedge keychain
		// writes erase the tail-truncation signal entirely.
		slog.Warn("audit: keychain counter increment failed; counter now lags the log (Verify reports unknown)",
			"err", cerr, "log", a.logPath)
	}

	// Physical write of the target, still under the flock, via the shared
	// atomic temp/chmod/rename/fsync helper (CR-02, R2-E2).
	return atomicWriteFile(path, content, perm)
}

// appendNoRefresh appends one HMAC-signed, hash-chained entry to the log WITHOUT
// triggering WriteAnchor or IncrementCounter. It is the internal batch-write
// primitive used by WriteFile so both the backup and write-intent JSONL entries
// share a single flock and a single subsequent anchor/counter refresh (D-08).
//
// MUST be called with the flock already acquired by the caller (and a.mu held
// on SignedAudit's own paths). Does not refresh anchor or counter.
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
	// Build the FULL signing input so the HMAC authenticates every
	// tamper-sensitive metadata field (CR-03). Verify reconstructs the
	// identical input from the parsed Entry, so the two must agree
	// byte-for-byte — in particular Time must serialise to the same RFC3339
	// form Verify reads back from the JSON entry.
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
	// R2-W4: fsync the append so the recorded intent is durable before any
	// subsequent physical rename can be.
	return appendLineSynced(a.logPath, line)
}

// appendAndRefreshLocked appends one signed entry and then refreshes the anchor
// and keychain counter. It is the shared signed-append core used by both
// SignedAudit.Append and the chain-aware unsigned *Audit (R2-C1), so the two
// writers produce byte-identical chain semantics.
//
// MUST be called with the audit flock already held by the caller.
func (a *SignedAudit) appendAndRefreshLocked(ctx context.Context, in SignInput, target string, dryRun bool) error {
	if err := a.appendNoRefresh(ctx, in, target, dryRun); err != nil {
		return err
	}
	key, err := a.hmacKey(ctx)
	if err != nil {
		return err
	}
	// AUD-02: anchor refreshed on EVERY append (not cadenced), under the SAME
	// flock as the append (WR-06) so EntryCount/LastHash describe a log state no
	// concurrent appender can change between the two reads inside WriteAnchor.
	if aerr := writeAnchorWithKey(ctx, a.logPath, key); aerr != nil {
		return fmt.Errorf("audit: anchor write failed (mutation aborted): %w", aerr)
	}
	// AUD-02: keychain counter incremented after successful anchor write.
	// Counter failure does NOT abort — anchor is already written (fail-soft
	// contract). R2-I2: the counter key is NOT deleted on failure; a lagging
	// counter degrades to CounterStatus="unknown" honestly, while deletion
	// would hand an attacker a way to erase the truncation signal.
	if cerr := IncrementCounter(ctx, a.kc); cerr != nil {
		slog.Warn("audit: keychain counter increment failed; counter now lags the log (Verify reports unknown)",
			"err", cerr, "log", a.logPath)
	}
	return nil
}

// backupNoRefresh records a backup chain entry for targetPath WITHOUT triggering
// WriteAnchor or IncrementCounter. It reads targetPath to compute the SHA-256
// hash, writes the .bak file atomically (preserving the original's permission
// bits — R2-W3), then appends the signed chain entry via appendNoRefresh. Used
// by WriteFile's batched path (D-08).
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
	if err := atomicWriteFile(bakPath, content, sourceMode(targetPath)); err != nil {
		return fmt.Errorf("audit: backup write %s: %w", bakPath, err)
	}
	diffHash := sha256.Sum256(content)
	if aerr := a.appendNoRefresh(ctx, SignInput{Title: "backup", DiffHash: diffHash}, bakPath, dryRun); aerr != nil {
		_ = os.Remove(bakPath) // rollback: remove orphaned .bak on chain-append failure
		return fmt.Errorf("audit: backup chain-entry failed (backup rolled back): %w", aerr)
	}
	return nil
}

// backupFileStreamingNoRefresh is the streaming sibling of backupNoRefresh for
// large binaries (WriteFilePath targets, up to 256 MiB): it copies targetPath
// to a .bak via a temp file while hashing the SAME bytes (io.TeeReader), so the
// chain-attested hash is computed from exactly the content that landed in the
// .bak — no read-hash-reread window (R2-W1).
//
// MUST be called with a.mu already held and flock already acquired by the caller.
func (a *SignedAudit) backupFileStreamingNoRefresh(ctx context.Context, targetPath string) error {
	in, err := os.Open(targetPath) //nolint:gosec // G304: targetPath is an audit-controlled path, not user input
	if err != nil {
		return fmt.Errorf("audit: backup read %s: %w", targetPath, err)
	}
	defer func() { _ = in.Close() }()

	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	bakPath := fmt.Sprintf("%s.bak.%s", targetPath, stamp)

	tmpFile, err := os.CreateTemp(filepath.Dir(bakPath), filepath.Base(bakPath)+".*.abysslink.tmp")
	if err != nil {
		return fmt.Errorf("audit: backup create temp for %s: %w", bakPath, err)
	}
	hasher := sha256.New()
	if _, cerr := io.Copy(tmpFile, io.TeeReader(in, hasher)); cerr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return fmt.Errorf("audit: backup copy %s: %w", targetPath, cerr)
	}
	if ferr := finalizeTemp(tmpFile, bakPath, sourceMode(targetPath)); ferr != nil {
		return fmt.Errorf("audit: backup write %s: %w", bakPath, ferr)
	}

	var diffHash [32]byte
	copy(diffHash[:], hasher.Sum(nil))
	if aerr := a.appendNoRefresh(ctx, SignInput{Title: "backup", DiffHash: diffHash}, bakPath, false); aerr != nil {
		_ = os.Remove(bakPath) // rollback: remove orphaned .bak on chain-append failure
		return fmt.Errorf("audit: backup chain-entry failed (backup rolled back): %w", aerr)
	}
	return nil
}

// WriteFilePath is the streaming equivalent of WriteFile for large binary
// installs (D-06 / WR-02). It streams src to a temp file beside dst while
// hashing the SAME bytes (io.TeeReader — no hash-then-reopen TOCTOU, R2-W1),
// enforcing the 256 MiB ceiling with an N+1 sentinel so an oversized src is
// rejected, never silently truncated.
//
// CORE-05 parity: dryRun performs and records NOTHING (the chain entry, anchor
// refresh and counter bump are all state mutations the --dry-run contract
// forbids — R2-W1 item 2).
//
// Rule 8: a pre-existing dst is backed up (and chain-attested) before being
// replaced, exactly like WriteFile — a binary swap no longer destroys the old
// file without a .bak.
//
// This is the SOLE definition of WriteFilePath on *SignedAudit.
func (a *SignedAudit) WriteFilePath(ctx context.Context, src, dst string, perm os.FileMode, dryRun bool) error {
	if dryRun {
		return nil
	}

	// Same critical section discipline as WriteFile: mutex, then flock, with
	// every chain entry, anchor/counter refresh AND the physical rename inside.
	a.mu.Lock()
	lockFD, err := acquireAuditLock(a.logPath)
	if err != nil {
		a.mu.Unlock()
		return fmt.Errorf("audit: acquire process lock: %w", err)
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

	key, kerr := a.ensureKeyLocked(ctx)
	if kerr != nil {
		return kerr
	}

	// CORE-03 parity (R2-W2): refuse a symlink destination.
	fi, statErr := os.Lstat(dst)
	dstExists := statErr == nil
	if dstExists && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("audit: refusing to write %s: target is a symlink", dst)
	}

	var entryCount int64
	if dstExists {
		// Rule 8: back up the existing binary (chain-attested) before the swap.
		if bErr := a.backupFileStreamingNoRefresh(ctx, dst); bErr != nil {
			return fmt.Errorf("audit: backup before write %s: %w", dst, bErr)
		}
		entryCount++
	}

	// Stage src beside dst, hashing the same bytes that land in the temp file.
	tmpFile, diffHash, err := stageSrcForWrite(src, dst)
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()

	// Record the write-intent entry BEFORE the rename (the actual mutation),
	// using the hash of exactly the bytes staged in the temp file.
	if aerr := a.appendNoRefresh(ctx, SignInput{Title: "write", DiffHash: diffHash}, dst, false); aerr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return aerr
	}
	entryCount++

	if aerr := writeAnchorWithKey(ctx, a.logPath, key); aerr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("audit: anchor write failed (mutation aborted): %w", aerr)
	}
	if cntErr := addCounter(ctx, a.kc, entryCount); cntErr != nil {
		// R2-I2: never delete the counter key on a transient failure (see WriteFile).
		slog.Warn("audit: keychain counter increment failed; counter now lags the log (Verify reports unknown)",
			"err", cntErr, "log", a.logPath)
	}

	// Physical install: fsync, chmod, rename, dir-sync via the shared helper.
	return finalizeTemp(tmpFile, dst, perm)
}

// stageSrcForWrite streams src into a unique temp file in dst's directory
// while hashing the SAME bytes (io.TeeReader — no hash-then-reopen TOCTOU,
// R2-W1). The LimitReader is given ceiling+1 so a src that grew past the
// ceiling is DETECTED (n > ceiling) rather than silently truncated at the
// boundary. On success the open temp file and the staged-content hash are
// returned; the caller owns finalize/cleanup.
func stageSrcForWrite(src, dst string) (*os.File, [32]byte, error) {
	var diffHash [32]byte
	srcFile, err := os.Open(src) //nolint:gosec // G304: src is a caller-supplied binary path; callers in internal/cli supply installer-derived paths, not user-controlled paths
	if err != nil {
		return nil, diffHash, fmt.Errorf("audit: WriteFilePath open src %s: %w", src, err)
	}
	// Fast-fail on an obviously oversized src before staging anything to disk;
	// the N+1 sentinel below remains the authoritative check (a src can grow
	// between this Stat and the copy).
	if sfi, serr := srcFile.Stat(); serr == nil && sfi.Size() > writeFilePathCeiling {
		_ = srcFile.Close()
		return nil, diffHash, fmt.Errorf("audit: WriteFilePath: src %s exceeds 256 MiB ceiling", src)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".*.abysslink.tmp")
	if err != nil {
		_ = srcFile.Close()
		return nil, diffHash, fmt.Errorf("audit: WriteFilePath create temp for %s: %w", dst, err)
	}
	hasher := sha256.New()
	n, cerr := io.Copy(tmpFile, io.TeeReader(io.LimitReader(srcFile, writeFilePathCeiling+1), hasher))
	_ = srcFile.Close()
	if cerr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, diffHash, fmt.Errorf("audit: WriteFilePath copy to temp: %w", cerr)
	}
	if n > writeFilePathCeiling {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, diffHash, fmt.Errorf("audit: WriteFilePath: src %s exceeds 256 MiB ceiling", src)
	}
	copy(diffHash[:], hasher.Sum(nil))
	return tmpFile, diffHash, nil
}

// fetchHMACKey fetches and hex-decodes the stored HMAC key. It is a
// package-private FUNCTION (not a method) so WriteAnchor and Verify can read
// the key WITHOUT constructing a *SignedAudit — and without any risk of
// triggering key generation, which only ever happens in ensureKeyLocked.
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
// fork the chain. Holding the flock through the anchor write also keeps the
// anchor's EntryCount/LastHash consistent with the log a concurrent appender
// cannot mutate mid-read. Both locks are released exactly once, on every exit,
// via the deferred unlock — so the keychain counter step also runs under the
// lock. Lazy HMAC-key generation (first mutating use) happens here, under the
// flock (R2-W5/R2-12).
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

	if _, kerr := a.ensureKeyLocked(ctx); kerr != nil {
		return kerr
	}
	return a.appendAndRefreshLocked(ctx, in, target, dryRun)
}
