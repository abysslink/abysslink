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

package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/secrets"
)

// AuditWriter is the minimal file-mutation contract this package needs from
// internal/audit. Both audit.New(...) (*audit.Audit) and audit.NewSigned(...)
// (*audit.SignedAudit) satisfy it; tests inject a fake. Defined locally so the
// Store can be unit-tested without touching a real audit log.
type AuditWriter interface {
	// WriteFile records the mutation in the audit log (SHA-256 of content
	// only, never the content itself) and writes content to path atomically.
	WriteFile(path string, content []byte, perm os.FileMode, dryRun bool) error

	// Update runs a lost-update-free, cross-process read-modify-write of path
	// under the same cross-process lock WriteFile uses. content is called with
	// the lock held and MUST re-read the current on-disk state; the bytes it
	// returns are recorded in the audit log and written atomically. content
	// returning (nil, nil) means "no change" (nothing written or recorded).
	// The device store routes every records-file mutation through this so a
	// concurrent process (daemon TouchLastSeen vs. CLI revoke) cannot clobber
	// the other's write — see Store.update.
	Update(ctx context.Context, path string, perm os.FileMode, content func() ([]byte, error)) error
}

// Compile-time guard: the real audit writers must keep satisfying this
// package's view of the contract, so interface drift fails here.
var _ AuditWriter = (audit.AuditWriter)(nil)

// ErrExists is returned by Enroll when an active (non-revoked) device with the
// requested name already exists. Callers wanting new credentials for an
// existing device call Rotate instead.
var ErrExists = errors.New("active device with that name already exists")

// ErrNotFound is returned when no device matches the requested name or ID.
var ErrNotFound = errors.New("device not found")

// touchWriteInterval is the minimum gap between persisted LastSeen updates for
// one device: TouchLastSeen skips the file write when the stored LastSeen is
// already within this window of the reported instant.
const touchWriteInterval = 60 * time.Second

// recordsPerm is the mode of the records file. It holds no recoverable
// secret, but push tokens and bearer hashes are still operator-private.
const recordsPerm os.FileMode = 0o600

// Store manages the device records file and the in-process SSH CA. It is safe
// for concurrent use; every method serializes on one internal mutex. Read
// paths re-load the file when its mtime or size changed since the last load,
// so an external rewrite (another process, a restore) is picked up without a
// restart — VerifyBearer in the daemon hot path relies on this.
type Store struct {
	path string
	aud  AuditWriter
	kc   secrets.KeychainStore
	now  func() time.Time

	mu       sync.Mutex
	file     storeFile
	loaded   bool
	lastMod  time.Time
	lastSize int64
	lastInfo os.FileInfo // for os.SameFile: the audit writer renames into place, so any out-of-process write yields a new inode
	caSigner ssh.Signer  // lazily loaded/created from the keychain, cached
}

// New returns a Store over the records file at path. aud performs every file
// mutation (internal/audit contract: backup + audit entry + atomic write), kc
// holds the SSH CA private key, and now supplies the clock (nil means
// time.Now). New performs no I/O; the file is loaded lazily on first use.
func New(path string, aud AuditWriter, kc secrets.KeychainStore, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{path: path, aud: aud, kc: kc, now: now}
}

// reloadIfChangedLocked loads the records file on first use and re-loads it
// whenever its mtime or size differs from the last load. A missing file is an
// empty registry. Caller must hold s.mu.
func (s *Store) reloadIfChangedLocked() error {
	fi, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		if !s.loaded {
			s.file = newStoreFile()
			s.loaded = true
		}
		// Deleted after a successful load: keep the in-memory state; the
		// next mutation re-creates the file.
		return nil
	}
	if err != nil {
		return fmt.Errorf("device: stat records file %s: %w", s.path, err)
	}
	// Unchanged only when the same inode (os.SameFile) AND same mtime/size:
	// the audit writer commits via temp+rename, so an out-of-process write
	// (CLI revoke/enroll while the daemon serves) always replaces the inode
	// and is caught here even if mtime granularity and size happen to collide.
	if s.loaded && s.lastInfo != nil && os.SameFile(fi, s.lastInfo) &&
		fi.ModTime().Equal(s.lastMod) && fi.Size() == s.lastSize {
		return nil
	}

	return s.loadFromDiskLocked()
}

// loadFromDiskLocked unconditionally reads, parses, and commits the records
// file from disk into s.file, refreshing the change-detection fingerprint. It
// IGNORES the mtime/size/inode cache — callers use it when they need the
// CURRENT on-disk bytes regardless of what was last loaded (the locked
// read-modify-write in update relies on this so a stale cache can never seed a
// lost update). A missing file becomes an empty registry. Caller must hold
// s.mu (and, for update's freshness guarantee, the cross-process audit flock).
func (s *Store) loadFromDiskLocked() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		s.file = newStoreFile()
		s.loaded = true
		s.lastInfo = nil
		s.lastMod = time.Time{}
		s.lastSize = 0
		return nil
	}
	if err != nil {
		return fmt.Errorf("device: read records file %s: %w", s.path, err)
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("device: parse records file %s: %w", s.path, err)
	}
	if f.Version != fileVersion {
		return fmt.Errorf("device: records file %s: unsupported version %d (want %d)", s.path, f.Version, fileVersion)
	}
	if f.NextSerial == 0 {
		f.NextSerial = 1
	}
	if f.Devices == nil {
		f.Devices = []Record{}
	}
	s.file = f
	s.loaded = true
	if fi, statErr := os.Stat(s.path); statErr == nil {
		s.lastMod = fi.ModTime()
		s.lastSize = fi.Size()
		s.lastInfo = fi
	}
	return nil
}

// saveLocked writes f through the audit writer as ONE atomic mutation, then
// commits it to memory and refreshes the change-detection fingerprint. On
// error the in-memory state is left untouched (memory never runs ahead of
// disk). Caller must hold s.mu.
func (s *Store) saveLocked(f storeFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("device: marshal records file: %w", err)
	}
	data = append(data, '\n')
	if err := s.aud.WriteFile(s.path, data, recordsPerm, false); err != nil {
		return fmt.Errorf("device: write records file %s: %w", s.path, err)
	}
	s.file = f
	s.loaded = true
	if fi, statErr := os.Stat(s.path); statErr == nil {
		s.lastMod = fi.ModTime()
		s.lastSize = fi.Size()
		s.lastInfo = fi
	}
	return nil
}

// update is the single cross-process-safe read-modify-write path for every
// records-file mutation. It holds s.mu (in-process serialization) and routes
// through s.aud.Update, which holds the cross-process audit flock for the whole
// closure. Inside that closure update reloads the CURRENT on-disk file (fresh,
// ignoring the change-detection cache), runs mutate on it, and — only when
// mutate reports a change — returns the marshalled bytes for the audited write.
//
// This closes the lost-update race the in-process mutex alone left open: the
// daemon's TouchLastSeen and the CLI's Revoke run in separate processes, so
// without the flock-protected reload-then-write the later writer would clobber
// the earlier one (e.g. a touch silently reverting a revoke). Because the
// reload happens under the same flock the write commits under, mutate always
// sees the latest state any other process committed.
//
// mutate receives the freshly loaded storeFile to inspect and mutate in place;
// it returns changed=false to skip the write entirely (no-op mutations:
// already-revoked, rate-limited touch, RevokeAll with nothing active). After a
// successful write update refreshes the in-process cache from disk.
func (s *Store) update(ctx context.Context, mutate func(f *storeFile) (changed bool, err error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.aud.Update(ctx, s.path, recordsPerm, func() ([]byte, error) {
		// Under the cross-process audit flock: read the CURRENT bytes from
		// disk, ignoring the mtime/size cache, so no stale in-memory state can
		// seed a lost update.
		if lerr := s.loadFromDiskLocked(); lerr != nil {
			return nil, lerr
		}
		f := s.file.clone()
		changed, merr := mutate(&f)
		if merr != nil {
			return nil, merr
		}
		if !changed {
			return nil, nil // signal "no change" to Update: no write, no audit entry
		}
		data, merr := json.MarshalIndent(f, "", "  ")
		if merr != nil {
			return nil, fmt.Errorf("device: marshal records file: %w", merr)
		}
		return append(data, '\n'), nil
	})
	if err != nil {
		return err
	}
	// Refresh the in-process cache from the just-written (or unchanged) file so
	// subsequent reads on this Store see the committed state and a fresh
	// fingerprint. A reload failure here is non-fatal: the next read path will
	// retry, and VerifyBearer reloads on its own and fails closed.
	if rerr := s.loadFromDiskLocked(); rerr != nil {
		return fmt.Errorf("device: refresh cache after write %s: %w", s.path, rerr)
	}
	return nil
}

// findActiveIn returns the index of the active (non-revoked) record named name
// within f, or -1.
func findActiveIn(f *storeFile, name string) int {
	for i := range f.Devices {
		if f.Devices[i].Name == name && f.Devices[i].active() {
			return i
		}
	}
	return -1
}

// findActiveLocked returns the index of the active (non-revoked) record named
// name in the in-memory file, or -1. Caller must hold s.mu with the file
// loaded.
func (s *Store) findActiveLocked(name string) int {
	return findActiveIn(&s.file, name)
}

// DefaultPath returns the canonical devices.json location,
// ~/.local/state/abysslink/devices.json, creating the state directory (0700)
// when it does not exist. Both abysslinkd and the CLI resolve the store
// through this single helper so the two sides can never disagree.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("device: resolve home dir: %w", err)
	}
	dir := filepath.Join(home, ".local", "state", "abysslink")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("device: mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, "devices.json"), nil
}
