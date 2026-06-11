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

	data, err := os.ReadFile(s.path)
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
	s.lastMod = fi.ModTime()
	s.lastSize = fi.Size()
	s.lastInfo = fi
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

// findActiveLocked returns the index of the active (non-revoked) record named
// name, or -1. Caller must hold s.mu with the file loaded.
func (s *Store) findActiveLocked(name string) int {
	for i := range s.file.Devices {
		if s.file.Devices[i].Name == name && s.file.Devices[i].active() {
			return i
		}
	}
	return -1
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
