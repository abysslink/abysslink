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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
)

// VerifyBearer checks a presented bearer credential against every active
// (non-revoked) record and returns a copy of the matching record. It is the
// daemon's hot path: the records file is re-loaded when its mtime/size
// changed since the last load, so an out-of-process revocation takes effect
// without a restart. The presented value is hashed first and the digests are
// compared with crypto/subtle constant-time comparison; the loop never exits
// early, so timing does not reveal which (if any) record matched. A reload
// failure fails closed (no record is verified against stale state).
func (s *Store) VerifyBearer(presented string) (*Record, bool) {
	sum := sha256.Sum256([]byte(presented))

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		slog.Warn("device: reload before VerifyBearer failed; failing closed", "err", err)
		return nil, false
	}

	var found *Record
	for i := range s.file.Devices {
		r := &s.file.Devices[i]
		if !r.active() || r.BearerSHA256 == "" {
			continue
		}
		stored, err := hex.DecodeString(r.BearerSHA256)
		if err != nil || len(stored) != sha256.Size {
			continue
		}
		// Run the compare on every candidate (no && short-circuit) so the
		// per-iteration work does not change once a match is found; only the
		// first match is recorded.
		match := subtle.ConstantTimeCompare(sum[:], stored) == 1
		if match && found == nil {
			found = r
		}
	}
	if found == nil {
		return nil, false
	}
	cp := *found
	return &cp, true
}

// TouchLastSeen records a device check-in (the daemon calls this on every
// fetch/ack). File writes are rate-limited: when the stored LastSeen is
// already within 60 seconds of when, the call is a no-op so the hot path does
// not rewrite the file on every poll. Touching a revoked device is a silent
// no-op; an unknown id returns ErrNotFound.
func (s *Store) TouchLastSeen(ctx context.Context, id string, when time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Fast-path rate limit: if the in-memory cache already shows LastSeen fresh
	// (within touchWriteInterval) we can skip the whole locked read-modify-write
	// — but only after a freshness reload so we never short-circuit on stale
	// cache. The cache reload is cheap (mtime/size check); the cross-process
	// flock is taken only when a write is actually warranted.
	s.mu.Lock()
	if err := s.reloadIfChangedLocked(); err == nil {
		if idx := indexByID(&s.file, id); idx >= 0 {
			r := s.file.Devices[idx]
			if r.Revoked || lastSeenFresh(r.LastSeen, when) {
				s.mu.Unlock()
				return nil
			}
		}
	}
	s.mu.Unlock()

	// A write looks warranted. Take the cross-process flock and re-evaluate
	// against the CURRENT on-disk state inside update: a concurrent process may
	// have revoked the device or already bumped LastSeen between the fast-path
	// check and acquiring the lock. The authoritative checks (revoked? fresh?)
	// run on the freshly loaded file, so a touch can never resurrect a device
	// another process just revoked, and never clobber that revocation.
	return s.update(ctx, func(f *storeFile) (bool, error) {
		idx := indexByID(f, id)
		if idx < 0 {
			return false, fmt.Errorf("device: touch id %q: %w", id, ErrNotFound)
		}
		r := &f.Devices[idx]
		if r.Revoked {
			return false, nil // revoked under us: do not write (would revert nothing, but also nothing to do)
		}
		if lastSeenFresh(r.LastSeen, when) {
			return false, nil // another process already bumped it within the window
		}
		r.LastSeen = when.UTC()
		return true, nil
	})
}

// indexByID returns the index of the record with the given ID in f, or -1.
func indexByID(f *storeFile, id string) int {
	for i := range f.Devices {
		if f.Devices[i].ID == id {
			return i
		}
	}
	return -1
}

// lastSeenFresh reports whether a stored LastSeen is within touchWriteInterval
// of when (so a persisted update would be redundant). A zero LastSeen is never
// fresh — the first check-in always writes.
func lastSeenFresh(lastSeen, when time.Time) bool {
	if lastSeen.IsZero() {
		return false
	}
	d := when.Sub(lastSeen)
	if d < 0 {
		d = -d
	}
	return d < touchWriteInterval
}

// List returns a copy of every record, active and revoked. When a freshness
// reload fails it serves the last-loaded state (read paths degrade open;
// only VerifyBearer fails closed).
func (s *Store) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		slog.Warn("device: reload before List failed; serving cached state", "err", err)
	}
	return append([]Record(nil), s.file.Devices...)
}

// Get returns a copy of the record named name, preferring the active record
// when both an active and revoked record carry the name; with only revoked
// matches it returns the most recently enrolled one.
func (s *Store) Get(name string) (*Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		slog.Warn("device: reload before Get failed; serving cached state", "err", err)
	}

	var revoked *Record
	for i := range s.file.Devices {
		r := &s.file.Devices[i]
		if r.Name != name {
			continue
		}
		if r.active() {
			cp := *r
			return &cp, true
		}
		revoked = r // records append in enrollment order; keep the latest
	}
	if revoked == nil {
		return nil, false
	}
	cp := *revoked
	return &cp, true
}

// Stale returns copies of every active device that has gone quiet (DEVC-04):
// never seen and enrolled longer than window ago, or last seen longer than
// window ago. Revoked devices are never stale.
func (s *Store) Stale(window time.Duration) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		slog.Warn("device: reload before Stale failed; serving cached state", "err", err)
	}

	now := s.now()
	var out []Record
	for i := range s.file.Devices {
		if s.file.Devices[i].staleAt(now, window) {
			out = append(out, s.file.Devices[i])
		}
	}
	return out
}
