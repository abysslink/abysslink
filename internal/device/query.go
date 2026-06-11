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
		if subtle.ConstantTimeCompare(sum[:], stored) == 1 && found == nil {
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

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reloadIfChangedLocked(); err != nil {
		return err
	}

	idx := -1
	for i := range s.file.Devices {
		if s.file.Devices[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("device: touch id %q: %w", id, ErrNotFound)
	}
	r := s.file.Devices[idx]
	if r.Revoked {
		return nil
	}
	if !r.LastSeen.IsZero() {
		d := when.Sub(r.LastSeen)
		if d < 0 {
			d = -d
		}
		if d < touchWriteInterval {
			return nil
		}
	}

	f := s.file.clone()
	f.Devices[idx].LastSeen = when.UTC()
	return s.saveLocked(f)
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
