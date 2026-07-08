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

package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"

	"github.com/awnumar/memguard"
)

// SecureBytes holds an in-memory secret in a memguard LockedBuffer: the memory
// is mlock'd (excluded from swap where the OS honours it) and zeroized on free
// (MEM-01). It is DEFENSE IN DEPTH ONLY — never a guarantee. The honest bounds:
//
//   - Go's garbage collector moves and copies runtime-managed memory, so any
//     plain []byte or string the secret passed through BEFORE entering the
//     LockedBuffer (keychain client return values, YAML decode buffers, the
//     shell.Runner stdout string) is not protected. We narrow the window, we
//     do not close it — so we never claim "secrets never hit disk".
//   - Locking is capped by RLIMIT_MEMLOCK; containers often ship a tiny memlock
//     limit. When the kernel refuses the lock, SecureBytes surfaces an honest
//     WARN once and falls back to a plain zeroizable buffer (MEM-01: never a
//     silent no-op), and Locked() reports false so a doctor check can see it.
//
// A SecureBytes is safe for concurrent Bytes()/Fingerprint() reads; Destroy is
// idempotent. The zero value is not usable — construct via NewSecureBytes.
type SecureBytes struct {
	mu     sync.Mutex
	buf    *memguard.LockedBuffer // nil after Destroy or when locking failed
	plain  []byte                 // fallback storage when mlock is unavailable
	locked bool
}

// mlockWarnOnce ensures the "could not mlock" WARN is emitted at most once per
// process rather than on every secret — the operator needs to know the posture,
// not a flood.
var mlockWarnOnce sync.Once

// NewSecureBytes copies b into locked memory and WIPES the caller's slice (b is
// zeroized before return, so the caller must not reuse it). When mlock fails
// (RLIMIT_MEMLOCK, unsupported platform) it falls back to a plain buffer and
// logs one honest WARN. b may be empty; the result is then a valid empty
// SecureBytes.
func NewSecureBytes(b []byte) *SecureBytes {
	sb := &SecureBytes{}
	// NewBufferFromBytes moves the bytes into locked memory and wipes the
	// source slice. It does not error; a lock failure surfaces via the global
	// panic handler in memguard, so we guard defensively and fall back.
	sb.buf = newLockedBufferOrFallback(sb, b)
	return sb
}

// newLockedBufferOrFallback attempts to build a LockedBuffer; on any failure it
// records the plain fallback on sb and returns nil. Isolated so the recover()
// is tightly scoped.
func newLockedBufferOrFallback(sb *SecureBytes, b []byte) (buf *memguard.LockedBuffer) {
	defer func() {
		if r := recover(); r != nil {
			// mlock refused (RLIMIT_MEMLOCK) or platform unsupported: honest
			// WARN once, plain zeroizable fallback (MEM-01 — never silent).
			mlockWarnOnce.Do(func() {
				slog.Warn("secrets: could not lock secret memory (mlock unavailable); using an unlocked, zeroized-on-free fallback — defense-in-depth reduced. Raise RLIMIT_MEMLOCK (ulimit -l) to enable locking.",
					"err", r)
			})
			plain := make([]byte, len(b))
			copy(plain, b)
			wipe(b)
			sb.plain = plain
			sb.locked = false
			buf = nil
		}
	}()
	if len(b) == 0 {
		buf = memguard.NewBuffer(0)
	} else {
		buf = memguard.NewBufferFromBytes(b)
	}
	sb.locked = true
	return buf
}

// Bytes returns the secret bytes for immediate use. The returned slice aliases
// locked memory and MUST NOT be retained past the immediate operation, copied,
// or mutated. Returns nil after Destroy.
func (s *SecureBytes) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf != nil {
		return s.buf.Bytes()
	}
	return s.plain
}

// Fingerprint returns the hex SHA-256 of the secret — safe to log/print (used
// by rotation output). Returns "" after Destroy.
func (s *SecureBytes) Fingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bytesLocked()
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *SecureBytes) bytesLocked() []byte {
	if s.buf != nil {
		return s.buf.Bytes()
	}
	return s.plain
}

// Locked reports whether the secret is held in mlock'd memory (true) or the
// unlocked fallback (false). Surfaced by the sec-mlock doctor check.
func (s *SecureBytes) Locked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked
}

// Destroy zeroizes and frees the secret. Idempotent; the SecureBytes is unusable
// afterwards (Bytes returns nil).
func (s *SecureBytes) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf != nil {
		s.buf.Destroy()
		s.buf = nil
	}
	if s.plain != nil {
		wipe(s.plain)
		s.plain = nil
	}
	s.locked = false
}

// wipe overwrites b with zeros. Best-effort (the GC may already have copied it).
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// MlockAvailable probes whether this process can lock secret memory, so a
// doctor check can report the posture without holding a real secret. It locks
// and immediately frees a one-byte buffer; a lock failure is reported as false
// with no secret exposure.
func MlockAvailable() (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	buf := memguard.NewBuffer(1)
	buf.Destroy()
	return true
}
