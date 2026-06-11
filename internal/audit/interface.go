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
	"os"
)

// AuditWriter is the file-mutation contract satisfied by both *Audit (unsigned,
// backward-compatible v1/v2 path) and *SignedAudit (HMAC-chained, tamper-evident
// path introduced in Phase 17). Callers depend on this interface so the concrete
// writer can be swapped via dependency injection (modules.Deps.Audit).
//
// The method intentionally carries NO context.Context parameter. This keeps the
// signature drop-in compatible with the pre-existing *Audit.WriteFile, so no
// caller needs to change when *SignedAudit is injected instead. *SignedAudit's
// implementation uses context.Background() internally (see signed.go) — that is
// explicitly justified because WriteFile is a convenience wrapper over Append,
// not a hot path, and the audit-then-write ordering invariant is enforced inside
// the implementation rather than expressed in the interface.
// "AuditWriter" is the documented public contract across modules.Deps and CLI wiring.
//
//nolint:revive // name mandated by Phase 17 plan (AUD-03 must_haves + grep contract);
type AuditWriter interface {
	// WriteFile records the intended mutation in the audit log (recording only
	// the SHA-256 of content, never the content itself), then writes content to
	// path atomically. When dryRun is true no file is written or backed up:
	// *Audit appends a DryRun-tagged entry (chain-aware — signed when the log
	// carries an active chain, R2-C1), while *SignedAudit records nothing at
	// all (CORE-05 — chain entries would mutate disk/keychain state, which the
	// --dry-run contract forbids).
	WriteFile(path string, content []byte, perm os.FileMode, dryRun bool) error

	// Update performs a lost-update-free, cross-process read-modify-write of
	// path. It acquires the same lock(s) WriteFile uses, then calls content,
	// which MUST read the CURRENT on-disk state of path (fresh, ignoring any
	// in-memory cache) and return the full new file bytes. While the lock is
	// held no other process's audit-backed write to path can interleave, so the
	// read-modify-write content performs cannot lose a concurrent update. The
	// returned bytes are recorded in the audit log and written atomically, all
	// under the held lock. content may return (nil, nil) to signal "no change",
	// in which case nothing is written or recorded; a non-nil error aborts with
	// no write. dryRun has no analogue here — Update is for real mutations only.
	Update(ctx context.Context, path string, perm os.FileMode, content func() ([]byte, error)) error
}

// Compile-time assertions that both writers satisfy AuditWriter.
var (
	_ AuditWriter = (*Audit)(nil)
	_ AuditWriter = (*SignedAudit)(nil)
)
