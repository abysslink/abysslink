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

package duress

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
	"github.com/abysslink/abysslink/internal/secrets"
)

// Mode is the outcome of resolving a presented credential against the stored
// real/decoy digests.
type Mode int

const (
	// ModeNone means the presented credential matched neither slot — the normal
	// authentication failure. A load/lookup failure ALSO resolves to ModeNone
	// (fail closed): a degraded keychain never resolves to the real view.
	ModeNone Mode = iota
	// ModeReal means the presented credential matched the real slot: show the
	// real rig view, degrade nothing.
	ModeReal
	// ModeDecoy means the presented credential matched the decoy slot: show the
	// benign rig view AND trigger the real (reversible) kill-switch degradation.
	ModeDecoy
)

// Keychain coordinates for the stored credential digests. service is the
// codebase-wide "abysslink" service; the accounts are non-secret selectors.
// Only argon2id PHC DIGESTS are stored — never a plaintext credential.
const (
	// KeychainService is the composite-key service for the credential digests.
	KeychainService = "abysslink"
	// RealAccount stores the argon2id digest of the REAL unlock credential.
	RealAccount = "duress-real"
	// DecoyAccount stores the argon2id digest of the DECOY credential.
	DecoyAccount = "duress-decoy" //nolint:gosec // G101: keychain account selector, not a credential
)

// argon2id parameters (x/crypto recommended interactive params, mirroring
// internal/modules/codeserver). A duress passphrase is low-entropy and the
// digest is at rest in a keychain a disk-imaging adversary could read, so a
// slow, salted KDF is used rather than a bare SHA-256.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32 // fixed digest width — neutralises the length side-channel
	argonSaltLen = 16
)

// degradeReason is the GENERIC machine reason recorded for a duress-triggered
// degradation. It says nothing about a decoy credential — the audit trail and
// the persisted latch never reveal decoy-vs-real (DUR-03: no credential body,
// no decoy discriminator).
//
// It is NOT disguised as the routine dead-man reason ("no-contact-timeout").
// Recording a duress event as a timeout would be a lie in the operator's own
// audit log, so we tell the truth: this reason is duress-specific. The honest
// consequence — a FORENSIC reader with the on-disk latch can tell a duress
// activation from a routine timeout — is out of scope by design (the decoy
// defends against CASUAL coercion, never a forensic adversary; see the
// threat-model doc) and is disclosed there, not hidden here.
const degradeReason = "session-degraded"

// auditOpSessionDegraded is the generic audit category for a duress activation.
// It carries no decoy-vs-real discriminator and no credential body.
const auditOpSessionDegraded = "session-degraded"

// HashCredential derives a fresh, salted argon2id PHC digest of presented. The
// output is a single-line string safe to store in the keychain (the real
// backends reject newlines). The plaintext is never returned or stored.
func HashCredential(presented string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("duress: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(presented), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// digestMatches reports whether the argon2id PHC digest matches presented. The
// compare runs over fixed 32-byte digests with crypto/subtle (constant-time,
// no length leak). ok is false when the stored PHC cannot be parsed (the slot
// is skipped, exactly like a len-guard failure in device.VerifyBearer).
func digestMatches(phc, presented string) (match, ok bool) {
	parts := strings.Split(phc, "$")
	// "" / "argon2id" / "v=19" / "m=…,t=…,p=…" / salt / digest
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false
	}
	var mem, t uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &threads); err != nil {
		return false, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != argonKeyLen {
		// GUARD the digest width before the constant-time compare — an
		// unequal-length compare returns 0 and would mask a bug.
		return false, false
	}
	got := argon2.IDKey([]byte(presented), salt, t, mem, threads, uint32(len(want))) // #nosec G115 -- len(want) == argonKeyLen (32), bounded above
	return subtle.ConstantTimeCompare(got, want) == 1, true
}

// credSlot pairs a candidate mode with its stored PHC digest.
type credSlot struct {
	mode Mode
	phc  string
}

// Resolve compares presented against the stored real and decoy digests and
// returns the matching Mode. It:
//
//   - reduces presented to a fixed 32-byte argon2id digest per slot before the
//     constant-time compare, so neither the credential length nor its content
//     leaks through timing;
//   - iterates EVERY configured slot with no `&&` short-circuit and no early
//     return, recording only the first match, so timing never reveals WHICH
//     slot matched (mirrors device.VerifyBearer / device/query.go:47-63); and
//   - fails CLOSED: a disabled feature, a non-keychain secret source, a nil
//     store, or any keychain error resolves to ModeNone (never to ModeReal).
func Resolve(ctx context.Context, presented string, cfg config.DuressConfig, store secrets.KeychainStore) Mode {
	if !cfg.Enabled || cfg.ResolvedSecretSource() != config.DuressSecretSourceKeychain || store == nil {
		return ModeNone
	}

	slots := make([]credSlot, 0, 2)
	for _, s := range []struct {
		mode    Mode
		account string
	}{
		{ModeReal, RealAccount},
		{ModeDecoy, DecoyAccount},
	} {
		phc, err := store.Get(ctx, KeychainService, s.account)
		if err != nil {
			if errors.Is(err, secrets.ErrNotFound) {
				continue // this slot is simply not enrolled
			}
			// Keychain unavailable / locked / transient: fail CLOSED for the whole
			// resolution rather than partially resolving against a degraded store.
			slog.Warn("duress: keychain lookup failed; failing closed to no-match", "account", s.account, "err", err)
			return ModeNone
		}
		slots = append(slots, credSlot{mode: s.mode, phc: phc})
	}

	found := ModeNone
	for _, sl := range slots {
		match, ok := digestMatches(sl.phc, presented)
		// No short-circuit: compute every slot, record only the first match.
		if ok && match && found == ModeNone {
			found = sl.mode
		}
	}
	return found
}

// RigView is the machine-state summary the unlock command renders. The SAME
// view type and renderer are used for the real and the decoy path, so a benign
// (idle-machine) real view and a decoy view are byte-for-byte indistinguishable
// (DUR-02). The decoy view carries zero fleet / sessions / armed agents.
type RigView struct {
	// Hostname is the machine name shown to the operator.
	Hostname string
	// Fleet is the number of enrolled rigs.
	Fleet int
	// Sessions is the number of active remote sessions.
	Sessions int
	// Armed is the number of armed (autonomous) agents.
	Armed int
}

// defaultDecoyHostname is the benign hostname shown when decoy.hostname is
// unset. Generic on purpose — it must not hint that a real fleet exists.
const defaultDecoyHostname = "workstation"

// DecoyRigView builds the benign view shown on a decoy unlock. It is pure
// substitution: a quiet machine with no fleet, no sessions, no armed agents.
func DecoyRigView(dc config.DecoyConfig) RigView {
	host := dc.Hostname
	if host == "" {
		host = defaultDecoyHostname
	}
	return RigView{Hostname: host, Fleet: 0, Sessions: 0, Armed: 0}
}

// AuditAppender records a duress activation. It matches *audit.Audit.Append —
// only a title + content hash is recorded, never a credential body.
type AuditAppender interface {
	Append(op, target string, content []byte, dryRun bool) error
}

// TriggerOpts carries the dependencies for a duress-triggered degradation. All
// are nil-safe: a CLI invocation with no daemon-owned registry can still set
// the persisted latch (stopping future arms) even though it cannot signal live
// pgids it does not know about.
type TriggerOpts struct {
	// Registry is the armed-run registry whose pgids are frozen/killed. A nil
	// registry is a safe no-op (nothing live to disarm).
	Registry *deadman.Registry
	// FlagPath is the persisted lockdown-latch path (deadman.LockdownFlagPath).
	FlagPath string
	// LockdownUpdater audit-writes the lockdown latch (deadman.SetLockdownFlag).
	LockdownUpdater deadman.AuditUpdater
	// Audit records the single generic activation entry. Optional.
	Audit AuditAppender
	// SignalFn sends the kill-ladder signals. Nil uses deadman.DefaultSignalFunc
	// (syscall.Kill(-pgid, sig)); tests inject a recorder so no real process
	// group is signalled.
	SignalFn deadman.SignalFunc
	// KillGrace is the SIGTERM -> SIGKILL grace period; zero uses the deadman
	// default (5s).
	KillGrace time.Duration
	// Now is injected for tests; nil uses time.Now.
	Now func() time.Time
}

// Trigger performs the REAL, reversible kill-switch degradation of the session
// when the decoy credential is entered (DUR-02). It:
//
//  1. drives deadman.Lockdown — the SAME degradation seam the dead-man switch
//     fires: it disarms (SIGTERM -> grace -> SIGKILL) every registered armed
//     pgid and sets the persisted lockdown latch so a fresh agent cannot
//     silently re-arm behind the decoy; and
//  2. appends ONE generic, hash-only audit entry (op=session-degraded) that
//     records THAT the session was degraded, never WHICH credential triggered
//     it (DUR-03).
//
// It is NON-DESTRUCTIVE: no device credential, SSH-CA, network state, or file
// is deleted or overwritten. The degradation is reversible (an operator clears
// the latch with the existing lockdown-clear path). Errors are aggregated and
// returned; the audit is best-effort and never loosens the degradation.
func Trigger(ctx context.Context, opts TriggerOpts) error {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	var errs []error

	// 1. Freeze/kill armed pgids + latch the lockdown so nothing re-arms.
	lderr := deadman.Lockdown(ctx, deadman.LockdownOpts{
		Registry: opts.Registry,
		SignalFn: opts.SignalFn,
		RevokeAutonomy: func() error {
			if opts.LockdownUpdater == nil || opts.FlagPath == "" {
				return nil // CLI-with-no-daemon: nothing to latch through
			}
			return deadman.SetLockdownFlag(ctx, opts.FlagPath, opts.LockdownUpdater, degradeReason, now)
		},
		// Audit is emitted generically below (not via Lockdown's own "deadman-
		// lockdown" op) so the entry carries the neutral session-degraded op.
		Audit:     nil,
		Reason:    degradeReason,
		KillGrace: opts.KillGrace,
	})
	if lderr != nil {
		errs = append(errs, fmt.Errorf("duress: lockdown: %w", lderr))
	}

	// 2. One generic, hash-only activation entry. content is nil — nothing about
	//    the credential (or that it was a decoy) is recorded.
	if opts.Audit != nil {
		if aerr := opts.Audit.Append(auditOpSessionDegraded, "session", nil, false); aerr != nil {
			errs = append(errs, fmt.Errorf("duress: audit append: %w", aerr))
		}
	}

	slog.Warn("duress: session degraded via kill-switch", "errors", len(errs))
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
