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

package deadman

// timer.go is the daemon-hosted dead-man no-contact timer (SUPL-06). When the
// operator goes silent for the configured interval, the timer fires Lockdown
// once (disarm armed pgids + revoke autonomy + audit) and then stays latched
// until a fresh heartbeat re-arms it.
//
// RESTART-SAFETY (32-CONTEXT.md / T-32-24): the last-contact timestamp is
// PERSISTED to disk through the audit chain, so a daemon restart re-reads the
// persisted contact and computes the remaining time from it — it never resets
// the clock on restart. A missing last-contact file is treated as "now" so a
// freshly-enabled switch starts the clock rather than instantly firing
// (T-32-25 false-trigger guard).
//
// TAMPER-EVIDENCE (T-32-26): the last-contact timestamp is written ONLY through
// the audit writer (Update), never a bare os.WriteFile — a forged timestamp
// that flips the deadline forward to defeat the switch is detectable in the
// tamper-evident chain.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// contactPerm is the permission mode for the last-contact state file. 0600:
// the file records only a single non-secret timestamp, but runtime security
// state is kept owner-only by convention (matches the registry + audit log).
const contactPerm = 0o600

// defaultTickInterval is how often the timer re-reads the persisted last-contact
// and checks the deadline when the caller does not inject a tick. It is well
// below any sane no-contact interval (floor 1h) so the deadline is honoured
// promptly without busy-looping.
const defaultTickInterval = time.Minute

// lastContact is the on-disk shape of the persisted contact timestamp. It
// carries ONLY the timestamp — no operator identity, no secret — so the file is
// safe to audit-write (T-32-26).
type lastContact struct {
	// At is the wall-clock time of the most recent operator contact (heartbeat),
	// or the moment the switch was first enabled. The no-contact deadline is
	// At + interval.
	At time.Time `json:"at"`
}

// AuditUpdater is the subset of internal/audit.Audit the timer needs to PERSIST
// the last-contact timestamp: the cross-process compare-and-swap Update path.
// The timestamp is written ONLY through this interface so every reset is
// recorded in the tamper-evident audit chain (T-32-26) — a hand-edited
// deadman-contact.json that flips the deadline forward is detectable, and the
// write never happens via a bare os.WriteFile.
type AuditUpdater interface {
	Update(ctx context.Context, path string, perm os.FileMode, content func() ([]byte, error)) error
}

// ContactStatePath returns the canonical last-contact state path under
// XDG_STATE_HOME (default ~/.local/state/abysslink/deadman-contact.json),
// mirroring StatePath / audit.DefaultLogPath. It ensures the parent directory
// exists (so the first audit write can land) but does NOT create the file.
func ContactStatePath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("deadman: home dir: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "abysslink")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("deadman: mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, "deadman-contact.json"), nil
}

// Heartbeat records an operator contact by persisting now() as the last-contact
// timestamp through the audit writer (T-32-26: never a bare os.WriteFile). It
// resets the no-contact deadline to now + interval. A heartbeat is the "contact"
// signal that re-arms a latched timer; the `deadman heartbeat` CLI and any
// future phone-ack path call this.
//
// now is injected so tests can advance a fake clock; pass time.Now in
// production.
func Heartbeat(ctx context.Context, contactPath string, aud AuditUpdater, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}
	if aud == nil {
		return errors.New("deadman: heartbeat: nil audit writer")
	}
	return aud.Update(ctx, contactPath, contactPerm, func() ([]byte, error) {
		return marshalContact(lastContact{At: now().UTC()})
	})
}

// SeedContact records the FIRST contact ("enable moment") for the dead-man
// switch when no contact has ever been persisted. It is the fix for the CR-02
// fail-open gap: without a seeded contact, LastContact synthesizes "now" on
// every tick and the no-contact deadline is perpetually reset, so the timer
// NEVER fires for an operator who enables the switch and then walks away. By
// treating ENABLE as the first contact (32-CONTEXT decision), the clock starts
// counting from enable, so a freshly-enabled-then-silent switch fires after the
// interval.
//
// SeedContact is IDEMPOTENT and restart-safe (T-32-24): it reads LastContact
// first and, if a persisted contact already exists (found==true), returns nil
// WITHOUT writing — a redundant call (enable twice, or a daemon restart after
// enable) never resets an in-flight deadline. Only when no contact file exists
// does it write contact=now through the SAME audit-backed Heartbeat path
// (T-32-26: never a bare os.WriteFile).
//
// now is injected for tests; pass time.Now in production.
func SeedContact(ctx context.Context, contactPath string, aud AuditUpdater, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}
	if aud == nil {
		return errors.New("deadman: seed contact: nil audit writer")
	}
	_, found, err := LastContact(contactPath, now)
	if err != nil {
		return fmt.Errorf("deadman: seed contact: read existing %s: %w", contactPath, err)
	}
	if found {
		// An in-flight deadline already exists; preserve it (restart-safety).
		return nil
	}
	// First contact = enable moment: start the clock now, audit-written.
	return Heartbeat(ctx, contactPath, aud, now)
}

// LastContact reads the persisted last-contact timestamp. A MISSING file is NOT
// an error: it returns (now(), false, nil), so a freshly-enabled switch that has
// never recorded a contact treats "now" as the contact moment and starts the
// clock — it never instantly fires (T-32-25). The boolean reports whether a
// persisted timestamp was found (false ⇒ the returned time is the synthesized
// "now", not an on-disk value).
//
// now is injected for tests; pass time.Now in production. The read uses
// os.ReadFile (a read is not a mutation — only writes go through the audit
// writer).
func LastContact(contactPath string, now func() time.Time) (time.Time, bool, error) {
	if now == nil {
		now = time.Now
	}
	raw, err := os.ReadFile(contactPath) //nolint:gosec // G304: contactPath is the internal state path (ContactStatePath/test temp), not user-controlled
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return now().UTC(), false, nil
		}
		return time.Time{}, false, fmt.Errorf("deadman: read contact %s: %w", contactPath, err)
	}
	if len(raw) == 0 {
		return now().UTC(), false, nil
	}
	var lc lastContact
	if uErr := json.Unmarshal(raw, &lc); uErr != nil {
		return time.Time{}, false, fmt.Errorf("deadman: parse contact %s: %w", contactPath, uErr)
	}
	return lc.At, true, nil
}

// TimerOpts carries the dead-man timer dependencies. Tick and Now default to
// production values when zero/nil, so callers supply only what they need.
type TimerOpts struct {
	// Registry is the armed-run registry Lockdown reads pgids from. A nil
	// registry makes Lockdown a no-op on the disarm step (revoke + audit still
	// run) — never a panic.
	Registry *Registry

	// ContactPath is the persisted last-contact state file
	// (ContactStatePath()). REQUIRED: the timer reads the persisted contact off
	// disk on every tick so a restart computes the remaining time from it.
	ContactPath string

	// Interval is the no-contact window before lockdown fires. REQUIRED and must
	// be > 0 (the daemon resolves the 24h default before constructing opts).
	Interval time.Duration

	// SignalFn sends the kill-ladder signals on lockdown. Nil uses
	// DefaultSignalFunc (the production process-group signal).
	SignalFn SignalFunc

	// RevokeAutonomy is the daemon hook that revokes further agent autonomy on
	// lockdown (sets a persisted lockdown flag so further arms / gated execs are
	// refused). Nil defaults to a no-op.
	RevokeAutonomy func() error

	// Audit records the lockdown event (Lockdown's AuditAppender). Required in
	// production; tests inject a recorder.
	Audit AuditAppender

	// KillGrace is the SIGTERM -> SIGKILL grace passed to Lockdown. Zero uses
	// the lockdown default (5s).
	KillGrace time.Duration

	// Tick is how often the loop re-reads the persisted contact and checks the
	// deadline. Zero uses defaultTickInterval (1m). Tests inject a small tick
	// (or drive via a fake clock) to cross the deadline without sleeping the
	// real interval.
	Tick time.Duration

	// Now is the injected clock. Nil uses time.Now. Tests advance a fake clock
	// past the deadline to assert the timer fires without real sleeping.
	Now func() time.Time
}

// StartTimer launches the daemon-hosted dead-man timer goroutine and returns
// immediately, handing back a channel that closes once the goroutine has exited
// (after ctx cancellation) so callers can join on shutdown. The goroutine runs a
// ticker-driven loop: on each tick it reads
// the persisted last-contact timestamp and, if now - lastContact >= interval,
// fires Lockdown EXACTLY ONCE (it latches so it does not re-fire every tick
// after firing). The latch is released only by a FRESH heartbeat — i.e. when
// the persisted contact advances past the moment of the last fire.
//
// The goroutine exits cleanly on ctx cancellation (no leak). StartTimer itself
// never fires; all firing happens on the goroutine's ticks. It is the caller's
// responsibility (the daemon) to only call StartTimer when the switch is
// enabled — a disabled switch must launch no goroutine.
//
// RESTART-SAFETY (T-32-24): because the deadline is computed from the PERSISTED
// last-contact on every tick, a new StartTimer (after a daemon restart) does NOT
// reset the clock — it resumes counting from the persisted contact.
func StartTimer(ctx context.Context, opts TimerOpts) (<-chan struct{}, error) {
	if opts.Interval <= 0 {
		return nil, fmt.Errorf("deadman: StartTimer: interval must be > 0, got %s", opts.Interval)
	}
	if opts.ContactPath == "" {
		return nil, errors.New("deadman: StartTimer: empty contact path")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	tick := opts.Tick
	if tick <= 0 {
		tick = defaultTickInterval
	}

	// done closes once the goroutine has fully exited after ctx cancellation, so
	// callers can JOIN on shutdown: the daemon for clean teardown, and tests to
	// guarantee no registry/audit write is still in flight when t.TempDir is
	// removed. A bare cancel() only signals the goroutine; it does not wait for it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		runTimer(ctx, opts, now, tick)
	}()
	return done, nil
}

// runTimer is the goroutine body. It is separated from StartTimer so the
// validation/defaulting stays out of the hot loop and the loop is independently
// readable. fired latches the single-shot lockdown; it is reset to the
// zero-time sentinel and only re-fires when a heartbeat advances the persisted
// contact past the previous fire's contact.
func runTimer(ctx context.Context, opts TimerOpts, now func() time.Time, tick time.Duration) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	// firedFor records the last-contact timestamp that triggered the most recent
	// fire. While the persisted contact equals firedFor (no fresh heartbeat) the
	// timer stays latched and does not re-fire. A heartbeat moves the persisted
	// contact forward, which differs from firedFor and re-arms the switch.
	var firedFor time.Time
	var latched bool

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			contact, _, err := LastContact(opts.ContactPath, now)
			if err != nil {
				slog.Warn("deadman: timer: read last-contact failed; skipping tick", "err", err)
				continue
			}
			// Re-arm on a fresh heartbeat: the persisted contact advanced past the
			// contact we last fired for.
			if latched && contact.After(firedFor) {
				latched = false
			}
			if latched {
				continue // already fired for this contact; wait for a heartbeat
			}
			if now().UTC().Sub(contact) < opts.Interval {
				continue // T-32-25 false-trigger guard: never fire before the deadline
			}
			// Deadline crossed with no heartbeat: fire Lockdown exactly once.
			fireLockdown(ctx, opts, contact)
			firedFor = contact
			latched = true
		}
	}
}

// fireLockdown invokes Lockdown with the timer's injected dependencies. A
// Lockdown error is logged (the timer never panics) but does NOT clear the
// latch — a failed disarm should not cause a re-fire storm; the next heartbeat
// re-arms cleanly.
func fireLockdown(ctx context.Context, opts TimerOpts, contact time.Time) {
	slog.Warn("deadman: no-contact interval elapsed; firing lockdown",
		"last_contact", contact.Format(time.RFC3339), "interval", opts.Interval)
	err := Lockdown(ctx, LockdownOpts{
		Registry:       opts.Registry,
		SignalFn:       opts.SignalFn,
		RevokeAutonomy: opts.RevokeAutonomy,
		Audit:          opts.Audit,
		Reason:         "no-contact-timeout",
		KillGrace:      opts.KillGrace,
	})
	if err != nil {
		slog.Error("deadman: lockdown returned errors", "err", err)
	}
}

// marshalContact serialises a lastContact to indented JSON for the state file.
func marshalContact(lc lastContact) ([]byte, error) {
	data, err := json.MarshalIndent(lc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("deadman: marshal contact: %w", err)
	}
	return data, nil
}

// lockdownFlag is the on-disk shape of the lockdown flag. It carries only the
// reason + time — no secret — so the file is safe to audit-write.
type lockdownFlag struct {
	// Reason is a short machine reason for the lockdown (e.g.
	// "no-contact-timeout"). It is observable state, never a free-text body.
	Reason string `json:"reason"`
	// At is the time the lockdown flag was set.
	At time.Time `json:"at"`
}

// LockdownFlagPath returns the canonical lockdown-flag path under XDG_STATE_HOME
// (default ~/.local/state/abysslink/deadman-lockdown.json). It ensures the
// parent directory exists but does NOT create the file (its absence means "not
// locked down").
func LockdownFlagPath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("deadman: home dir: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "abysslink")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("deadman: mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, "deadman-lockdown.json"), nil
}

// SetLockdownFlag persists the lockdown flag through the audit writer (never a
// bare os.WriteFile) so a fresh agent cannot simply re-arm after lockdown: the
// arm path consults IsLockedDown and refuses while the flag is set. This is the
// concrete, generic RevokeAutonomy implementation the daemon injects into the
// timer — it sets a persisted flag the arm/gate path reads, deliberately NOT a
// runtime gate.enforcing toggle (D-40). now is injected for tests.
func SetLockdownFlag(ctx context.Context, flagPath string, aud AuditUpdater, reason string, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}
	if aud == nil {
		return errors.New("deadman: set lockdown flag: nil audit writer")
	}
	return aud.Update(ctx, flagPath, contactPerm, func() ([]byte, error) {
		data, err := json.MarshalIndent(lockdownFlag{Reason: reason, At: now().UTC()}, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("deadman: marshal lockdown flag: %w", err)
		}
		return data, nil
	})
}

// IsLockedDown reports whether the lockdown flag is set (the file exists and is
// non-empty). A missing file means "not locked down" (the normal state). It
// reads with os.ReadFile (a read is not a mutation). The arm path calls this to
// refuse arming a fresh agent after a dead-man lockdown.
func IsLockedDown(flagPath string) (bool, string, error) {
	raw, err := os.ReadFile(flagPath) //nolint:gosec // G304: flagPath is the internal state path (LockdownFlagPath/test temp), not user-controlled
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("deadman: read lockdown flag %s: %w", flagPath, err)
	}
	if len(raw) == 0 {
		return false, "", nil
	}
	var lf lockdownFlag
	if uErr := json.Unmarshal(raw, &lf); uErr != nil {
		return false, "", fmt.Errorf("deadman: parse lockdown flag %s: %w", flagPath, uErr)
	}
	return true, lf.Reason, nil
}

// ClearLockdownFlag removes the lockdown flag, re-enabling arming. It is the
// operator's explicit un-lockdown path (e.g. after investigating). Removing a
// missing flag is a no-op (returns nil). The removal itself is a state mutation;
// it is recorded by the caller's audit context where one is available. (The flag
// file carries no secret, so a bare Remove is acceptable for the clear path —
// the security-relevant direction is SETTING the flag, which is audit-written.)
func ClearLockdownFlag(flagPath string) error {
	if err := os.Remove(flagPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("deadman: clear lockdown flag %s: %w", flagPath, err)
	}
	return nil
}
