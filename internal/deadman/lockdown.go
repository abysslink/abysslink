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

// Lockdown is the dead-man switch action. SCOPE (SUPL-06, locked in
// 32-CONTEXT.md): it disarms every registered armed pgid by reusing the Phase
// 31 process-group kill ladder (SIGTERM -> grace -> SIGKILL via
// syscall.Kill(-pgid, sig) — the process-group signal path, never a per-pane
// teardown, KILL-03), revokes further agent autonomy through an injected hook,
// and audit-logs the event. It does NOTHING else.
//
// It deliberately does NOT import or call any SSH-CA, device-credential, or
// network-revocation path — auto-revoking those on a timer is too destructive
// (32-CONTEXT.md). A test (TestLockdownDoesNotTouchSSHCAOrDeviceOrNetwork)
// statically asserts this file's imports contain none of those packages.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"syscall"
	"time"
)

// defaultKillGrace is the SIGTERM -> SIGKILL grace period when LockdownOpts
// leaves KillGrace zero. It mirrors the budget watcher's resolvedKillGrace
// default (5s, D-07).
const defaultKillGrace = 5 * time.Second

// SignalFunc sends sig to the process group identified by pgid (positive). The
// production implementation is DefaultSignalFunc = syscall.Kill(-pgid, sig) —
// the same process-group disarm the budget watcher uses. Injectable so tests
// observe the ladder without signalling a real group.
type SignalFunc func(pgid int, sig syscall.Signal) error

// DefaultSignalFunc is the production signal sender: syscall.Kill(-pgid, sig).
// It mirrors budget.defaultSignalFn exactly — the negative pgid targets the
// whole process group (KILL-03: process-group signal, not a per-pane teardown).
func DefaultSignalFunc(pgid int, sig syscall.Signal) error {
	return syscall.Kill(-pgid, sig) //nolint:gosec // G104: deadman lockdown intentionally signals the armed process group, mirroring internal/budget
}

// AuditAppender records the lockdown event in the tamper-evident audit log. It
// matches *audit.Audit.Append. Only a title + content hash is recorded — never
// a caller-supplied free-text body that might carry secrets.
type AuditAppender interface {
	Append(op, target string, content []byte, dryRun bool) error
}

// LockdownOpts carries the lockdown dependencies. SignalFn and RevokeAutonomy
// default to safe production/no-op values when nil, so a caller that only wants
// disarm + audit can leave them unset.
type LockdownOpts struct {
	// Registry is the armed-run registry to read pgids from. A nil registry is a
	// safe no-op (no panic) — there is simply nothing to disarm.
	Registry *Registry

	// SignalFn sends the kill-ladder signals. Defaults to DefaultSignalFunc.
	SignalFn SignalFunc

	// RevokeAutonomy is the hook that revokes further agent autonomy (e.g. sets a
	// daemon lockdown flag so further arms/gated execs are refused — supplied by
	// Plan 06). Defaults to a no-op so this plan is independently testable.
	RevokeAutonomy func() error

	// Audit records the deadman-lockdown event. Required in production; tests
	// inject a recorder.
	Audit AuditAppender

	// Reason is a short machine reason (e.g. "no-contact-timeout"). It is the
	// audit entry's target — NOT a free-text body — so no secrets leak.
	Reason string

	// KillGrace is the SIGTERM -> SIGKILL grace period. Zero uses
	// defaultKillGrace (5s).
	KillGrace time.Duration
}

// Lockdown disarms every registered armed pgid (SIGTERM -> grace -> SIGKILL via
// the process-group signal func), revokes agent autonomy, and audit-logs the
// event — and nothing else. Every pgid is attempted even if an earlier one
// fails (one failure never strands the rest); the failures are aggregated into
// the returned error. Disarmed pgids are deregistered from the registry.
//
// A nil or empty registry is a safe no-op. A non-positive pgid in the registry
// is skipped and logged (T-32-23: syscall.Kill(-pgid) on a bad pgid would
// signal the wrong group), never signalled.
func Lockdown(ctx context.Context, opts LockdownOpts) error {
	signalFn := opts.SignalFn
	if signalFn == nil {
		signalFn = DefaultSignalFunc
	}
	revoke := opts.RevokeAutonomy
	if revoke == nil {
		revoke = func() error { return nil }
	}
	grace := opts.KillGrace
	if grace <= 0 {
		grace = defaultKillGrace
	}

	var errs []error

	// 1. Disarm every registered armed pgid.
	if opts.Registry != nil {
		runs, err := opts.Registry.List()
		if err != nil {
			errs = append(errs, fmt.Errorf("deadman: lockdown: list registry: %w", err))
		}
		for _, run := range runs {
			if run.PGID <= 0 {
				// T-32-23: never syscall.Kill(-pgid) a non-positive pgid — it
				// would resolve to the wrong process group. Bookkeeping cleanup
				// only: drop the bad entry, never signal it.
				slog.Warn("deadman: lockdown skipping non-positive pgid in registry",
					"pgid", run.PGID, "closure_prefix", closurePrefix(run.ClosureHash))
				if derr := opts.Registry.Deregister(run.PGID); derr != nil {
					errs = append(errs, derr)
				}
				continue
			}
			if derr := disarm(ctx, signalFn, run.PGID, grace); derr != nil {
				errs = append(errs, derr)
			}
			// Deregister regardless: the run is being torn down. A deregister
			// failure is recorded but never strands the remaining pgids.
			if derr := opts.Registry.Deregister(run.PGID); derr != nil {
				errs = append(errs, fmt.Errorf("deadman: lockdown: deregister pgid %d: %w", run.PGID, derr))
			}
		}
	}

	// 2. Revoke further agent autonomy so a fresh agent cannot simply re-arm.
	if rerr := revoke(); rerr != nil {
		errs = append(errs, fmt.Errorf("deadman: lockdown: revoke autonomy: %w", rerr))
	}

	// 3. Audit-log the event (title + reason only — no secrets, no free-text body).
	if opts.Audit != nil {
		// content is the reason bytes; only its sha256 is recorded by Append.
		if aerr := opts.Audit.Append("deadman-lockdown", opts.Reason, []byte(opts.Reason), false); aerr != nil {
			errs = append(errs, fmt.Errorf("deadman: lockdown: audit append: %w", aerr))
		}
	}

	slog.Warn("deadman: lockdown executed", "reason", opts.Reason, "errors", len(errs))

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// disarm runs the SIGTERM -> grace -> SIGKILL ladder against one process group.
// pgid MUST be > 0 (the caller guarantees this). A SIGTERM failure is recorded
// but does NOT skip the SIGKILL — both are attempted so the group is disposed of
// even if the first signal is lost. The grace sleep respects ctx cancellation.
func disarm(ctx context.Context, signalFn SignalFunc, pgid int, grace time.Duration) error {
	var errs []error
	slog.Info("deadman: disarming armed pgid", "pgid", pgid, "grace", grace)

	if err := signalFn(pgid, syscall.SIGTERM); err != nil {
		errs = append(errs, fmt.Errorf("deadman: SIGTERM pgid %d: %w", pgid, err))
	}

	// Grace sleep, interruptible by context cancellation.
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}

	if err := signalFn(pgid, syscall.SIGKILL); err != nil {
		errs = append(errs, fmt.Errorf("deadman: SIGKILL pgid %d: %w", pgid, err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// closurePrefix returns a short, log-safe prefix of a closure hash for
// diagnostics (never the full value in a warning line).
func closurePrefix(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}
