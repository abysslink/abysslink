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

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
	"github.com/abysslink/abysslink/internal/modules/sentinel"
)

// buildSentinelEngine constructs the compromised-agent detector engine from
// cfg. It returns nil when the detector is disabled (the decorator then becomes
// a pure pass-through). When enabled it wires the hash-only audit appender
// (always-on Tier 0) and, only behind cfg.Sentinel.Quarantine, a reversible
// dead-man lockdown closure (Tier 1). Every wiring step is fail-soft: a missing
// path degrades the affected tier and logs, never panics the daemon.
func buildSentinelEngine(ctx context.Context, cfg *config.Config) *sentinel.Engine {
	if !cfg.Sentinel.Enabled {
		return nil
	}

	econf := sentinel.Config{
		Enabled:             true,
		Quarantine:          cfg.Sentinel.Quarantine,
		WindowExecs:         cfg.Sentinel.WindowExecs,
		WindowSeconds:       cfg.Sentinel.WindowSeconds,
		ExtraSensitivePaths: cfg.Sentinel.ExtraSensitivePaths,
		ExtraAllowlist:      cfg.Sentinel.EgressAllowlist,
	}

	opts := []sentinel.Option{}

	// Tier 0 audit appender. audit.New probes the platform keychain lazily when
	// the chain is active (nil under `go test`), so we do not need kc here — this
	// also breaks the kc<-gated<-sentinel construction cycle.
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		slog.Warn("abysslinkd: sentinel: audit log path unavailable; detections will not be recorded to the audit log", "err", err)
	} else {
		opts = append(opts, sentinel.WithAudit(audit.New(logPath)))
	}

	// Tier 1 quarantine (opt-in). Reuse deadman.Lockdown wholesale (disarm armed
	// pgids via the SIGTERM->grace->SIGKILL ladder + latch the lockdown flag);
	// never hand-roll a kill ladder. Non-destructive and reversible — Lockdown
	// deliberately does not touch SSH-CA / device-cred / network.
	if cfg.Sentinel.Quarantine {
		if q := buildSentinelQuarantine(ctx, logPath, err); q != nil {
			opts = append(opts, sentinel.WithQuarantine(q))
		} else {
			slog.Warn("abysslinkd: sentinel: quarantine requested but could not be wired; degrading to flag+audit only")
		}
	}

	return sentinel.NewEngine(econf, opts...)
}

// buildSentinelQuarantine builds the reversible-lockdown closure, or nil when
// its dependencies (audit log path, registry state, lockdown flag) are
// unavailable. logErr is the earlier DefaultLogPath error, if any.
func buildSentinelQuarantine(ctx context.Context, logPath string, logErr error) sentinel.QuarantineFunc {
	if logErr != nil {
		return nil
	}
	aud := audit.New(logPath)

	statePath, err := deadman.StatePath()
	if err != nil {
		slog.Warn("abysslinkd: sentinel: registry state path unavailable; quarantine disabled", "err", err)
		return nil
	}
	flagPath, err := deadman.LockdownFlagPath()
	if err != nil {
		slog.Warn("abysslinkd: sentinel: lockdown flag path unavailable; quarantine disabled", "err", err)
		return nil
	}
	reg := deadman.New(statePath, aud)

	return func(qctx context.Context, reason string) error {
		return deadman.Lockdown(qctx, deadman.LockdownOpts{
			Registry: reg,
			// RevokeAutonomy latches the lockdown flag so arm_cmd's preflight
			// fail-closes further arming until it is explicitly cleared.
			RevokeAutonomy: func() error {
				return deadman.SetLockdownFlag(ctx, flagPath, aud, reason, time.Now)
			},
			Audit:  aud,
			Reason: reason,
		})
	}
}
