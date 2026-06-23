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

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
)

// deadmanContactPath and deadmanFlagPath are package-var seams so tests can
// redirect the dead-man state files to a temp dir without touching
// XDG_STATE_HOME globally. Production uses the real XDG paths.
var (
	deadmanContactPathFn = deadman.ContactStatePath
)

// newDeadmanCmd builds the `abysslink deadman` command (SUPL-06) with three
// subcommands:
//
//   - enable    — turns the dead-man switch ON in abysslink.yaml (dry-run
//     default; --apply persists). Optional --interval-hours (default 24).
//   - status    — reports whether the switch is enabled, the interval, the
//     persisted last-contact time, and the remaining time. No mutation.
//   - heartbeat — records an operator contact (audit-written), resetting the
//     no-contact deadline.
//
// The command is deliberately GENERIC (no Claude coupling): heartbeat is the
// "contact" signal a phone-ack path could later call, but the command says
// nothing about any specific agent.
func newDeadmanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deadman",
		Short: "Configure the opt-in dead-man switch (no-contact lockdown)",
		Long: `The dead-man switch fires a lockdown (disarm armed agents + revoke
autonomy + audit) after a configurable interval of operator silence. It is
OPT-IN and ships OFF: enable it explicitly, then send a heartbeat (the "contact"
signal) before the no-contact interval elapses to keep it from firing.

The timer is hosted by the daemon (abysslinkd) and is restart-safe — the
last-contact deadline survives a daemon restart.`,
		Example: `  # Turn the switch on (dry-run shows the change; --apply persists)
  abysslink deadman enable --apply
  abysslink deadman enable --interval-hours 12 --apply

  # Reset the no-contact deadline (send a "contact" signal)
  abysslink deadman heartbeat

  # Show the switch state and time remaining until lockdown
  abysslink deadman status`,
	}

	cmd.AddCommand(newDeadmanEnableCmd(), newDeadmanStatusCmd(), newDeadmanHeartbeatCmd())
	return cmd
}

// newDeadmanEnableCmd builds `deadman enable`. Dry-run is the default (CLAUDE.md
// mutating-op rule); --apply persists the config change through the audit-backed
// config.Write.
func newDeadmanEnableCmd() *cobra.Command {
	var intervalHours int
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable the dead-man switch in abysslink.yaml (dry-run by default)",
		Example: `  # Preview the change (dry-run default), then persist with --apply
  abysslink deadman enable
  abysslink deadman enable --apply

  # Use a 12-hour no-contact interval instead of the 24h default
  abysslink deadman enable --interval-hours 12 --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDeadmanEnable(cmd, intervalHours)
		},
	}
	cmd.Flags().IntVar(&intervalHours, "interval-hours", 0,
		"no-contact interval in hours before lockdown fires (0 = 24h default; floor 1h)")
	return cmd
}

// runDeadmanEnable sets Deadman.Enabled=true (and the optional interval) in the
// config and persists it under --apply. Without --apply it prints the resolved
// plan and writes nothing.
func runDeadmanEnable(cmd *cobra.Command, intervalHours int) error {
	p := newPrinter(cmd)
	_, apply, err := resolveApplyFlags(cmd)
	if err != nil {
		return err
	}
	path := resolveConfigPath(cmd)
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load config %s: %w (run `abysslink init` first)", path, err)
	}

	cfg.Deadman.Enabled = true
	if intervalHours != 0 {
		cfg.Deadman.IntervalHours = intervalHours
	}
	// Validate the resulting switch (rejects a sub-floor interval) BEFORE writing,
	// so a bad --interval-hours never reaches disk.
	if vErr := config.Validate(cfg); vErr != nil {
		return vErr
	}
	resolved := cfg.Deadman.ResolvedIntervalHours()

	if !apply {
		printerInfo(p, fmt.Sprintf("[plan] would enable the dead-man switch in %s (no-contact interval: %dh)", path, resolved))
		printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to persist."))
		return nil
	}

	if wErr := config.Write(path, cfg); wErr != nil {
		return fmt.Errorf("write config: %w", wErr)
	}

	// CR-02: treat ENABLE as the first contact so the no-contact clock starts
	// counting from now. Without this seed, LastContact synthesizes "now" on
	// every daemon tick and the timer NEVER fires for an operator who enables
	// the switch and walks away (fail-OPEN). The seed is audit-written
	// (deadman.SeedContact → Heartbeat, T-32-26) and idempotent (a second enable
	// preserves an in-flight deadline). A seed failure must NOT fail the enable —
	// the config is already persisted; the daemon's startDeadmanTimer seeds at
	// the first tick as a backstop.
	if cc, ccErr := loadCmdContext(cmd); ccErr != nil {
		slog.Warn("deadman enable: could not build deps to seed the contact clock; the daemon seeds it at its first tick instead", "err", ccErr)
	} else if deps, depsErr := buildDeps(cmd.Context(), cc); depsErr != nil {
		slog.Warn("deadman enable: could not build deps to seed the contact clock; the daemon seeds it at its first tick instead", "err", depsErr)
	} else if contactPath, pErr := deadmanContactPathFn(); pErr != nil {
		slog.Warn("deadman enable: could not resolve contact state path to seed the clock; the daemon seeds it at its first tick instead", "err", pErr)
	} else if sErr := deadmanSeedContact(cmd.Context(), contactPath, deps.Audit, time.Now); sErr != nil {
		slog.Warn("deadman enable: could not seed the contact clock; the daemon seeds it at its first tick instead", "err", sErr)
	}

	printerInfo(p, fmt.Sprintf("Dead-man switch enabled in %s (no-contact interval: %dh).", path, resolved))
	printerInfo(p, styleMuted.Render("The daemon hosts the timer; send `abysslink deadman heartbeat` to reset the deadline."))
	printerInfo(p, styleMuted.Render("Restart the daemon to pick up the change: abysslink daemon restart --apply"))
	return nil
}

// newDeadmanStatusCmd builds `deadman status` — a read-only report of the switch
// state, interval, persisted last-contact time, and remaining time.
func newDeadmanStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the dead-man switch state and time remaining until lockdown",
		Example: `  # Show enabled state, interval, last contact, and time remaining
  abysslink deadman status`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDeadmanStatus(cmd)
		},
	}
}

// runDeadmanStatus prints the switch state without mutating anything.
func runDeadmanStatus(cmd *cobra.Command) error {
	p := newPrinter(cmd)
	cc, err := loadCmdContext(cmd)
	if err != nil {
		return err
	}
	dm := cc.cfg.Deadman

	if !dm.Enabled {
		p.Printv("enabled", "false")
		printerInfo(p, styleMuted.Render("The dead-man switch is OFF. Enable it with `abysslink deadman enable --apply`."))
		return nil
	}

	interval := time.Duration(dm.ResolvedIntervalHours()) * time.Hour
	contactPath, pErr := deadmanContactPathFn()
	if pErr != nil {
		return fmt.Errorf("resolve contact state path: %w", pErr)
	}
	contact, found, lErr := deadman.LastContact(contactPath, time.Now)
	if lErr != nil {
		return fmt.Errorf("read last contact: %w", lErr)
	}

	p.Printv("enabled", "true")
	p.Printv("interval", interval.String())
	if found {
		p.Printv("last_contact", contact.Format(time.RFC3339))
	} else {
		p.Printv("last_contact", "none (clock starts at first daemon tick)")
	}

	deadline := contact.Add(interval)
	remaining := time.Until(deadline)
	if remaining < 0 {
		remaining = 0
	}
	p.Printv("remaining", remaining.Round(time.Second).String())
	if remaining == 0 {
		printerInfo(p, styleWarn.Render("No-contact deadline has elapsed — lockdown will fire on the next daemon tick."))
	}
	return nil
}

// newDeadmanHeartbeatCmd builds `deadman heartbeat` — the "contact" signal that
// resets the no-contact deadline. The reset is audit-written.
func newDeadmanHeartbeatCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "heartbeat",
		Short: "Record an operator contact, resetting the no-contact deadline",
		Example: `  # Send a contact signal so the no-contact timer does not fire
  abysslink deadman heartbeat`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDeadmanHeartbeat(cmd)
		},
	}
}

// runDeadmanHeartbeat writes the last-contact timestamp through the audit-backed
// writer (T-32-26), resetting the deadline. A heartbeat is the contact signal;
// it is always a real mutation (no dry-run) — recording a contact is the
// operator's explicit intent and is itself audit-logged.
func runDeadmanHeartbeat(cmd *cobra.Command) error {
	p := newPrinter(cmd)
	ctx := cmd.Context()
	cc, err := loadCmdContext(cmd)
	if err != nil {
		return err
	}
	deps, err := buildDeps(ctx, cc)
	if err != nil {
		return fmt.Errorf("deadman heartbeat: %w", err)
	}

	contactPath, pErr := deadmanContactPathFn()
	if pErr != nil {
		return fmt.Errorf("resolve contact state path: %w", pErr)
	}

	// deps.Audit is audit.AuditWriter (WriteFile + Update); deadman.Heartbeat
	// needs only Update, so the interface satisfies it directly.
	if hErr := deadmanHeartbeat(ctx, contactPath, deps.Audit, time.Now); hErr != nil {
		return fmt.Errorf("record heartbeat: %w", hErr)
	}

	interval := time.Duration(cc.cfg.Deadman.ResolvedIntervalHours()) * time.Hour
	printerInfo(p, "Heartbeat recorded — no-contact deadline reset.")
	if cc.cfg.Deadman.Enabled {
		p.Printv("remaining", interval.Round(time.Second).String())
	} else {
		printerInfo(p, styleMuted.Render("Note: the dead-man switch is currently OFF; enable it with `abysslink deadman enable --apply`."))
	}
	return nil
}

// deadmanHeartbeat is a thin seam over deadman.Heartbeat so the heartbeat write
// is invoked through a single typed function (and the audit writer type is
// pinned to the AuditUpdater interface deadman expects).
func deadmanHeartbeat(ctx context.Context, contactPath string, aud deadman.AuditUpdater, now func() time.Time) error {
	return deadman.Heartbeat(ctx, contactPath, aud, now)
}

// deadmanSeedContact is a thin seam over deadman.SeedContact so the enable-time
// "first contact = enable moment" seed is invoked through a single typed
// function (pinning the audit-writer type to deadman.AuditUpdater). It is
// idempotent: a second enable preserves an in-flight deadline.
func deadmanSeedContact(ctx context.Context, contactPath string, aud deadman.AuditUpdater, now func() time.Time) error {
	return deadman.SeedContact(ctx, contactPath, aud, now)
}
