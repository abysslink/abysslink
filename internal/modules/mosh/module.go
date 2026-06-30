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

package mosh

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// mosh's default UDP datagram port range. mosh-server picks one port in this
// range per session; the host firewall must allow inbound UDP across it.
const (
	moshUDPLow  = 60000
	moshUDPHigh = 61000
)

// Module implements the mosh module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	plat   platform.Platform
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, plat: d.Platform}
}

// Name returns the module name.
func (m *Module) Name() string { return "mosh" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect checks whether mosh-server is installed.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.moshInstalled(ctx) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: modules.SeverityWarning,
			Message:  "mosh-server is not installed or not on PATH",
		})
	}

	return findings, nil
}

// moshInstalled reports whether mosh-server is installed. Some versions print
// their version to stderr and exit non-zero, so both streams are checked.
func (m *Module) moshInstalled(ctx context.Context) bool {
	res, err := m.runner.Run(ctx, "mosh-server", "--version")
	if err == nil && res.ExitCode == 0 {
		slog.Debug("mosh-server detected", "output", strings.TrimSpace(res.Stdout+res.Stderr))
		return true
	}
	return strings.Contains(strings.ToLower(res.Stdout+res.Stderr), "mosh")
}

// reachabilityFindings reports host-level gaps that let mosh-server install and
// run yet still fail at connect: not on the non-login PATH (macOS), or blocked
// by the host firewall (macOS app-block / Linux closed UDP range). All probes
// are read-only and best-effort — a probe that errors is skipped, never fatal.
func (m *Module) reachabilityFindings(ctx context.Context) []modules.Finding {
	if m.plat == nil {
		return nil
	}
	var findings []modules.Finding

	// PATH (macOS): mosh-server not resolvable on the non-login base PATH.
	if pl, ok := m.plat.(platform.PathLinker); ok {
		if onPath, err := pl.IsOnSystemPath(ctx, "mosh-server"); err == nil && !onPath {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "mosh_path",
				Severity: modules.SeverityWarning,
				Message:  `mosh-server is not on the system PATH used by non-login SSH shells; mosh over Tailscale SSH will fail with "No response from Mosh server"`,
			})
		}
	}

	// Firewall: only blocks while active.
	fw := m.plat.Firewall()
	if status, _ := fw.Status(ctx); status != "enabled" {
		return findings
	}
	if af, ok := fw.(platform.AppFirewall); ok {
		if serverPath, err := m.moshServerPath(ctx); err == nil {
			if allowed, err := af.IsAppAllowed(ctx, serverPath); err == nil && !allowed {
				findings = append(findings, modules.Finding{
					Module:   m.Name(),
					Check:    "mosh_firewall",
					Severity: modules.SeverityWarning,
					Message:  "mosh-server is not allowed through the macOS Application Firewall; incoming mosh UDP is dropped",
				})
			}
		}
	}
	if rf, ok := fw.(platform.RangeFirewall); ok {
		if allowed, err := rf.IsPortRangeAllowed(ctx, moshUDPLow, moshUDPHigh, "udp"); err == nil && !allowed {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "mosh_firewall",
				Severity: modules.SeverityWarning,
				Message:  "udp 60000-61000 is not open in the host firewall; incoming mosh UDP is dropped",
			})
		}
	}

	return findings
}

// Plan computes actions needed. It must reflect every mutation Apply will make,
// because the runner invokes Apply ONLY when Plan returns ≥1 action (so apply
// never exceeds the dry-run preview). Critically, that includes reachability
// work on an ALREADY-INSTALLED mosh: linking mosh-server onto the non-login PATH
// and allowing it through the firewall. Omitting these would skip Apply on every
// already-installed machine — exactly the host where mosh fails at connect with
// "No response from Mosh server". All probes here are read-only (dry-run safe).
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Mosh.Enabled {
		return nil, nil
	}

	if !m.moshInstalled(ctx) {
		// A fresh install is never on the non-login PATH and not yet firewall-
		// allowed; Apply installs and then runs the same reachability steps.
		return []modules.Action{{
			Module:      m.Name(),
			Description: "install mosh and make mosh-server reachable (PATH + firewall)",
			Reversible:  false,
		}}, nil
	}

	// Installed — surface reachability gaps so the runner calls Apply to close
	// them. Reuses the same read-only probes Verify reports to the user.
	if len(m.reachabilityFindings(ctx)) > 0 {
		return []modules.Action{{
			Module:      m.Name(),
			Description: "make mosh-server reachable: link onto PATH and allow through firewall",
			Reversible:  false,
		}}, nil
	}

	return nil, nil
}

// Apply executes planned changes.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Mosh.Enabled {
		return nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return fmt.Errorf("mosh apply: detect: %w", err)
	}

	for _, f := range findings {
		if f.Check != "installed" {
			continue
		}
		slog.Info("mosh apply: installing mosh-server")
		if err := m.plat.InstallPackage(ctx, "mosh"); err != nil {
			return fmt.Errorf("mosh apply: install mosh: %w", err)
		}
	}

	// mosh "works on paper" once installed (ACL grants the UDP range), but two
	// host-level gaps make it fail at connect time with "No response from Mosh
	// server" — and they are platform-specific. ensureReachable closes both via
	// optional platform capabilities, so this module stays OS-agnostic.
	if err := m.ensureReachable(ctx); err != nil {
		return fmt.Errorf("mosh apply: make mosh-server reachable: %w", err)
	}

	return nil
}

// ensureReachable makes mosh-server reachable for the non-login remote shell
// Tailscale SSH uses. Two gaps, addressed via optional platform capabilities so
// the module carries no OS-specific code:
//
//  1. PATH (macOS): Homebrew's bin dir is absent from the non-login base PATH,
//     so mosh-server is "not found" and never announces. PathLinker symlinks it
//     onto /usr/local/bin. Linux installs onto PATH already → no PathLinker.
//
//  2. Firewall: the macOS Application Firewall blocks the unsigned mosh-server
//     binary's first incoming UDP (AppFirewall.AllowApp); a Linux host firewall
//     drops the UDP range unless opened (RangeFirewall.AllowPortRange).
//
// Each step is check-then-act: it queries current state first and only mutates
// (and only escalates privilege) when needed, keeping `up --apply` idempotent.
func (m *Module) ensureReachable(ctx context.Context) error {
	if m.plat == nil {
		return nil
	}

	pl, hasLinker := m.plat.(platform.PathLinker)
	fw := m.plat.Firewall()
	af, hasApp := fw.(platform.AppFirewall)

	// The binary path is only needed for PATH-linking and per-app firewall
	// allow (both macOS); resolving it elsewhere would run brew needlessly.
	var serverPath string
	if hasLinker || hasApp {
		p, err := m.moshServerPath(ctx)
		if err != nil {
			return err
		}
		serverPath = p
	}

	if hasLinker {
		if err := ensurePathLink(ctx, pl, serverPath); err != nil {
			return err
		}
	}
	// Firewall — per-app allow (macOS) is proactive; per-range open (Linux)
	// only makes sense against an active firewall.
	if hasApp {
		if err := ensureAppAllowed(ctx, af, serverPath); err != nil {
			return err
		}
	}
	if rf, ok := fw.(platform.RangeFirewall); ok {
		if err := ensurePortRange(ctx, fw, rf); err != nil {
			return err
		}
	}
	return nil
}

// ensurePathLink symlinks serverPath onto the system base PATH if not already
// resolvable there.
func ensurePathLink(ctx context.Context, pl platform.PathLinker, serverPath string) error {
	onPath, err := pl.IsOnSystemPath(ctx, filepath.Base(serverPath))
	if err != nil {
		return fmt.Errorf("check system PATH: %w", err)
	}
	if onPath {
		return nil
	}
	slog.Info("mosh apply: linking mosh-server onto system PATH", "binary", serverPath)
	if err := pl.SymlinkIntoSystemPath(ctx, serverPath); err != nil {
		return fmt.Errorf("link mosh-server onto system PATH: %w", err)
	}
	return nil
}

// ensureAppAllowed allows serverPath through the per-application firewall unless
// it is already permitted (a query error is treated as "not confirmed" → allow).
func ensureAppAllowed(ctx context.Context, af platform.AppFirewall, serverPath string) error {
	if allowed, err := af.IsAppAllowed(ctx, serverPath); err == nil && allowed {
		return nil
	}
	slog.Info("mosh apply: allowing mosh-server through the application firewall", "binary", serverPath)
	if err := af.AllowApp(ctx, serverPath); err != nil {
		return fmt.Errorf("allow mosh-server through application firewall: %w", err)
	}
	return nil
}

// ensurePortRange opens the mosh UDP range in the host firewall when it is
// active and the range is not already open.
func ensurePortRange(ctx context.Context, fw platform.FirewallController, rf platform.RangeFirewall) error {
	if status, _ := fw.Status(ctx); status != "enabled" {
		return nil
	}
	if allowed, err := rf.IsPortRangeAllowed(ctx, moshUDPLow, moshUDPHigh, "udp"); err == nil && allowed {
		return nil
	}
	slog.Info("mosh apply: opening mosh UDP range in the host firewall", "range", "60000-61000/udp")
	if err := rf.AllowPortRange(ctx, moshUDPLow, moshUDPHigh, "udp"); err != nil {
		return fmt.Errorf("open mosh UDP range: %w", err)
	}
	return nil
}

// moshServerPath returns the stable Homebrew symlink path to mosh-server
// (<brew --prefix>/bin/mosh-server). Using the brew bin symlink (not the
// versioned Cellar path) keeps a downstream symlink valid across `brew upgrade`.
func (m *Module) moshServerPath(ctx context.Context) (string, error) {
	res, err := m.runner.Run(ctx, "brew", "--prefix")
	if err != nil || res.ExitCode != 0 {
		return "", fmt.Errorf("brew --prefix: %w", err)
	}
	prefix := strings.TrimSpace(res.Stdout)
	if prefix == "" {
		return "", fmt.Errorf("brew --prefix returned empty output")
	}
	return filepath.Join(prefix, "bin", "mosh-server"), nil
}

// Verify surfaces the host-level reachability gaps that let mosh-server install
// and run yet still fail at connect time ("No response from Mosh server"): not
// on the non-login PATH (macOS), or blocked by the host firewall. These live in
// Verify, not Detect, deliberately: runner.Doctor calls BOTH Detect and Verify,
// so Detect carries the install check (also consumed by Plan/Apply) while Verify
// carries the doctor-only reachability probes — no double-emission (NET-18), and
// Plan/Apply stay free of the extra brew/firewall probes.
//
// Only meaningful when the module is enabled, a platform is wired (nil in some
// unit tests), and mosh-server is actually installed (else Detect's "installed"
// warning already covers it).
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	if m.cfg == nil || !m.cfg.Modules.Mosh.Enabled || m.plat == nil {
		return nil, nil
	}
	if !m.moshInstalled(ctx) {
		return nil, nil
	}
	return m.reachabilityFindings(ctx), nil
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
