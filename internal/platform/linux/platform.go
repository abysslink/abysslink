//go:build linux

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

package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// Platform is the Linux implementation of platform.Platform.
type Platform struct {
	runner shell.Runner
	distro platform.Distro
	pkgMgr platform.PackageManager
}

// New detects the distro from /etc/os-release and returns a Linux Platform.
func New(runner shell.Runner) (*Platform, error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		// If /etc/os-release is absent (e.g. container base), carry on with unknowns.
		return &Platform{runner: runner, distro: platform.DistroUnknown}, nil
	}
	defer func() { _ = f.Close() }()

	fields, _ := ParseOSRelease(f)
	d := DetectDistro(fields)
	return &Platform{
		runner: runner,
		distro: d,
		pkgMgr: DistroToPackageManager(d),
	}, nil
}

// OS returns "linux".
func (p *Platform) OS() string { return "linux" }

// Distro returns the detected Linux distribution.
func (p *Platform) Distro() platform.Distro { return p.distro }

// PackageManager returns the package manager for this distribution.
func (p *Platform) PackageManager() platform.PackageManager { return p.pkgMgr }

// InstallPackage installs a package using the detected package manager. System
// package managers (apt/dnf/pacman) require root, so they are invoked via sudo
// when the process is not already root; nix installs into the per-user profile
// and never uses sudo.
func (p *Platform) InstallPackage(ctx context.Context, name string) error {
	switch p.pkgMgr {
	case platform.PkgApt:
		return p.runPrivileged(ctx, "apt-get", "install", "-y", name)
	case platform.PkgDnf:
		return p.runPrivileged(ctx, "dnf", "install", "-y", name)
	case platform.PkgPacman:
		return p.runPrivileged(ctx, "pacman", "-S", "--noconfirm", name)
	case platform.PkgNix:
		// nix-env needs no sudo, but its failure is still carried in the exit
		// code with err == nil (C4 bug class) — check Ok(), not just err.
		res, err := p.runner.Run(ctx, "nix-env", "-iA", "nixpkgs."+name)
		if err != nil {
			return err
		}
		if !res.Ok() {
			return fmt.Errorf("nix-env -iA nixpkgs.%s exited %d: %s", name, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		return nil
	default:
		return fmt.Errorf("unsupported package manager: %q", p.pkgMgr)
	}
}

// RemovePackage removes a package using the detected package manager.
func (p *Platform) RemovePackage(ctx context.Context, name string) error {
	switch p.pkgMgr {
	case platform.PkgApt:
		return p.runPrivileged(ctx, "apt-get", "remove", "-y", name)
	case platform.PkgDnf:
		return p.runPrivileged(ctx, "dnf", "remove", "-y", name)
	case platform.PkgPacman:
		return p.runPrivileged(ctx, "pacman", "-R", "--noconfirm", name)
	case platform.PkgNix:
		res, err := p.runner.Run(ctx, "nix-env", "-e", name)
		if err != nil {
			return err
		}
		if !res.Ok() {
			return fmt.Errorf("nix-env -e %s exited %d: %s", name, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		return nil
	default:
		return fmt.Errorf("unsupported package manager: %q", p.pkgMgr)
	}
}

// runPrivileged runs a command that needs root. If the process is already root
// it runs directly; otherwise it prefixes sudo (which prompts on the terminal
// when credentials are needed). The binary is always exec'd directly — never
// via a shell — so there is no shell-injection surface.
func (p *Platform) runPrivileged(ctx context.Context, name string, args ...string) error {
	var res shell.Result
	var err error
	if os.Geteuid() == 0 {
		res, err = p.runner.Run(ctx, name, args...)
	} else {
		res, err = p.runner.Run(ctx, "sudo", append([]string{name}, args...)...)
	}
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited %d: %s", name, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// lsblkOutput is the top-level JSON structure from lsblk -J.
type lsblkOutput struct {
	Blockdevices []lsblkDevice `json:"blockdevices"`
}

// lsblkDevice represents a single block device entry in lsblk JSON output.
type lsblkDevice struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Children []lsblkDevice `json:"children"`
}

// hasCryptDevice recursively scans a device tree for TYPE=crypt entries.
func hasCryptDevice(devices []lsblkDevice) bool {
	for _, dev := range devices {
		if strings.EqualFold(dev.Type, "crypt") {
			return true
		}
		if hasCryptDevice(dev.Children) {
			return true
		}
	}
	return false
}

// DiskEncryptionStatus checks whether the root filesystem sits on a LUKS device
// by running lsblk -J -o NAME,TYPE and scanning for TYPE=crypt.
func (p *Platform) DiskEncryptionStatus(ctx context.Context) (platform.DiskState, error) {
	result, err := p.runner.Run(ctx, "lsblk", "-J", "-o", "NAME,TYPE")
	if err != nil {
		return platform.DiskUnknown, fmt.Errorf("lsblk: %w", err)
	}

	var out lsblkOutput
	if err := json.Unmarshal([]byte(result.Stdout), &out); err != nil {
		return platform.DiskUnknown, nil
	}

	if hasCryptDevice(out.Blockdevices) {
		return platform.DiskEncrypted, nil
	}
	return platform.DiskUnencrypted, nil
}

// Firewall returns the Linux firewall controller.
func (p *Platform) Firewall() platform.FirewallController {
	return &linuxFirewall{p: p}
}

// KeepAwake prevents system or display sleep on Linux.
//
// System: uses systemd-inhibit to block sleep until the context is cancelled.
// Display: stub returning not-yet-implemented.
// Off: no-op.
func (p *Platform) KeepAwake(ctx context.Context, mode platform.KeepAwakeMode) error {
	switch mode {
	case platform.KeepAwakeOff:
		return nil
	case platform.KeepAwakeSystem:
		_, err := p.runner.Run(ctx,
			"systemd-inhibit",
			"--what=sleep",
			"--who=abysslink",
			"--why=requested",
			"--mode=block",
			"sleep", "infinity",
		)
		return err
	case platform.KeepAwakeDisplay:
		// Best-effort: disable X11 screensaver and DPMS. Continues without error
		// if xset is unavailable (Wayland/headless) — systemd-inhibit already
		// handles system sleep via KeepAwakeSystem.
		res, xErr := p.runner.Run(ctx, "xset", "s", "off")
		if xErr != nil || res.ExitCode != 0 {
			slog.Warn("keep-awake display: xset unavailable; display may sleep (system keep-awake unaffected)")
			return nil
		}
		if res2, err2 := p.runner.Run(ctx, "xset", "-dpms"); err2 != nil || res2.ExitCode != 0 {
			slog.Warn("keep-awake display: xset -dpms failed; DPMS may still be active, display may blank")
		}
		return nil
	default:
		return fmt.Errorf("unknown keep-awake mode: %s", mode)
	}
}

// linuxFirewall implements platform.FirewallController for Linux.
// It holds a *Platform so it can use runPrivileged for write operations
// (ufw/iptables require root) while using the plain runner for read-only
// status queries.
type linuxFirewall struct{ p *Platform }

func (f *linuxFirewall) AllowPort(ctx context.Context, port int, proto string) error {
	rule := fmt.Sprintf("%d/%s", port, proto)
	// Prefer ufw (privilege-elevated; ufw manages rules persistently across reboots).
	if err := f.p.runPrivileged(ctx, "ufw", "allow", rule); err == nil {
		return nil
	}
	// Fall back to iptables (privilege-elevated; ephemeral, lost on reboot).
	return f.p.runPrivileged(ctx, "iptables", "-A", "INPUT",
		"-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
}

// AllowPortRange opens the inclusive [lo,hi] range for proto. Implements the
// optional platform.RangeFirewall capability — used by the mosh module to open
// the mosh UDP range (60000-61000). Prefers ufw (persistent), falls back to
// iptables (ephemeral). Both use ufw/iptables range syntax "lo:hi".
func (f *linuxFirewall) AllowPortRange(ctx context.Context, lo, hi int, proto string) error {
	rule := fmt.Sprintf("%d:%d/%s", lo, hi, proto)
	if err := f.p.runPrivileged(ctx, "ufw", "allow", rule); err == nil {
		return nil
	}
	return f.p.runPrivileged(ctx, "iptables", "-A", "INPUT",
		"-p", proto, "--dport", fmt.Sprintf("%d:%d", lo, hi), "-j", "ACCEPT")
}

// IsPortRangeAllowed reports whether [lo,hi]/proto appears as an ALLOW rule in
// `ufw status`. A genuine exec/IO failure (err != nil — e.g. context cancelled)
// is propagated so the doctor probe skips rather than emit a false "not open"
// warning; a non-zero exit (ufw absent/errored — the codebase's C4 class, where
// failures surface in ExitCode with err == nil) is treated as "not confirmed
// open". Implements platform.RangeFirewall.
func (f *linuxFirewall) IsPortRangeAllowed(ctx context.Context, lo, hi int, proto string) (bool, error) {
	res, err := f.p.runner.Run(ctx, "ufw", "status")
	if err != nil {
		return false, fmt.Errorf("ufw status: %w", err)
	}
	if res.ExitCode != 0 {
		return false, nil // ufw absent or errored — cannot confirm
	}
	needle := fmt.Sprintf("%d:%d/%s", lo, hi, proto)
	return strings.Contains(res.Stdout, needle), nil
}

func (f *linuxFirewall) DenyPort(ctx context.Context, port int, proto string) error {
	rule := fmt.Sprintf("%d/%s", port, proto)
	// Prefer ufw (privilege-elevated).
	if err := f.p.runPrivileged(ctx, "ufw", "deny", rule); err == nil {
		return nil
	}
	// Fall back to iptables DROP (privilege-elevated).
	return f.p.runPrivileged(ctx, "iptables", "-A", "INPUT",
		"-p", proto, "--dport", fmt.Sprintf("%d", port), "-j", "DROP")
}

func (f *linuxFirewall) Status(ctx context.Context) (string, error) {
	// Try ufw first — most common on Ubuntu/Debian. Read-only; no privilege needed.
	if res, err := f.p.runner.Run(ctx, "ufw", "status"); err == nil {
		out := res.Stdout
		if strings.Contains(out, "Status: active") {
			return "enabled", nil
		}
		if strings.Contains(out, "Status: inactive") {
			return "disabled", nil
		}
	}
	// Fall back to nft. Check for actual deny/reject rules — a skeleton ruleset
	// (e.g. firewalld on Fedora/RHEL) emits non-empty output with only ACCEPT
	// policies, which is functionally equivalent to "disabled".
	if res, err := f.p.runner.Run(ctx, "nft", "list", "ruleset"); err == nil && res.ExitCode == 0 {
		out := strings.ToLower(res.Stdout)
		if strings.Contains(out, "drop") || strings.Contains(out, "reject") {
			return "enabled", nil
		}
	}
	// Fall back to iptables -S (machine-readable rule list). The default empty
	// policy produces exactly 3 lines (-P INPUT/FORWARD/OUTPUT ACCEPT); any
	// user-added rule appends an additional -A or -I line.
	if res, err := f.p.runner.Run(ctx, "iptables", "-S"); err == nil && res.ExitCode == 0 {
		if strings.Count(res.Stdout, "\n") > 3 {
			return "enabled", nil
		}
		return "disabled", nil
	}
	return "unknown", nil
}
