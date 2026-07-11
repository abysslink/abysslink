//go:build darwin

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

package darwin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// fwBin is the macOS Application Firewall control binary.
const fwBin = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// systemPathDir is the base-PATH directory abysslink symlinks Homebrew binaries
// into so non-login shells (e.g. the shell Tailscale SSH execs commands in) can
// resolve them. It is present on the default PATH for sh/bash/zsh/fish, whereas
// /opt/homebrew/bin is not. A var (not const) so tests can redirect it to a
// temp dir.
var systemPathDir = "/usr/local/bin"

// Platform is the macOS implementation of platform.Platform.
type Platform struct {
	runner shell.Runner
}

// New returns a Darwin Platform using the given shell runner.
func New(runner shell.Runner) *Platform {
	return &Platform{runner: runner}
}

// OS returns "darwin".
func (p *Platform) OS() string { return "darwin" }

// Distro returns DistroUnknown (not applicable on macOS).
func (p *Platform) Distro() platform.Distro { return platform.DistroUnknown }

// PackageManager returns PkgBrew.
func (p *Platform) PackageManager() platform.PackageManager { return platform.PkgBrew }

// InstallPackage installs a Homebrew package. A brew failure (package not
// found, network down) exits non-zero with err == nil from shell.Runner — the
// exit code MUST be checked or modules proceed to configure binaries that were
// never installed (C4).
func (p *Platform) InstallPackage(ctx context.Context, name string) error {
	res, err := p.runner.Run(ctx, "brew", "install", name)
	if err != nil {
		return err
	}
	if !res.Ok() {
		return fmt.Errorf("brew install %s exited %d: %s", name, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// RemovePackage uninstalls a Homebrew package.
func (p *Platform) RemovePackage(ctx context.Context, name string) error {
	res, err := p.runner.Run(ctx, "brew", "uninstall", name)
	if err != nil {
		return err
	}
	if !res.Ok() {
		return fmt.Errorf("brew uninstall %s exited %d: %s", name, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// runPrivileged runs a command that needs root. If the process is already root
// it runs directly; otherwise it prefixes sudo (which prompts on the terminal
// when credentials are needed). The binary is always exec'd directly — never via
// a shell — so there is no shell-injection surface. Mirrors the Linux platform.
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

// SymlinkIntoSystemPath symlinks binaryPath into /usr/local/bin under its base
// name so non-login shells resolve it. Idempotent: if the link already points at
// binaryPath it does nothing (and uses no privilege). Implements
// platform.PathLinker. The link target is the stable Homebrew bin symlink, so it
// keeps resolving across `brew upgrade` (which only re-points its own symlink).
func (p *Platform) SymlinkIntoSystemPath(ctx context.Context, binaryPath string) error {
	link := filepath.Join(systemPathDir, filepath.Base(binaryPath))
	if link == binaryPath {
		// The binary already lives in the system PATH dir (Intel Homebrew:
		// brew --prefix == /usr/local). Linking it onto itself would create a
		// self-referential symlink; there is nothing to do.
		return nil
	}
	if dst, err := os.Readlink(link); err == nil && dst == binaryPath {
		return nil // already linked correctly — no privilege needed
	}
	if err := p.runPrivileged(ctx, "mkdir", "-p", systemPathDir); err != nil {
		return fmt.Errorf("create %s: %w", systemPathDir, err)
	}
	if err := p.runPrivileged(ctx, "ln", "-sf", binaryPath, link); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", link, binaryPath, err)
	}
	return nil
}

// RemoveFromSystemPath removes the abysslink-managed symlink for binaryPath on
// uninstall, but ONLY when the link points exactly at binaryPath. A
// package-manager-owned link (Intel Homebrew uses a relative ../Cellar target),
// a real file, or an absent link is left untouched — so this never deletes a
// binary abysslink did not create. dryRun reports without mutating. Implements
// platform.PathLinker.
func (p *Platform) RemoveFromSystemPath(ctx context.Context, binaryPath string, dryRun bool) (string, error) {
	link := filepath.Join(systemPathDir, filepath.Base(binaryPath))
	dst, err := os.Readlink(link)
	if err != nil || dst != binaryPath {
		return "", nil // not our managed symlink — leave it
	}
	if dryRun {
		return link, nil
	}
	if err := p.runPrivileged(ctx, "rm", "-f", link); err != nil {
		return "", fmt.Errorf("remove %s: %w", link, err)
	}
	return link, nil
}

// IsOnSystemPath reports whether a binary named name resolves on the system base
// PATH via the abysslink-managed symlink in /usr/local/bin. os.Stat follows the
// symlink, so a dangling link reports false. Implements platform.PathLinker.
func (p *Platform) IsOnSystemPath(_ context.Context, name string) (bool, error) {
	link := filepath.Join(systemPathDir, name)
	switch _, err := os.Stat(link); {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

// DiskEncryptionStatus reports FileVault status via fdesetup.
//
// The parse ORDER is load-bearing and fails closed (BKLG-02). Real macOS prints
// "FileVault is On. Encryption in progress: Percent completed = NN.N" during
// initial encryption — which STARTS WITH "FileVault is On". A thin
// HasPrefix("FileVault is On") therefore fails OPEN, reporting DiskEncrypted
// while plaintext blocks still exist on disk. The in-progress/deferred/decryption
// substrings are matched BEFORE the "On" prefix so mid-encryption maps to
// DiskEncrypting (not-safe), and any unrecognized output maps to DiskUnknown —
// never DiskEncrypted.
//
// The three in-progress literals are lifted verbatim from the hardening detector
// (internal/modules/hardening/detect_darwin.go) and are tagged ASSUMED (MEDIUM
// confidence) — confirm against real hardware. A parse miss fails closed.
func (p *Platform) DiskEncryptionStatus(ctx context.Context) (platform.DiskState, error) {
	result, err := p.runner.Run(ctx, "fdesetup", "status")
	if err != nil {
		return platform.DiskUnknown, fmt.Errorf("fdesetup status: %w", err)
	}
	// Non-zero exit is a fault, not "unencrypted": fail closed to UNKNOWN.
	if !result.Ok() {
		return platform.DiskUnknown, fmt.Errorf("fdesetup status exited %d: %s",
			result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	out := strings.TrimSpace(result.Stdout)
	switch {
	case strings.HasPrefix(out, "FileVault is Off"):
		return platform.DiskUnencrypted, nil
	// In-progress states (ASSUMED literals) MUST be checked before the "On"
	// prefix — "FileVault is On. Encryption in progress …" starts with "On".
	case strings.Contains(out, "Encryption in progress"),
		strings.Contains(out, "Deferred enablement appears to be active"),
		strings.Contains(out, "Decryption in progress"):
		return platform.DiskEncrypting, nil
	case strings.HasPrefix(out, "FileVault is On"):
		return platform.DiskEncrypted, nil
	default:
		// Unrecognized output fails closed to UNKNOWN, never DiskEncrypted.
		return platform.DiskUnknown, fmt.Errorf("fdesetup status: unrecognized output: %q", out)
	}
}

// Firewall returns the macOS firewall controller.
func (p *Platform) Firewall() platform.FirewallController { return &darwinFirewall{p: p} }

// KeepAwake prevents system or display sleep using caffeinate.
//
// BLOCKING semantics (mirrors the linux KeepAwakeSystem implementation):
// System/Display run `caffeinate` which holds the assertion and BLOCKS until
// ctx is cancelled — cancellation of the same ctx is the release mechanism.
// KeepAwakeOff is therefore a no-op: there is no cross-process way to release
// an assertion held by a previous caffeinate; the previous `caffeinate -s -t 0`
// "off" spawned a new caffeinate that exited immediately and released nothing.
//
// TODO: if a non-blocking on/off pair is ever needed, manage a long-lived
// caffeinate process handle (start/kill) or use pmset assertions instead.
func (p *Platform) KeepAwake(ctx context.Context, mode platform.KeepAwakeMode) error {
	switch mode {
	case platform.KeepAwakeOff:
		// No-op by design: "on" is released by cancelling the ctx passed to it.
		return nil
	case platform.KeepAwakeDisplay:
		_, err := p.runner.Run(ctx, "caffeinate", "-d")
		return err
	case platform.KeepAwakeSystem:
		_, err := p.runner.Run(ctx, "caffeinate", "-s")
		return err
	default:
		return fmt.Errorf("unknown keep-awake mode: %s", mode)
	}
}

// darwinFirewall implements platform.FirewallController plus the optional
// platform.AppFirewall capability. It holds a *Platform so it can use
// runPrivileged for write operations (socketfilterfw --add needs root) while
// using the plain runner for read-only state queries.
type darwinFirewall struct{ p *Platform }

func (f *darwinFirewall) AllowPort(_ context.Context, port int, proto string) error {
	// macOS Application Firewall is per-application, not per-port.
	// Per-port rules require the BSD packet filter (pf). Use AllowApp instead.
	return fmt.Errorf("darwin: application firewall is per-application not per-port; use pfctl(8) to allow %s/%d", proto, port)
}

func (f *darwinFirewall) DenyPort(_ context.Context, port int, proto string) error {
	return fmt.Errorf("darwin: application firewall is per-application not per-port; use pfctl(8) to deny %s/%d", proto, port)
}

// AllowApp permits incoming connections to binaryPath via socketfilterfw,
// then unblocks it (an app can be in the list but blocked). Implements
// platform.AppFirewall. Both subcommands need root, hence runPrivileged.
func (f *darwinFirewall) AllowApp(ctx context.Context, binaryPath string) error {
	if err := f.p.runPrivileged(ctx, fwBin, "--add", binaryPath); err != nil {
		return fmt.Errorf("socketfilterfw --add %s: %w", binaryPath, err)
	}
	if err := f.p.runPrivileged(ctx, fwBin, "--unblockapp", binaryPath); err != nil {
		return fmt.Errorf("socketfilterfw --unblockapp %s: %w", binaryPath, err)
	}
	return nil
}

// IsAppAllowed reports whether incoming connections to binaryPath are permitted.
// socketfilterfw --getappblocked is read-only (no root needed) and prints
// "... is permitted." or "... is blocked." Implements platform.AppFirewall.
//
// An exec error or unrecognized output is returned as an error (not a bare
// false) so callers can tell "confirmed blocked" from "could not determine":
// the apply path re-allows on either (safe), while the doctor probe skips the
// finding on error — avoiding a false-positive "not allowed" warning.
func (f *darwinFirewall) IsAppAllowed(ctx context.Context, binaryPath string) (bool, error) {
	res, err := f.p.runner.Run(ctx, fwBin, "--getappblocked", binaryPath)
	if err != nil {
		return false, fmt.Errorf("darwin firewall: socketfilterfw --getappblocked: %w", err)
	}
	out := strings.ToLower(res.Stdout)
	switch {
	case strings.Contains(out, "permitted"):
		return true, nil
	case strings.Contains(out, "blocked"):
		return false, nil
	default:
		return false, fmt.Errorf("darwin firewall: unrecognized socketfilterfw output: %q", strings.TrimSpace(res.Stdout))
	}
}

func (f *darwinFirewall) Status(ctx context.Context) (string, error) {
	res, err := f.p.runner.Run(ctx, fwBin, "--getglobalstate")
	if err != nil {
		return "unknown", fmt.Errorf("darwin firewall: socketfilterfw: %w", err)
	}
	if res.ExitCode != 0 {
		return "unknown", fmt.Errorf("darwin firewall: socketfilterfw exited %d: %s",
			res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	out := strings.TrimSpace(res.Stdout)
	if strings.Contains(out, "State = 1") {
		return "enabled", nil
	}
	if strings.Contains(out, "State = 0") {
		return "disabled", nil
	}
	return "unknown", nil
}
