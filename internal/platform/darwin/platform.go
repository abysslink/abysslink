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
	"strings"

	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

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

// InstallPackage installs a Homebrew package.
func (p *Platform) InstallPackage(ctx context.Context, name string) error {
	_, err := p.runner.Run(ctx, "brew", "install", name)
	return err
}

// RemovePackage uninstalls a Homebrew package.
func (p *Platform) RemovePackage(ctx context.Context, name string) error {
	_, err := p.runner.Run(ctx, "brew", "uninstall", name)
	return err
}

// DiskEncryptionStatus reports FileVault status via fdesetup.
func (p *Platform) DiskEncryptionStatus(ctx context.Context) (platform.DiskState, error) {
	result, err := p.runner.Run(ctx, "fdesetup", "status")
	if err != nil {
		return platform.DiskUnknown, fmt.Errorf("fdesetup status: %w", err)
	}
	if strings.HasPrefix(strings.TrimSpace(result.Stdout), "FileVault is On") {
		return platform.DiskEncrypted, nil
	}
	return platform.DiskUnencrypted, nil
}

// Firewall returns the macOS firewall controller.
func (p *Platform) Firewall() platform.FirewallController { return &darwinFirewall{runner: p.runner} }

// KeepAwake prevents system or display sleep using caffeinate.
func (p *Platform) KeepAwake(ctx context.Context, mode platform.KeepAwakeMode) error {
	switch mode {
	case platform.KeepAwakeOff:
		_, err := p.runner.Run(ctx, "caffeinate", "-s", "-t", "0")
		return err
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

type darwinFirewall struct{ runner shell.Runner }

func (f *darwinFirewall) AllowPort(_ context.Context, port int, proto string) error {
	// macOS Application Firewall is per-application, not per-port.
	// Per-port rules require the BSD packet filter (pf).
	return fmt.Errorf("darwin: application firewall is per-application not per-port; use pfctl(8) to allow %s/%d", proto, port)
}

func (f *darwinFirewall) DenyPort(_ context.Context, port int, proto string) error {
	return fmt.Errorf("darwin: application firewall is per-application not per-port; use pfctl(8) to deny %s/%d", proto, port)
}

func (f *darwinFirewall) Status(ctx context.Context) (string, error) {
	res, err := f.runner.Run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
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
