//go:build !darwin && !linux

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

// Package stub provides a no-op Platform implementation for unsupported operating systems,
// returning "unsupported" errors so cross-compilation targets still link.
package stub

import (
	"context"
	"fmt"

	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// Platform is a stub implementation for unsupported platforms (e.g., Windows, cross-compile targets).
type Platform struct{}

// New returns a stub Platform that returns "unsupported" errors.
func New(_ shell.Runner) *Platform { return &Platform{} }

func (p *Platform) OS() string                              { return "unsupported" }
func (p *Platform) Distro() platform.Distro                 { return platform.DistroUnknown }
func (p *Platform) PackageManager() platform.PackageManager { return "" }

func (p *Platform) InstallPackage(_ context.Context, name string) error {
	return fmt.Errorf("unsupported platform: cannot install %s", name)
}

func (p *Platform) RemovePackage(_ context.Context, name string) error {
	return fmt.Errorf("unsupported platform: cannot remove %s", name)
}

func (p *Platform) ServiceInstall(_ context.Context, _ platform.ServiceSpec) error {
	return fmt.Errorf("unsupported platform")
}

func (p *Platform) ServiceUninstall(_ context.Context, _ string) error {
	return fmt.Errorf("unsupported platform")
}

func (p *Platform) ServiceStart(_ context.Context, _ string) error {
	return fmt.Errorf("unsupported platform")
}

func (p *Platform) ServiceStop(_ context.Context, _ string) error {
	return fmt.Errorf("unsupported platform")
}

func (p *Platform) ServiceStatus(_ context.Context, _ string) (platform.ServiceStatus, error) {
	return platform.ServiceUnknown, fmt.Errorf("unsupported platform")
}

func (p *Platform) DiskEncryptionStatus(_ context.Context) (platform.DiskState, error) {
	return platform.DiskUnknown, fmt.Errorf("unsupported platform")
}

func (p *Platform) Firewall() platform.FirewallController { return &stubFirewall{} }

func (p *Platform) KeepAwake(_ context.Context, _ platform.KeepAwakeMode) error {
	return fmt.Errorf("unsupported platform")
}

type stubFirewall struct{}

func (f *stubFirewall) AllowPort(_ context.Context, _ int, _ string) error {
	return fmt.Errorf("unsupported platform")
}

func (f *stubFirewall) DenyPort(_ context.Context, _ int, _ string) error {
	return fmt.Errorf("unsupported platform")
}

func (f *stubFirewall) Status(_ context.Context) (string, error) {
	return "", fmt.Errorf("unsupported platform")
}
