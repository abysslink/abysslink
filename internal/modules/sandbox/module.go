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

package sandbox

import (
	"context"
	"errors"
	"log/slog"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// ErrNotSupported is returned by Apply on non-Linux platforms: Landlock is a
// Linux-only kernel LSM (kernel >= 5.13) with no macOS/Windows equivalent. It
// is declared here (not in a build-tagged file) so callers and tests can
// reference it on every platform; only the non-Linux applyLandlockProfile
// returns it.
var ErrNotSupported = errors.New("sandbox: Landlock is Linux-only (kernel >= 5.13 required)")

// Module applies kernel-native process isolation for remote-access services.
//
// On Linux it uses the Landlock LSM (kernel >= 5.13) via go-landlock; on every
// other platform it is a no-op that reports the capability is unavailable.
// The platform-specific behaviour lives in build-tagged files:
//   - sandbox_linux.go (//go:build linux): real Landlock probe + apply.
//   - sandbox_stub.go  (//go:build !linux): isLandlockSupported()==false,
//     applyLandlockProfile()==ErrNotSupported.
//
// This file has NO build tag — it compiles on all platforms and dispatches to
// the platform functions, so the function signatures in the two build-tagged
// files MUST match.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "sandbox" }

// Deps returns this module's dependencies.
func (m *Module) Deps() []string { return nil }

// IsLandlockSupported reports whether the running kernel supports the Landlock
// LSM (Linux kernel >= 5.13). It is an exported, build-tag-polymorphic wrapper
// around the package-internal isLandlockSupported() so the cli/doctor package
// can probe the capability across the package boundary. Always false on non-Linux.
func IsLandlockSupported() bool { return isLandlockSupported() }

// Detect reports whether kernel-native process isolation (Landlock) is
// available. When the sandbox module is enabled but Landlock is unavailable
// (non-Linux, or Linux kernel < 5.13 / Landlock disabled) it emits a WARN
// finding; when Landlock is available it returns no finding.
func (m *Module) Detect(_ context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.Sandbox.Enabled {
		slog.Debug("sandbox module disabled, skipping detect")
		return nil, nil
	}

	if !isLandlockSupported() {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "sandbox-landlock-supported",
			Severity: modules.SeverityWarning,
			Message:  "Landlock not supported on this platform (Linux kernel >= 5.13 required) — sandbox module is unavailable",
		}}, nil
	}

	slog.Debug("sandbox detect: Landlock LSM available")
	return nil, nil
}

// Plan reports the single sandbox action: apply Landlock process isolation.
// Returns nil when the module is disabled.
func (m *Module) Plan(_ context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Sandbox.Enabled {
		return nil, nil
	}
	return []modules.Action{{
		Module:      m.Name(),
		Description: "sandbox: apply Landlock process isolation (Linux kernel >= 5.13 required)",
		Reversible:  false,
	}}, nil
}

// Apply applies the Landlock profile on Linux; on every other platform it
// returns ErrNotSupported (Landlock is a Linux-only kernel feature).
func (m *Module) Apply(ctx context.Context) error {
	return applyLandlockProfile(ctx)
}

// Verify re-runs Detect.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-runs Detect — sandbox findings are advisory and not auto-repairable.
func (m *Module) Repair(ctx context.Context) error {
	_, err := m.Detect(ctx)
	return err
}
