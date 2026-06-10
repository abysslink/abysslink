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

package lock

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetect_LockEnabled_OKFinding(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	// Lock is on and config requires it: expect exactly one SeverityOK finding
	// for lock_enabled (not empty — D-03 presence-based "ran" detection requires it).
	require.Len(t, findings, 1, "lock is on, config requires it: expect one OK finding")
	assert.Equal(t, "lock_enabled", findings[0].Check)
	assert.Equal(t, modules.SeverityOK, findings[0].Severity)
}

func TestLockEnabledOK(t *testing.T) {
	// Clean path: lock is enabled and config requires it → expect SeverityOK
	// finding with Check=="lock_enabled".
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "lock_enabled" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"lock_enabled\" on clean path, got none")
	}
	assert.Equal(t, modules.SeverityOK, found.Severity, "clean path must emit SeverityOK for lock_enabled")
}

func TestDetect_LockDisabled_ConfigRequires_Warning(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":false}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "lock_enabled", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_NonZeroExit_Warning(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "tailscale not running"}})
	cfg := config.Defaults()
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "lock_status", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

// TestApply_SeverityOK_NoError asserts that Apply returns nil (no error) when
// Detect yields a SeverityOK lock_enabled finding — i.e. when Tailnet Lock is
// correctly enabled. This is the CR-01 regression test.
func TestApply_SeverityOK_NoError(t *testing.T) {
	// Detect makes one Run call; Apply calls Detect, so the mock must have one call.
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})

	err := m.Apply(context.Background())
	assert.NoError(t, err, "Apply must not error when Tailnet Lock is correctly enabled (SeverityOK path)")
}

// TestApply_LockDisabled_ReturnsError asserts that Apply returns the actionable
// "not yet enabled" error when Detect yields a non-OK lock_enabled finding.
func TestApply_LockDisabled_ReturnsError(t *testing.T) {
	// Detect makes one Run call; lock disabled, config requires it → SeverityWarning.
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":false}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})

	err := m.Apply(context.Background())
	require.Error(t, err, "Apply must return an error when Tailnet Lock is required but not enabled")
	assert.Contains(t, err.Error(), "Tailnet Lock is required but not yet enabled")
}

// TestVerifyReturnsNil asserts that Verify returns nil findings and nil error
// (Pitfall-4 fix: Verify must not delegate to Detect to avoid double-emission).
func TestVerifyReturnsNil(t *testing.T) {
	// No mock calls expected — Verify must return nil without running any commands.
	r := shell.NewMockRunner()
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Verify(context.Background())
	require.NoError(t, err, "Verify must not return an error")
	require.Empty(t, findings, "Verify must return nil/empty findings (no double-emission)")
}

// TestDetect_ConfigDisabled_EmitsVisibleWarning: Tailnet Lock is an
// on-by-default, "never weaken" control. When the user disables it in config
// (and it is off on the tailnet), Detect must emit a WARN finding so the
// disablement is visible in doctor output instead of silently fail-open
// (review INFO — contrast with the disk-encryption FATAL posture).
func TestDetect_ConfigDisabled_EmitsVisibleWarning(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":false}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1, "config-disabled lock must be visible, not silent")
	assert.Equal(t, "lock_disabled", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

// TestPlanApply_ConfigDisabled_NoAction asserts the lock_disabled finding is
// report-only: Plan emits no action and Apply returns nil (the check name is
// deliberately distinct from lock_enabled).
func TestPlanApply_ConfigDisabled_NoAction(t *testing.T) {
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = false

	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":false}`}})
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	assert.Empty(t, actions, "lock_disabled is report-only — no plan action")

	r2 := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":false}`}})
	m2 := New(modules.Deps{Cfg: cfg, Runner: r2})
	assert.NoError(t, m2.Apply(context.Background()), "Apply must not error on lock_disabled")
}
