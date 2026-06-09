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
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enabledCfg returns a config with the sandbox module enabled.
func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Sandbox.Enabled = true
	return cfg
}

// TestSandboxModule_Detect_Disabled verifies Detect returns nil findings when
// the module is disabled, regardless of platform.
func TestSandboxModule_Detect_Disabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Sandbox.Enabled = false
	r := shell.NewMockRunner() // no shell calls expected
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.True(t, r.Done(), "no shell calls should be made when module is disabled")
}

// TestModule_Detect_macOS verifies that on darwin Detect emits the
// sandbox-landlock-supported WARN finding (Landlock is Linux-only). The check
// is skipped on Linux, where Landlock may be supported.
func TestModule_Detect_macOS(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Landlock may be supported on Linux; this test asserts the non-Linux stub path")
	}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: shell.NewMockRunner()})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "sandbox-landlock-supported", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
	assert.Contains(t, findings[0].Message, "Linux kernel")
}

// TestModule_Apply_macOS verifies Apply is a graceful no-op (nil error) on
// darwin instead of returning ErrNotSupported (F-61): a hard error here
// aborted `abysslink up --apply` fatally on every Mac with sandbox enabled.
// Plan must also have planned no action on this platform.
func TestModule_Apply_macOS(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Apply succeeds (or BestEffort no-ops) on Linux; this test asserts the non-Linux stub path")
	}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: shell.NewMockRunner()})

	actions, planErr := m.Plan(context.Background(), false)
	require.NoError(t, planErr)
	assert.Empty(t, actions, "no Landlock action may be planned on a platform that cannot apply it (F-61)")

	err := m.Apply(context.Background())
	assert.NoError(t, err, "Apply must skip gracefully (nil) on unsupported platforms, not fail the entire up run (F-61)")
}

// TestErrNotSupported_StillExported verifies the stub applyLandlockProfile
// still returns the exported ErrNotSupported for callers that bypass the
// Apply gate (the sentinel remains part of the package API after F-61).
func TestErrNotSupported_StillExported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("stub applyLandlockProfile exists only on non-Linux builds")
	}
	assert.ErrorIs(t, applyLandlockProfile(context.Background()), ErrNotSupported)
}

// TestIsLandlockSupported_Stub verifies the build-tag-polymorphic
// isLandlockSupported() returns false on non-Linux (stub) builds.
func TestIsLandlockSupported_Stub(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("stub returns false only on non-Linux builds")
	}
	assert.False(t, isLandlockSupported())
	assert.False(t, IsLandlockSupported(), "exported wrapper must mirror the internal probe")
}

// TestPlan_Disabled_Nil verifies Plan returns nil when the module is disabled.
func TestPlan_Disabled_Nil(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Sandbox.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	assert.Nil(t, actions)
}

// TestPlan_Enabled_ReturnsAction verifies Plan returns the single Landlock
// action when Landlock is actually supported. On platforms without Landlock,
// Plan returns nil (F-61) — that path is covered by TestModule_Apply_macOS.
func TestPlan_Enabled_ReturnsAction(t *testing.T) {
	if !isLandlockSupported() {
		t.Skip("Landlock unsupported on this platform; Plan correctly returns nil actions (F-61)")
	}
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "sandbox", actions[0].Module)
	assert.Contains(t, actions[0].Description, "Landlock")
	assert.False(t, actions[0].Reversible, "Landlock isolation is not reversible via auto-apply")
}

// TestVerify_DelegatesToDetect verifies Verify mirrors Detect.
func TestVerify_DelegatesToDetect(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: shell.NewMockRunner()})
	vf, verr := m.Verify(context.Background())
	df, derr := m.Detect(context.Background())
	require.NoError(t, verr)
	require.NoError(t, derr)
	assert.Equal(t, df, vf)
}
