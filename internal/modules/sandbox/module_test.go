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

func TestDetect_Disabled_NilFindings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Sandbox.Enabled = false
	r := shell.NewMockRunner() // no calls expected
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.True(t, r.Done(), "no shell calls should be made when module is disabled")
}

func TestDetect_Enabled_SandboxExecFails_Finding(t *testing.T) {
	// Simulate sandbox-exec returning a non-zero exit code with no "profile" in stderr.
	r := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 1, Stderr: "command not found"},
	})
	m := &Module{runner: r, cfg: enabledCfg()}
	// Exercise detectDarwin directly so the test is OS-independent.
	findings := m.detectDarwin(context.Background())
	require.Len(t, findings, 1)
	assert.Equal(t, "sandbox_exec_available", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_Enabled_SandboxExecProfileStderr_NoFinding(t *testing.T) {
	// sandbox-exec prints something containing "profile" to stderr — treat as available.
	r := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 1, Stderr: "sandbox: profile loading failed: no-internet"},
	})
	m := &Module{runner: r, cfg: enabledCfg()}
	findings := m.detectDarwin(context.Background())
	assert.Empty(t, findings, "stderr containing 'profile' means sandbox-exec is present")
}

func TestDetect_Enabled_SandboxExecOK_NoFinding(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})
	m := &Module{runner: r, cfg: enabledCfg()}
	findings := m.detectDarwin(context.Background())
	assert.Empty(t, findings)
}

func TestDetect_Linux_FirejailMissing_Finding(t *testing.T) {
	// firejail not found (exit 127), then systemctl --user status (exit 0).
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	m := &Module{runner: r, cfg: enabledCfg()}
	findings := m.detectLinux(context.Background())
	require.Len(t, findings, 1)
	assert.Equal(t, "firejail_available", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_Linux_FirejailPresent_NoFinding(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0, Stdout: "firejail version 0.9.72"}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	m := &Module{runner: r, cfg: enabledCfg()}
	findings := m.detectLinux(context.Background())
	assert.Empty(t, findings)
}

func TestPlan_Disabled_Nil(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Sandbox.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	assert.Nil(t, actions)
}

func TestPlan_Enabled_ReturnsAction(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "sandbox", actions[0].Module)
	assert.False(t, actions[0].Reversible, "sandbox profiles are not reversible via auto-apply")
}

func TestApply_IsNoOp(t *testing.T) {
	// Apply must always return nil — it is intentionally a no-op.
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: shell.NewMockRunner()})
	err := m.Apply(context.Background())
	assert.NoError(t, err)
	assert.True(t, m.runner.(*shell.MockRunner).Done(), "Apply must not invoke any shell commands")
}

func TestVerify_DelegatesToDetect(t *testing.T) {
	// Verify is an alias for Detect. Supply two calls so the test is safe on both
	// darwin (1 call: sandbox-exec) and linux (2 calls: firejail + systemctl).
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "command not found"}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	m := &Module{runner: r, cfg: enabledCfg()}
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)
	// On darwin: sandbox-exec not found → 1 finding.
	// On linux: firejail not found → 1 finding.
	assert.NotEmpty(t, findings)
}
