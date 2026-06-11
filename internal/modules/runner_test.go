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

package modules_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	lockmod "github.com/abysslink/abysslink/internal/modules/lock"
	sshmod "github.com/abysslink/abysslink/internal/modules/ssh"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeModule is a test double for Module that records call counts.
type fakeModule struct {
	name     string
	deps     []string
	findings []modules.Finding
	actions  []modules.Action
	applyErr error

	detectCalls int
	planCalls   int
	applyCalls  int
	verifyCalls int

	// executionOrder records when this module's Apply was called relative to others.
	executionOrder *[]string
}

func (f *fakeModule) Name() string { return f.name }
func (f *fakeModule) Deps() []string {
	if f.deps == nil {
		return []string{}
	}
	return f.deps
}
func (f *fakeModule) Detect(_ context.Context) ([]modules.Finding, error) {
	f.detectCalls++
	return f.findings, nil
}
func (f *fakeModule) Plan(_ context.Context, _ bool) ([]modules.Action, error) {
	f.planCalls++
	return f.actions, nil
}
func (f *fakeModule) Apply(_ context.Context) error {
	f.applyCalls++
	if f.executionOrder != nil {
		*f.executionOrder = append(*f.executionOrder, f.name)
	}
	return f.applyErr
}
func (f *fakeModule) Verify(_ context.Context) ([]modules.Finding, error) {
	f.verifyCalls++
	return f.findings, nil
}
func (f *fakeModule) Repair(_ context.Context) error { return nil }

func minimalCfg() *config.Config {
	return config.Defaults()
}

func TestRunner_DryRun(t *testing.T) {
	m := &fakeModule{
		name: "dry-mod",
		actions: []modules.Action{
			{Module: "dry-mod", Description: "do something", Reversible: true},
		},
	}
	runner, err := modules.NewRunner([]modules.Module{m}, minimalCfg())
	require.NoError(t, err)

	actions, findings, err := runner.Up(context.Background(), true /* dryRun */)
	require.NoError(t, err)

	// Apply must NOT have been called in dry-run mode.
	assert.Equal(t, 0, m.applyCalls, "Apply must not be called during dry-run")
	assert.Equal(t, 1, m.planCalls, "Plan must be called")
	assert.Equal(t, 1, m.detectCalls, "Detect must be called")
	assert.Equal(t, 1, m.verifyCalls, "Verify must be called")
	assert.Len(t, actions, 1)
	_ = findings
}

func TestRunner_Apply(t *testing.T) {
	m := &fakeModule{
		name: "apply-mod",
		actions: []modules.Action{
			{Module: "apply-mod", Description: "install thing"},
		},
	}
	runner, err := modules.NewRunner([]modules.Module{m}, minimalCfg())
	require.NoError(t, err)

	_, _, err = runner.Up(context.Background(), false /* dryRun */)
	require.NoError(t, err)

	assert.Equal(t, 1, m.applyCalls, "Apply must be called when not dry-run")
}

func TestRunner_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// A module that cancels the context during Detect so we verify Up stops cleanly.
	cancelMod := &fakeModule{name: "cancel-mod"}
	second := &fakeModule{name: "second-mod"}

	// Wrap cancelMod in a Module that cancels context on Detect.
	cancellingMod := &cancelOnDetect{fakeModule: cancelMod, cancel: cancel}

	runner, err := modules.NewRunner([]modules.Module{cancellingMod, second}, minimalCfg())
	require.NoError(t, err)

	_, _, err = runner.Up(ctx, false)
	// Must return a context error.
	assert.ErrorIs(t, err, context.Canceled)
	// The second module must not have been touched.
	assert.Equal(t, 0, second.detectCalls, "second module must not have been reached")
}

// cancelOnDetect wraps a fakeModule and cancels the context during Detect.
type cancelOnDetect struct {
	*fakeModule
	cancel context.CancelFunc
}

func (c *cancelOnDetect) Detect(ctx context.Context) ([]modules.Finding, error) {
	c.cancel()
	// After cancellation, return normally — the runner checks ctx.Done() between steps.
	return c.fakeModule.Detect(ctx)
}

func TestRunner_DependencyOrder(t *testing.T) {
	order := &[]string{}

	leaf := &fakeModule{
		name:           "leaf",
		actions:        []modules.Action{{Module: "leaf", Description: "leaf action"}},
		executionOrder: order,
	}
	dependent := &fakeModule{
		name:           "dependent",
		deps:           []string{"leaf"},
		actions:        []modules.Action{{Module: "dependent", Description: "dep action"}},
		executionOrder: order,
	}

	runner, err := modules.NewRunner([]modules.Module{dependent, leaf}, minimalCfg())
	require.NoError(t, err)

	_, _, err = runner.Up(context.Background(), false)
	require.NoError(t, err)

	require.Len(t, *order, 2)
	assert.Equal(t, "leaf", (*order)[0], "leaf must be applied before dependent")
	assert.Equal(t, "dependent", (*order)[1])
}

func TestRunner_Doctor(t *testing.T) {
	f1 := modules.Finding{Module: "m1", Check: "check-a", Severity: modules.SeverityOK, Message: "all good"}
	f2 := modules.Finding{Module: "m2", Check: "check-b", Severity: modules.SeverityWarning, Message: "hmm"}

	m1 := &fakeModule{name: "m1", findings: []modules.Finding{f1}}
	m2 := &fakeModule{name: "m2", findings: []modules.Finding{f2}}

	runner, err := modules.NewRunner([]modules.Module{m1, m2}, minimalCfg())
	require.NoError(t, err)

	findings, err := runner.Doctor(context.Background())
	require.NoError(t, err)

	// Doctor calls both Detect and Verify, so each module contributes 2 findings
	// (findings slice is returned from both Detect and Verify on fakeModule).
	assert.Equal(t, 1, m1.detectCalls)
	assert.Equal(t, 1, m1.verifyCalls)
	assert.Equal(t, 1, m2.detectCalls)
	assert.Equal(t, 1, m2.verifyCalls)
	// Each module's finding appears twice (once from Detect, once from Verify).
	assert.Len(t, findings, 4)
}

// TestRunner_ApplyAll_ErrorEmitsFatalFinding is the F-62 regression guard.
// Pre-fix, a module Apply error made ApplyAll return a non-nil error while the
// returned findings carried no SeverityFatal entry, so the CLI final summary
// printed "0 errors" alongside a non-zero exit. ApplyAll must now append a
// Fatal "apply-error" finding for the failing module, keep iterating over the
// remaining modules, return the first error, and still deliver the ApplyErr on
// the failing module's ModuleEvent.
func TestRunner_ApplyAll_ErrorEmitsFatalFinding(t *testing.T) {
	boom := fmt.Errorf("launchctl bootstrap failed")
	// Both modules plan one action: ApplyAll now skips zero-action modules
	// (apply must never exceed the dry-run preview), so the fixtures must
	// plan work for Apply to be attempted at all.
	act := []modules.Action{{Module: "x", Description: "test action"}}
	bad := &fakeModule{name: "bad-mod", applyErr: boom, actions: act}
	good := &fakeModule{name: "good-mod", actions: act}

	runner, err := modules.NewRunner([]modules.Module{bad, good}, minimalCfg())
	require.NoError(t, err)

	var events []modules.ModuleEvent
	findings, applyErr := runner.ApplyAll(context.Background(), func(evt modules.ModuleEvent) {
		events = append(events, evt)
	})

	// The first apply error is returned (wrapped with the module name).
	require.Error(t, applyErr)
	assert.ErrorIs(t, applyErr, boom)
	assert.Contains(t, applyErr.Error(), "bad-mod")

	// All modules are still attempted despite the error.
	assert.Equal(t, 1, bad.applyCalls)
	assert.Equal(t, 1, good.applyCalls)

	// F-62: a Fatal apply-error finding for the failing module must be present
	// so summary renderers count it as an error.
	var fatal *modules.Finding
	for i := range findings {
		if findings[i].Check == "apply-error" {
			fatal = &findings[i]
			break
		}
	}
	require.NotNil(t, fatal, "ApplyAll must append a Fatal apply-error finding when a module's Apply fails (F-62)")
	assert.Equal(t, "bad-mod", fatal.Module)
	assert.Equal(t, modules.SeverityFatal, fatal.Severity)
	assert.Equal(t, boom.Error(), fatal.Message)

	// The ModuleEvent for the failing module still carries ApplyErr as before.
	require.Len(t, events, 2)
	assert.Equal(t, "bad-mod", events[0].Module)
	assert.ErrorIs(t, events[0].ApplyErr, boom)
	assert.NoError(t, events[1].ApplyErr)
}

// TestRunnerDoctor_NoDoubleEmit is the D-02 regression guard asserting that no
// (Module, Check) pair appears more than once across a full runner.Doctor pass.
//
// It uses real lock and ssh module instances (not fakeModule) with MockRunners
// primed to their clean-path responses. Since both Verify methods now return nil
// (Pitfall-4 fix applied in this phase), each check must appear exactly once.
func TestRunnerDoctor_NoDoubleEmit(t *testing.T) {
	t.Helper()

	// ---- lock module: clean path → tailscale lock status returns {"Enabled":true} ----
	lockCfg := config.Defaults()
	lockCfg.Tailnet.Lock.Enabled = true
	lockRunner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`, ExitCode: 0}},
	)
	lockMod := lockmod.New(modules.Deps{Cfg: lockCfg, Runner: lockRunner})

	// ---- ssh module: clean path — platform-specific ----
	// On darwin: systemsetup -getremotelogin → "Remote Login: Off" (sshd correctly off).
	// On linux: systemctl is-active sshd → "inactive".
	// On other platforms the ssh module skips Detect, so a single call placeholder
	// is safe (it will never be consumed).
	sshCfg := config.Defaults()
	sshCfg.Modules.SSH.Enabled = true
	sshCfg.Modules.SSH.Mode = "tailscale"
	sshRunner := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "Remote Login: Off\n", ExitCode: 0}}, // darwin
		shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 0}},          // linux (sshd)
		shell.Call{Result: shell.Result{Stdout: "inactive\n", ExitCode: 0}},          // linux (ssh fallback)
	)
	sshMod := sshmod.New(modules.Deps{Cfg: sshCfg, Runner: sshRunner})

	runner, err := modules.NewRunner([]modules.Module{lockMod, sshMod}, lockCfg)
	require.NoError(t, err)

	allFindings, err := runner.Doctor(context.Background())
	require.NoError(t, err)

	// Build a map["{Module}/{Check}"] → count. Assert every count is exactly 1.
	seen := make(map[string]int, len(allFindings))
	for _, f := range allFindings {
		key := fmt.Sprintf("%s/%s", f.Module, f.Check)
		seen[key]++
	}
	for key, count := range seen {
		assert.Equal(t, 1, count,
			"D-02 violation: (Module/Check) pair %q appears %d times in a single Doctor pass — double-emission regression", key, count)
	}
}
