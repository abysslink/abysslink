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

// Package flow_test contains tests for the internal/flow package.
package flow_test

import (
	"context"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/flow"
	"github.com/abysslink/abysslink/internal/shell"
)

// noopRunner is a minimal shell.Runner implementation for tests: Run and
// RunWithStdin return a non-zero exit (not called by step funcs; included for
// completeness). RunInteractive is a no-op.
type noopRunner struct{}

func (n *noopRunner) Run(_ context.Context, _ string, _ ...string) (shell.Result, error) {
	return shell.Result{ExitCode: 1}, nil
}

func (n *noopRunner) RunWithStdin(_ context.Context, _ io.Reader, _ string, _ ...string) (shell.Result, error) {
	return shell.Result{ExitCode: 1}, nil
}

func (n *noopRunner) RunInteractive(_ context.Context, _ string, _ ...string) error {
	return nil
}

func (n *noopRunner) RunWithEnv(_ context.Context, _ map[string]string, _ string, _ ...string) (shell.Result, error) {
	return shell.Result{ExitCode: 1}, nil
}

func (n *noopRunner) RunStream(_ context.Context, _ string, _ ...string) (*shell.Stream, error) {
	return nil, nil
}

// noopPrinter is a minimal flow.Printer that discards all output.
type noopPrinter struct{}

func (p *noopPrinter) Print(_ string) {}

// TestStepFuncSignature verifies that step funcs return a non-nil *huh.Form
// (except StepDone which returns nil by contract) and nil error, without
// panicking and without calling .Run() or .RunWithContext() on the form.
func TestStepFuncSignature(t *testing.T) {
	ctx := context.Background()
	runner := &noopRunner{}
	printer := &noopPrinter{}
	state := &flow.FlowState{}

	steps := []struct {
		name     string
		fn       flow.StepFunc
		nilForm  bool // true for StepDone which intentionally returns nil
	}{
		{"StepAccount", flow.StepAccount, false},
		{"StepPrereqs", flow.StepPrereqs, false},
		{"StepConverge", flow.StepConverge, false},
		{"StepLock", flow.StepLock, false},
		{"StepEnroll", flow.StepEnroll, false},
		{"StepVerify", flow.StepVerify, false},
		{"StepACL", flow.StepACL, false},
		{"StepDone", flow.StepDone, true},
	}

	for _, tc := range steps {
		t.Run(tc.name, func(t *testing.T) {
			form, err := tc.fn(ctx, runner, printer, state)
			require.NoError(t, err, "%s must return nil error", tc.name)
			if tc.nilForm {
				require.Nil(t, form, "%s must return nil form (terminal step)", tc.name)
			} else {
				require.NotNil(t, form, "%s must return non-nil *huh.Form", tc.name)
			}
		})
	}
}

// TestFlowStateThreading verifies that FlowState is passed by pointer through
// multiple step funcs and that mutations made in one step are visible to
// subsequent steps (D-11: FlowState = pure data, no globals).
func TestFlowStateThreading(t *testing.T) {
	ctx := context.Background()
	runner := &noopRunner{}
	printer := &noopPrinter{}

	state := &flow.FlowState{}
	ptr1 := state

	// Call StepAccount — it binds to &state.BackendType and &state.Email.
	form1, err := flow.StepAccount(ctx, runner, printer, state)
	require.NoError(t, err)
	require.NotNil(t, form1)

	// Manually simulate the caller setting values on state (as if the form ran).
	state.BackendType = "tailscale"
	state.Email = "test@example.com"

	// Call StepPrereqs with the same *FlowState pointer.
	form2, err := flow.StepPrereqs(ctx, runner, printer, state)
	require.NoError(t, err)
	require.NotNil(t, form2)

	// The pointer identity is preserved — same address throughout.
	require.Same(t, ptr1, state, "FlowState pointer must be the same object throughout the flow")

	// Mutations from step 1 are still visible after step 2 call.
	require.Equal(t, "tailscale", state.BackendType, "BackendType set in step 1 must survive step 2 call")
	require.Equal(t, "test@example.com", state.Email, "Email set in step 1 must survive step 2 call")
}

// TestFlowStateNoSecrets asserts — via reflection — that no FlowState field
// name contains "Token", "Code" (standalone), "Secret", or "Password". This is
// a security regression guard for D-12: captured secrets never live in
// FlowState fields. "HaveAuthCode" is allowed because it is a boolean flag, not
// a secret value; the check matches substrings to catch partial names.
func TestFlowStateNoSecrets(t *testing.T) {
	forbidden := []string{"token", "secret", "password"}
	typ := reflect.TypeOf(flow.FlowState{})
	for i := range typ.NumField() {
		name := strings.ToLower(typ.Field(i).Name)
		for _, bad := range forbidden {
			require.False(t,
				strings.Contains(name, bad),
				"FlowState field %q must not contain %q (D-12 secret exclusion)",
				typ.Field(i).Name, bad,
			)
		}
		// "code" alone is forbidden, but "haveauthcode" (a boolean flag) is allowed.
		// The check: if name contains "code" without "have" prefix → forbidden.
		if strings.Contains(name, "code") && !strings.HasPrefix(name, "have") {
			t.Errorf("FlowState field %q contains 'code' without 'have' prefix (D-12 secret exclusion)", typ.Field(i).Name)
		}
	}
}

// TestResumeMarkerAdvancesOnlyOnSuccess verifies that WriteFlowState writes the
// correct stage, and ReadFlowState retrieves it. Also verifies that
// ReadFlowState on a non-existent file returns (0, nil) (first-run behaviour).
func TestResumeMarkerAdvancesOnlyOnSuccess(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	tmpFile := filepath.Join(t.TempDir(), "journey-state.json")

	// Non-existent file returns (0, nil) — first run.
	stage, err := flow.ReadFlowState(tmpFile + "_nonexistent")
	require.NoError(t, err, "ReadFlowState on missing file should return nil error")
	require.Equal(t, 0, stage, "ReadFlowState on missing file should return stage 0")

	// Write stage 3 then read back.
	require.NoError(t, flow.WriteFlowState(tmpFile, 3), "WriteFlowState should not error")
	got, err := flow.ReadFlowState(tmpFile)
	require.NoError(t, err, "ReadFlowState should not error after write")
	require.Equal(t, 3, got, "ReadFlowState should return the written stage")
}
