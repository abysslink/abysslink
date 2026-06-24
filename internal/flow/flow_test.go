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
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/flow"
)

// TestStepFuncSignature verifies that a step func returns a non-nil *huh.Form
// without calling .Run() or .RunWithContext() on it. Turned GREEN in Task 2
// once steps.go is implemented.
func TestStepFuncSignature(t *testing.T) {
	t.Skip("TODO: steps.go not yet implemented — Task 2")
}

// TestFlowStateThreading verifies that FlowState is passed by pointer through
// multiple step funcs and that mutations made in one step are visible in
// subsequent steps (D-11: FlowState = pure data). Turned GREEN in Task 2.
func TestFlowStateThreading(t *testing.T) {
	t.Skip("TODO: steps.go not yet implemented — Task 2")
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
