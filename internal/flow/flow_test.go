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

// Package flow_test contains stub tests that define the contract for
// internal/flow. All stubs are skipped until Wave 2 implements the package.
package flow_test

import (
	"testing"
)

// TestStepFuncSignature verifies that a step func returns a non-nil *huh.Form
// without calling .Run() or .RunWithContext() on it. After Wave 2 is
// implemented, this test asserts that flow.StepAccount returns a *huh.Form and
// that the caller — not the step func — is responsible for running it.
func TestStepFuncSignature(t *testing.T) {
	t.Skip("TODO: internal/flow not yet implemented — Wave 2")
}

// TestFlowStateThreading verifies that FlowState is passed by pointer through
// multiple step funcs and that mutations made in one step are visible in
// subsequent steps (D-11: FlowState = pure data).
func TestFlowStateThreading(t *testing.T) {
	t.Skip("TODO: internal/flow not yet implemented — Wave 2")
}

// TestFlowStateNoSecrets asserts — via reflection — that no FlowState field
// name contains "Token", "Code", "Secret", or "Password". This is a security
// regression guard for D-12: captured secrets never live in FlowState fields.
func TestFlowStateNoSecrets(t *testing.T) {
	t.Skip("TODO: internal/flow not yet implemented — Wave 2")
}

// TestResumeMarkerAdvancesOnlyOnSuccess verifies that writeFlowState (the
// resume-marker writer) is called only on explicit step success, and not when
// a step returns an error. This enforces D-10: the resume marker never advances
// past a partially-completed or failed step.
func TestResumeMarkerAdvancesOnlyOnSuccess(t *testing.T) {
	t.Skip("TODO: internal/flow not yet implemented — Wave 2")
}
