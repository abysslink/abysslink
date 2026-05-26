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

package modules

import "context"

// Severity classifies the result of a Verify or Detect call.
type Severity int

// Severity level constants ordered from least to most severe.
const (
	SeverityOK      Severity = 0 // passing check
	SeverityWarning Severity = 1 // degraded but non-blocking
	SeverityFatal   Severity = 2 // blocking failure
)

// Finding is a single check result from Detect or Verify.
type Finding struct {
	Module   string
	Check    string
	Severity Severity
	Message  string
}

// Action is a single planned change from Plan.
type Action struct {
	Module      string
	Description string
	Reversible  bool
}

// Result summarises what happened during Apply.
type Result struct {
	Module  string
	Applied []string
	Errors  []error
}

// Module is the interface every abysslink module must satisfy.
type Module interface {
	// Name returns the canonical module name (used in YAML and logs).
	Name() string
	// Deps returns the module names this module depends on (must be applied first).
	Deps() []string
	// Detect inspects the current system state and returns findings.
	// All findings are returned, even if the module is disabled.
	Detect(ctx context.Context) ([]Finding, error)
	// Plan computes the actions needed to reach the desired state.
	// If the module is disabled, Plan returns an empty slice.
	// dryRun=true means Plan must not mutate anything.
	Plan(ctx context.Context, dryRun bool) ([]Action, error)
	// Apply executes the planned changes.
	Apply(ctx context.Context) error
	// Verify confirms that the module's desired state is actually active.
	Verify(ctx context.Context) ([]Finding, error)
	// Repair attempts to fix all non-fatal findings from Verify.
	Repair(ctx context.Context) error
}
