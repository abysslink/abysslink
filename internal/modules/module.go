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
	// Explain is an optional human-readable rationale for the action.
	// Empty string means no explain text is shown.
	Explain    string
	Reversible bool
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
	// Most modules return nil findings when they are disabled in config
	// (doctor reports only what the user opted into); modules whose checks
	// are not gated by their own config section (e.g. claudecode's keychain
	// probe, lock's tailnet-wide state) may still emit findings while
	// disabled. Detect must never mutate system state either way.
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

// Teardowner is an OPTIONAL interface a module implements when it creates
// non-file resources — a Docker container, a running daemon, a registered
// service — that abysslink's file-backup reversal (uninstall) cannot undo.
// `uninstall` type-asserts every module for this interface and, after reversing
// file mutations, calls Teardown on those that implement it.
//
// Teardown must be best-effort and idempotent: a resource that is already gone
// is success (return no items, no error), and a missing prerequisite (e.g.
// Docker not installed) is not an error. When dryRun is true it must not mutate
// anything and only report what it would remove. The returned strings are
// human-readable resource identifiers for display, e.g.
// "docker container abysslink-ntfy".
type Teardowner interface {
	Teardown(ctx context.Context, dryRun bool) ([]string, error)
}

// ConfigReverter is an OPTIONAL interface a module implements when it MERGES
// into a shared, user-owned config file (e.g. ~/.claude/settings.json) instead
// of owning the whole file. On uninstall such a module removes ONLY its own
// additions, preserving edits the user made after install — far safer than the
// audit log's whole-file restore/delete, which would roll the file back to its
// pre-abysslink state (or delete it outright) and lose those edits.
//
// uninstall (1) collects OwnedPaths from every ConfigReverter and EXCLUDES them
// from the generic whole-file audit reversal, then (2) calls ReverseConfig to do
// the surgical removal. ReverseConfig must be best-effort and idempotent: a file
// already clean or missing returns no items and no error. When dryRun is true it
// must not mutate anything and only report what it would remove. The returned
// strings are human-readable descriptors of what was (or would be) removed.
type ConfigReverter interface {
	// OwnedPaths returns the absolute paths this module reverses surgically, so
	// uninstall can exclude them from whole-file restore/delete.
	OwnedPaths() []string
	ReverseConfig(ctx context.Context, dryRun bool) ([]string, error)
}
