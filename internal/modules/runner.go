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

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/abysslink/abysslink/internal/config"
)

// ProgressPhase indicates which phase of execution an event belongs to.
type ProgressPhase int

// Progress phase constants.
const (
	ProgressPhasePlan ProgressPhase = iota
	ProgressPhaseApply
)

// ModuleEvent is emitted by PlanAll and ApplyAll after each module completes
// its phase step.
type ModuleEvent struct {
	Module   string
	Phase    ProgressPhase
	Index    int // 1-based position in the module list
	Total    int // total number of modules
	Actions  []Action
	Findings []Finding
	ApplyErr error
}

// ProgressFunc is a callback invoked after each module completes its phase
// step. Implementations must not panic.
type ProgressFunc func(ModuleEvent)

// Runner orchestrates module execution in dependency order.
type Runner struct {
	modules []Module
	cfg     *config.Config
}

// NewRunner returns a Runner with the given modules and config.
// Modules are sorted into dependency order by TopoSort.
func NewRunner(modules []Module, cfg *config.Config) (*Runner, error) {
	sorted, err := TopoSort(modules)
	if err != nil {
		return nil, fmt.Errorf("module runner: %w", err)
	}
	return &Runner{modules: sorted, cfg: cfg}, nil
}

// Up runs Detect → Plan → Apply → Verify for all modules in dependency order.
// If dryRun is true, Apply is skipped and Plan output is accumulated instead.
// Respects context cancellation between module steps.
func (r *Runner) Up(ctx context.Context, dryRun bool) ([]Action, []Finding, error) {
	var allActions []Action
	var allFindings []Finding

	for _, m := range r.modules {
		// Check for cancellation before each module.
		select {
		case <-ctx.Done():
			return allActions, allFindings, ctx.Err()
		default:
		}

		log := slog.With("module", m.Name())

		// Detect.
		findings, err := m.Detect(ctx)
		if err != nil {
			return allActions, allFindings, fmt.Errorf("module %s detect: %w", m.Name(), err)
		}
		for _, f := range findings {
			log.Info("detect finding", "check", f.Check, "severity", f.Severity, "message", f.Message)
		}
		allFindings = append(allFindings, findings...)

		// Plan.
		actions, err := m.Plan(ctx, dryRun)
		if err != nil {
			return allActions, allFindings, fmt.Errorf("module %s plan: %w", m.Name(), err)
		}
		for _, a := range actions {
			log.Info("planned action", "description", a.Description, "reversible", a.Reversible)
		}
		allActions = append(allActions, actions...)

		// Apply (skipped in dry-run mode).
		if !dryRun && len(actions) > 0 {
			select {
			case <-ctx.Done():
				return allActions, allFindings, ctx.Err()
			default:
			}

			log.Info("applying")
			if err := m.Apply(ctx); err != nil {
				return allActions, allFindings, fmt.Errorf("module %s apply: %w", m.Name(), err)
			}
			log.Info("applied successfully")
		}

		// Verify.
		select {
		case <-ctx.Done():
			return allActions, allFindings, ctx.Err()
		default:
		}

		vFindings, err := m.Verify(ctx)
		if err != nil {
			return allActions, allFindings, fmt.Errorf("module %s verify: %w", m.Name(), err)
		}
		for _, f := range vFindings {
			log.Info("verify finding", "check", f.Check, "severity", f.Severity, "message", f.Message)
		}
		allFindings = append(allFindings, vFindings...)
	}

	return allActions, allFindings, nil
}

// Doctor runs Detect + Verify for all modules and returns all findings.
func (r *Runner) Doctor(ctx context.Context) ([]Finding, error) {
	var allFindings []Finding

	for _, m := range r.modules {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		log := slog.With("module", m.Name())

		findings, err := m.Detect(ctx)
		if err != nil {
			return allFindings, fmt.Errorf("module %s detect: %w", m.Name(), err)
		}
		for _, f := range findings {
			log.Info("doctor detect", "check", f.Check, "severity", f.Severity, "message", f.Message)
		}
		allFindings = append(allFindings, findings...)

		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		vFindings, err := m.Verify(ctx)
		if err != nil {
			return allFindings, fmt.Errorf("module %s verify: %w", m.Name(), err)
		}
		for _, f := range vFindings {
			log.Info("doctor verify", "check", f.Check, "severity", f.Severity, "message", f.Message)
		}
		allFindings = append(allFindings, vFindings...)
	}

	return allFindings, nil
}

// PlanAll runs Detect then Plan for all modules in dependency order, emitting a
// ModuleEvent via progress after each module completes. It returns the combined
// actions and findings. The first error stops iteration.
// If progress is nil, no events are emitted.
func (r *Runner) PlanAll(ctx context.Context, progress ProgressFunc) ([]Action, []Finding, error) {
	var allActions []Action
	var allFindings []Finding
	total := len(r.modules)

	for i, m := range r.modules {
		select {
		case <-ctx.Done():
			return allActions, allFindings, ctx.Err()
		default:
		}

		log := slog.With("module", m.Name())

		// Detect.
		findings, err := m.Detect(ctx)
		if err != nil {
			return allActions, allFindings, fmt.Errorf("module %s detect: %w", m.Name(), err)
		}
		for _, f := range findings {
			log.Info("detect finding", "check", f.Check, "severity", f.Severity, "message", f.Message)
		}
		allFindings = append(allFindings, findings...)

		// Plan.
		actions, err := m.Plan(ctx, true)
		if err != nil {
			return allActions, allFindings, fmt.Errorf("module %s plan: %w", m.Name(), err)
		}
		for _, a := range actions {
			log.Info("planned action", "description", a.Description, "reversible", a.Reversible)
		}
		allActions = append(allActions, actions...)

		if progress != nil {
			progress(ModuleEvent{
				Module:   m.Name(),
				Phase:    ProgressPhasePlan,
				Index:    i + 1,
				Total:    total,
				Actions:  actions,
				Findings: findings,
			})
		}
	}

	return allActions, allFindings, nil
}

// ApplyAll runs Apply then Verify for all modules in dependency order, emitting
// a ModuleEvent via progress after each module completes. Apply errors do not
// stop iteration — all modules are attempted. The first Apply error encountered
// is returned at the end.
// If progress is nil, no events are emitted.
func (r *Runner) ApplyAll(ctx context.Context, progress ProgressFunc) ([]Finding, error) {
	var allFindings []Finding
	var firstApplyErr error
	total := len(r.modules)

	for i, m := range r.modules {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		log := slog.With("module", m.Name())

		// Apply.
		applyErr := m.Apply(ctx)
		if applyErr != nil {
			log.Info("apply error", "error", applyErr)
			if firstApplyErr == nil {
				firstApplyErr = fmt.Errorf("module %s apply: %w", m.Name(), applyErr)
			}
			// F-62: surface the apply error as a Fatal finding so summary
			// renderers that count SeverityFatal (e.g. the CLI final summary)
			// report a non-zero error count consistent with the non-zero exit.
			allFindings = append(allFindings, Finding{
				Module:   m.Name(),
				Check:    "apply-error",
				Severity: SeverityFatal,
				Message:  applyErr.Error(),
			})
		} else {
			log.Info("applied successfully")
		}

		// Verify.
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		vFindings, err := m.Verify(ctx)
		if err != nil {
			return allFindings, fmt.Errorf("module %s verify: %w", m.Name(), err)
		}
		for _, f := range vFindings {
			log.Info("verify finding", "check", f.Check, "severity", f.Severity, "message", f.Message)
		}
		allFindings = append(allFindings, vFindings...)

		if progress != nil {
			progress(ModuleEvent{
				Module:   m.Name(),
				Phase:    ProgressPhaseApply,
				Index:    i + 1,
				Total:    total,
				Findings: vFindings,
				ApplyErr: applyErr,
			})
		}
	}

	return allFindings, firstApplyErr
}

// NOTE: Runner.Down was deleted (NET-15). It documented "Verify then
// Apply(disable)" but called m.Apply — the converge-UP path — for every
// module, so running it would have REINSTALLED everything instead of tearing
// it down. No CLI command referenced it. If module teardown is ever needed,
// design a dedicated disable path per module (TopoSortReverse in registry.go
// already provides the reverse dependency order).
