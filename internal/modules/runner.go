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

// Down runs modules in reverse dependency order, calling Verify then Apply(disable).
func (r *Runner) Down(ctx context.Context) error {
	reversed, err := TopoSortReverse(r.modules)
	if err != nil {
		return fmt.Errorf("module runner down: %w", err)
	}

	for _, m := range reversed {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log := slog.With("module", m.Name())

		findings, err := m.Verify(ctx)
		if err != nil {
			return fmt.Errorf("module %s verify: %w", m.Name(), err)
		}
		for _, f := range findings {
			log.Info("down verify", "check", f.Check, "severity", f.Severity, "message", f.Message)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Info("bringing down")
		if err := m.Apply(ctx); err != nil {
			return fmt.Errorf("module %s apply (down): %w", m.Name(), err)
		}
		log.Info("brought down successfully")
	}

	return nil
}
