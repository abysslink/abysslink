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

package watch

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module implements the watch module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the module name.
func (m *Module) Name() string { return "watch" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"notify"} }

// Detect checks whether pane watches are configured.
func (m *Module) Detect(_ context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.cfg.Modules.Watch.Enabled {
		slog.Debug("watch module disabled, skipping detect")
		return nil, nil
	}

	if len(m.cfg.Modules.Watch.Panes) == 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "panes_configured",
			Severity: modules.SeverityWarning,
			Message:  "no panes configured for watching; add entries to modules.watch.panes in abysslink.yaml",
		})
	}

	slog.Debug("watch detect", "panes", m.cfg.Modules.Watch.Panes)
	return findings, nil
}

// Plan computes actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Watch.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		if f.Check == "panes_configured" {
			_ = f // nothing to auto-configure
		}
	}

	// Watches run in abysslinkd; signal that config will be applied.
	if len(m.cfg.Modules.Watch.Panes) > 0 {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "configure pane watchers",
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply is a no-op — watches run inside abysslinkd.
func (m *Module) Apply(_ context.Context) error {
	return fmt.Errorf("watch module: apply not yet implemented — watches run in abysslinkd")
}

// Verify returns nil — there is no out-of-process state to verify.
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair returns nil — nothing to repair externally.
func (m *Module) Repair(_ context.Context) error {
	return nil
}
