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

package acl

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module implements the acl module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the module name.
func (m *Module) Name() string { return "acl" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect checks whether admin API credentials are configured.
func (m *Module) Detect(_ context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	// The ACL module requires a Tailscale admin API key to apply changes.
	// For now, detect whether the relevant identity fields are configured.
	if m.cfg.Identity.Email == "" {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "admin_credentials",
			Severity: modules.SeverityWarning,
			Message:  "identity.email not configured — admin API credentials cannot be derived",
		})
	}

	slog.Debug("acl detect", "email", m.cfg.Identity.Email)
	return findings, nil
}

// Plan computes actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action

	// If credentials are not configured, we can't do much.
	credsMissing := false
	for _, f := range findings {
		if f.Check == "admin_credentials" {
			credsMissing = true
		}
	}

	if !credsMissing {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "ensure tag owners, grants, SSH rules in tailnet ACL",
			Reversible:  false,
		})
	}

	return actions, nil
}

// Apply executes planned changes.
func (m *Module) Apply(_ context.Context) error {
	return fmt.Errorf("acl module: apply not yet implemented")
}

// Verify returns nil — we cannot verify ACL state without making an admin API call.
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
