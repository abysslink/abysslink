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

package hardening

import (
	"context"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// Module implements the hardening module.
// Platform-specific detection is delegated to detect_darwin.go and detect_linux.go.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the module name.
func (m *Module) Name() string { return "hardening" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{} }

// Detect inspects OS hardening state via platform-specific helpers.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	return detectPlatform(ctx, m)
}

// Plan returns no actions — hardening module reports but does not auto-fix.
func (m *Module) Plan(_ context.Context, _ bool) ([]modules.Action, error) {
	return nil, nil
}

// Apply is intentionally a no-op — the doctor command surfaces findings instead.
func (m *Module) Apply(_ context.Context) error {
	return nil
}

// Verify runs the same checks as Detect.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return detectPlatform(ctx, m)
}

// Repair is a no-op — hardening issues require manual operator action.
func (m *Module) Repair(_ context.Context) error {
	return nil
}
