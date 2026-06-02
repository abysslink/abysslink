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

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

// Deps is the dependency bundle injected into every module constructor. It
// centralises the parsed config, shell runner, platform facade, keychain store,
// and audit writer so modules never construct system-access primitives
// themselves. Fields may be nil only where a module is known not to need them
// (e.g. Keychain when no keychain backend is available); modules that require a
// dependency must nil-check and return a clear error rather than panicking.
type Deps struct {
	Cfg      *config.Config
	Runner   shell.Runner
	Backend  backend.Client
	Platform platform.Platform
	Keychain secrets.KeychainStore
	Audit    audit.AuditWriter
	// Registry is the metrics sink for all modules. Use NoopRegistry when
	// metrics are disabled or unavailable — modules must call Registry methods
	// unconditionally (never nil-check before calling).
	Registry metrics.Registry
	// Prompt displays msg to the user and blocks until they press Enter. It is
	// wired by the CLI layer (the only layer allowed to write to stdout), so
	// modules can trigger interactive pauses without violating the no-stdout-in-
	// library-code rule. Nil means no-op (tests, non-interactive contexts).
	Prompt func(ctx context.Context, msg string) error
}

// MetricsRegistry returns d.Registry, or a NoopRegistry when the field is nil.
// Modules call this instead of touching d.Registry directly so a zero-value
// Deps (tests, callers that have not wired metrics) behaves as if a nil-safe
// NoopRegistry were present — metrics calls are always safe to make.
func (d Deps) MetricsRegistry() metrics.Registry {
	if d.Registry == nil {
		return metrics.NoopRegistry{}
	}
	return d.Registry
}
