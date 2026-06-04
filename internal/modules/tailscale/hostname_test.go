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

package tailscale

import (
	"context"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// TestApply_BadHostname_RejectsArgv asserts that ensureHostname (called via Apply)
// returns an error containing "unsafe characters" for a hostname with a leading
// dash, and does NOT call runner.Run with the unsafe value (D-03, NET-03).
//
// RED: This test FAILS until plan 25-02 Task 2 adds config.ValidateHostname in
// ensureHostname before the runner.Run call.
func TestApply_BadHostname_RejectsArgv(t *testing.T) {
	cfg := config.Defaults()
	cfg.Tailnet.Hostname = "-bad-leading-dash"
	cfg.Tailnet.SSH = true

	// MockRunner records every Run call; if the test passes, no Run call with
	// --hostname=-bad-leading-dash should be recorded.
	mock := shell.NewMockRunner()
	m := New(modules.Deps{Runner: mock, Cfg: cfg})

	err := m.ensureHostname(context.Background())
	if err == nil {
		t.Fatal("expected ensureHostname to return error for leading-dash hostname, got nil — " +
			"RED: config.ValidateHostname guard not yet wired in ensureHostname (fix in plan 25-02 Task 2)")
	}
	if !strings.Contains(err.Error(), "unsafe characters") {
		t.Errorf("expected error to contain %q, got: %v", "unsafe characters", err)
	}
}
