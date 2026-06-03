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

package lock

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetect_LockEnabled_NoFindings(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "lock is on, config requires it: no findings expected")
}

func TestLockEnabledOK(t *testing.T) {
	// Clean path: lock is enabled and config requires it → expect SeverityOK
	// finding with Check=="lock_enabled".
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":true}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "lock_enabled" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"lock_enabled\" on clean path, got none")
	}
	assert.Equal(t, modules.SeverityOK, found.Severity, "clean path must emit SeverityOK for lock_enabled")
}

func TestDetect_LockDisabled_ConfigRequires_Warning(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: `{"Enabled":false}`}})
	cfg := config.Defaults()
	cfg.Tailnet.Lock.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "lock_enabled", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_NonZeroExit_Warning(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "tailscale not running"}})
	cfg := config.Defaults()
	m := New(modules.Deps{Cfg: cfg, Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "lock_status", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}
