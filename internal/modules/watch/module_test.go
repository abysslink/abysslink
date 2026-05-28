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
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enabledNoPanes() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Watch.Enabled = true
	cfg.Modules.Watch.Panes = nil
	return cfg
}

func enabledWithPanes() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Watch.Enabled = true
	cfg.Modules.Watch.Panes = []string{"main"}
	return cfg
}

func TestDetect_NoPanesConfigured_Warning(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledNoPanes(), Runner: shell.NewMockRunner()})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "panes_configured", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_PanesConfigured_NoFindings(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledWithPanes(), Runner: shell.NewMockRunner()})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDetect_Disabled_NoFindings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Watch.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestPlan_Disabled_ReturnsNil(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Watch.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	assert.Nil(t, actions)
}

func TestPlan_PanesConfigured_ReturnsAction(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledWithPanes(), Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, "watch", actions[0].Module)
}

func TestPlan_NoPanes_ReturnsEmpty(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledNoPanes(), Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	assert.Empty(t, actions)
}

func TestApply_AlwaysNil(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledWithPanes(), Runner: shell.NewMockRunner()})
	require.NoError(t, m.Apply(context.Background()))
}

func TestVerify_AlwaysNilFindings(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledWithPanes(), Runner: shell.NewMockRunner()})
	findings, err := m.Verify(context.Background())
	require.NoError(t, err)
	assert.Nil(t, findings)
}
