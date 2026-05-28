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

//go:build darwin

package hardening

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckFileVault_FatalWhenOff(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "FileVault is Off.\n"}})
	m := &Module{runner: r}
	findings, err := checkFileVault(context.Background(), m)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "filevault", findings[0].Check)
	assert.Equal(t, modules.SeverityFatal, findings[0].Severity)
}

func TestCheckFileVault_NilWhenOn(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "FileVault is On.\n"}})
	m := &Module{runner: r}
	findings, err := checkFileVault(context.Background(), m)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckFirewall_WarnWhenDisabled(t *testing.T) {
	json := `{"SPFirewallDataType":[{"spfw_global_state":"disabled"}]}`
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: json}})
	m := &Module{runner: r}
	findings, err := checkFirewall(context.Background(), m)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "firewall", findings[0].Check)
}

func TestCheckFirewall_NilWhenEnabled(t *testing.T) {
	json := `{"SPFirewallDataType":[{"spfw_global_state":"enabled"}]}`
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: json}})
	m := &Module{runner: r}
	findings, err := checkFirewall(context.Background(), m)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
