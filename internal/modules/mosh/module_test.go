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

package mosh

import (
	"context"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetect_MoshNotInstalled_Warning(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 127, Stderr: "command not found"}})
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "installed", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

func TestDetect_MoshInstalled_NoFindings(t *testing.T) {
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "mosh-server (mosh 1.4.0)\n"}})
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDetect_MoshVersionInStderr_NoFindings(t *testing.T) {
	// Some versions of mosh-server print version to stderr and exit non-zero.
	r := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "mosh 1.3.2 [build mosh 1.3.2]"}})
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "stderr contains 'mosh', should not flag as missing")
}
