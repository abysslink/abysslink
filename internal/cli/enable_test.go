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

package cli

import (
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetModuleEnabled(t *testing.T) {
	cfg := config.Defaults()

	require.NoError(t, setModuleEnabled(cfg, "claudecode", true))
	assert.True(t, cfg.ClaudeCode.Enabled)

	require.NoError(t, setModuleEnabled(cfg, "code-server", true))
	assert.True(t, cfg.Modules.CodeServer.Enabled)

	// Alias resolves to the same field.
	require.NoError(t, setModuleEnabled(cfg, "et", true))
	assert.True(t, cfg.Modules.EternalTerminal.Enabled)

	require.NoError(t, setModuleEnabled(cfg, "ttyd", false))
	assert.False(t, cfg.Modules.Ttyd.Enabled)

	assert.Error(t, setModuleEnabled(cfg, "nonsense", true))
}
