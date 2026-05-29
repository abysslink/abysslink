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

func TestOptionalACLPorts_DefaultConfig(t *testing.T) {
	// ntfy tcp/2586 is now part of the default ACL grant (not optional).
	// Default config with only ntfy enabled should produce no optional-ACL reminder.
	cfg := config.Defaults()
	cfg.Modules.CodeServer.Enabled = false
	cfg.Modules.Ttyd.Enabled = false
	cfg.Modules.EternalTerminal.Enabled = false
	cfg.Modules.Syncthing.Enabled = false
	cfg.Modules.Upsnap.Enabled = false
	ports := optionalACLPorts(cfg)
	for _, p := range ports {
		assert.NotEqual(t, "ntfy", p.module, "ntfy is in the default grant; must not appear as optional ACL port")
	}
}

func TestOptionalACLPorts_AllDisabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Ntfy.Enabled = false
	cfg.Modules.CodeServer.Enabled = false
	cfg.Modules.Ttyd.Enabled = false
	cfg.Modules.EternalTerminal.Enabled = false
	ports := optionalACLPorts(cfg)
	assert.Empty(t, ports, "all optional modules disabled: no ACL reminder needed")
}

func TestOptionalACLPorts_CodeServerAndTtyd(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Ntfy.Enabled = false
	cfg.Modules.CodeServer.Enabled = true
	cfg.Modules.Ttyd.Enabled = true
	cfg.Modules.EternalTerminal.Enabled = false
	ports := optionalACLPorts(cfg)
	require.Len(t, ports, 2)

	portMap := map[string]string{}
	for _, p := range ports {
		portMap[p.module] = p.port
	}
	assert.Equal(t, "tcp/8080", portMap["code-server"])
	assert.Equal(t, "tcp/7681", portMap["ttyd"])
}

func TestOptionalACLPorts_EternalTerminal(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Ntfy.Enabled = false
	cfg.Modules.EternalTerminal.Enabled = true
	ports := optionalACLPorts(cfg)
	require.Len(t, ports, 1)
	assert.Equal(t, "eternal-terminal", ports[0].module)
	assert.Equal(t, "tcp/2022", ports[0].port)
}
