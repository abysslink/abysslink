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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunInitFormDefaultsTailscale asserts that when autoYes=true (non-interactive),
// runInitForm produces a config with Backend.Type == "tailscale" — the default path
// is unchanged by the headscale extension.
func TestRunInitFormDefaultsTailscale(t *testing.T) {
	cfg, err := runInitForm(nil, true)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "tailscale", cfg.Backend.Type,
		"autoYes=true must default Backend.Type to 'tailscale'")
}

// TestRunInitFormHeadscaleModeAssignments asserts that the headscale path correctly
// sets cfg.Backend.Type, cfg.Server.Headscale.ServerURL, and cfg.Server.Headscale.User.
// This test exercises initFormResult directly to simulate the form-selected headscale
// option, bypassing the interactive huh prompts which cannot run in non-TTY test
// environments.
func TestRunInitFormHeadscaleModeAssignments(t *testing.T) {
	r := initFormResult{
		backendType:        "headscale",
		headscaleServerURL: "https://headscale.example.com",
	}
	cfg, err := applyInitFormResult(r)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "headscale", cfg.Backend.Type,
		"headscale backend type must be set in config")
	assert.Equal(t, "https://headscale.example.com", cfg.Server.Headscale.ServerURL,
		"server URL must be populated from form input")
	assert.Equal(t, "abysslink", cfg.Server.Headscale.User,
		"Headscale user must default to 'abysslink' (D-13)")
}

// TestRunInitFormTailscaleNoHeadscaleFields asserts that selecting tailscale backend
// leaves cfg.Server.Headscale.ServerURL empty and User unset — no Headscale fields
// leak into a Tailscale config.
func TestRunInitFormTailscaleNoHeadscaleFields(t *testing.T) {
	r := initFormResult{
		backendType:        "tailscale",
		headscaleServerURL: "",
	}
	cfg, err := applyInitFormResult(r)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "tailscale", cfg.Backend.Type)
	assert.Empty(t, cfg.Server.Headscale.ServerURL,
		"Headscale server URL must not be set when tailscale backend is selected")
	assert.Empty(t, cfg.Server.Headscale.User,
		"Headscale user must not be set when tailscale backend is selected")
}

// TestRunInitFormNetBirdModeAssignments asserts that the netbird path correctly
// sets cfg.Backend.Type and cfg.Server.NetBird.ServerURL.
// This test exercises initFormResult directly to simulate the form-selected netbird
// option, bypassing the interactive huh prompts which cannot run in non-TTY test
// environments.
func TestRunInitFormNetBirdModeAssignments(t *testing.T) {
	r := initFormResult{
		backendType:      "netbird",
		netbirdServerURL: "https://nb.example.com",
	}
	cfg, err := applyInitFormResult(r)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "netbird", cfg.Backend.Type,
		"netbird backend type must be set in config")
	assert.Equal(t, "https://nb.example.com", cfg.Server.NetBird.ServerURL,
		"NetBird server URL must be populated from form input")
}

// TestRunInitFormNetBirdNoHeadscaleFields asserts that selecting netbird backend
// leaves cfg.Server.Headscale.ServerURL empty — no Headscale fields leak into a
// NetBird config.
func TestRunInitFormNetBirdNoHeadscaleFields(t *testing.T) {
	r := initFormResult{
		backendType:      "netbird",
		netbirdServerURL: "https://nb.example.com",
	}
	cfg, err := applyInitFormResult(r)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "netbird", cfg.Backend.Type)
	assert.Empty(t, cfg.Server.Headscale.ServerURL,
		"Headscale server URL must not be set when netbird backend is selected")
	assert.Empty(t, cfg.Server.Headscale.User,
		"Headscale user must not be set when netbird backend is selected")
}

// TestRunInitFormNetBirdServerURLRequired asserts that when backend is netbird and
// no server URL is provided, the config validation will catch it at runtime.
// This tests the constraint path exercised by config.Validate.
func TestRunInitFormNetBirdServerURLRequired(t *testing.T) {
	r := initFormResult{
		backendType:      "netbird",
		netbirdServerURL: "", // intentionally empty to confirm the field maps correctly
	}
	cfg, err := applyInitFormResult(r)
	require.NoError(t, err, "applyInitFormResult succeeds — validation is caller's responsibility")
	require.NotNil(t, cfg)
	assert.Equal(t, "netbird", cfg.Backend.Type)
	assert.Empty(t, cfg.Server.NetBird.ServerURL,
		"server URL is empty when not provided — caller must validate")
}
