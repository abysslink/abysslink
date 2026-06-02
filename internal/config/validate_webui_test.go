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

package config_test

import (
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validWebUIBaseConfig returns a Config that passes the top-level Validate so
// each TestValidateWebUI sub-case isolates the webui-specific behaviour.
func validWebUIBaseConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Version = 1
	cfg.Identity.Email = "a@b.com"
	cfg.Identity.UnixUser = "user"
	cfg.Tailnet.Hostname = "host"
	return cfg
}

func TestValidateWebUI(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*config.Config)
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "nil when disabled (zero value)",
			mutate:  func(c *config.Config) { c.WebUI.Enabled = false },
			wantErr: false,
		},
		{
			name: "nil when enabled with valid tailnet ip bind addr",
			mutate: func(c *config.Config) {
				c.WebUI.Enabled = true
				c.WebUI.ReadOnly = true
				c.WebUI.BindAddr = "100.64.0.1:8443"
			},
			wantErr: false,
		},
		{
			name: "rejects 0.0.0.0 bind addr",
			mutate: func(c *config.Config) {
				c.WebUI.Enabled = true
				c.WebUI.ReadOnly = true
				c.WebUI.BindAddr = "0.0.0.0:8443"
			},
			wantErr:   true,
			errSubstr: "WEB-02",
		},
		{
			name: "rejects double colon bind addr",
			mutate: func(c *config.Config) {
				c.WebUI.Enabled = true
				c.WebUI.ReadOnly = true
				c.WebUI.BindAddr = "::"
			},
			wantErr:   true,
			errSubstr: "WEB-02",
		},
		{
			name: "rejects read_only false when enabled",
			mutate: func(c *config.Config) {
				c.WebUI.Enabled = true
				c.WebUI.ReadOnly = false
			},
			wantErr:   true,
			errSubstr: "WEB-02",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validWebUIBaseConfig()
			tc.mutate(cfg)
			err := config.ValidateWebUI(cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidateWebUIPropagatedByValidate proves the top-level Validate wires in
// ValidateWebUI (sixth behaviour case).
func TestValidateWebUIPropagatedByValidate(t *testing.T) {
	cfg := validWebUIBaseConfig()
	cfg.WebUI.Enabled = true
	cfg.WebUI.ReadOnly = false
	err := config.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WEB-02")
}

func TestDefaultsWebUI(t *testing.T) {
	cfg := config.Defaults()
	assert.False(t, cfg.WebUI.Enabled, "webui must default OFF")
	assert.True(t, cfg.WebUI.ReadOnly, "webui.read_only must default true")
	assert.Equal(t, 8443, cfg.WebUI.Port, "webui.port must default 8443")
}
