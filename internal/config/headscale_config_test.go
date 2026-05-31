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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
)

// TestHeadscaleServer_DefaultsPopulated asserts that Defaults() populates the
// HeadscaleServer sub-struct with paranoid-safe defaults (HS-01, HS-02 foundation).
func TestHeadscaleServer_DefaultsPopulated(t *testing.T) {
	cfg := config.Defaults()
	hs := cfg.Server.Headscale
	assert.Equal(t, "/usr/local/bin/headscale", hs.BinaryPath,
		"Defaults().Server.Headscale.BinaryPath must be /usr/local/bin/headscale")
	assert.Equal(t, "/etc/headscale/config.yaml", hs.ConfigPath,
		"Defaults().Server.Headscale.ConfigPath must be /etc/headscale/config.yaml")
	assert.Equal(t, "/var/lib/headscale/db.sqlite", hs.DBPath,
		"Defaults().Server.Headscale.DBPath must be /var/lib/headscale/db.sqlite")
	assert.Equal(t, 30, hs.CertExpiryWarnDays,
		"Defaults().Server.Headscale.CertExpiryWarnDays must be 30")
	assert.Equal(t, "1h", hs.PreAuthKeyExpiry,
		"Defaults().Server.Headscale.PreAuthKeyExpiry must be 1h (paranoid-safe default, D-11)")
}

// TestHeadscaleServer_YAMLParsed asserts that all HeadscaleServer fields are
// parseable from YAML (KnownFields strict mode must accept all new fields).
func TestHeadscaleServer_YAMLParsed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "headscale.yaml")
	yaml := `version: 1
identity:
  email: ops@example.com
  unix_user: ops
tailnet:
  hostname: headscale-rig
server:
  headscale:
    server_url: "https://hs.example.com"
    binary_path: "/opt/headscale/bin/headscale"
    config_path: "/opt/headscale/config.yaml"
    db_path: "/opt/headscale/db.sqlite"
    acme: true
    tls_cert_path: "/opt/headscale/tls.crt"
    tls_key_path: "/opt/headscale/tls.key"
    cert_expiry_warn_days: 14
    pre_auth_key_expiry: "2h"
    user: "myuser"
`
	require.NoError(t, os.WriteFile(p, []byte(yaml), 0o600))

	cfg, err := config.Load(p)
	require.NoError(t, err, "KnownFields strict mode must accept all HeadscaleServer fields")

	hs := cfg.Server.Headscale
	assert.Equal(t, "https://hs.example.com", hs.ServerURL)
	assert.Equal(t, "/opt/headscale/bin/headscale", hs.BinaryPath)
	assert.Equal(t, "/opt/headscale/config.yaml", hs.ConfigPath)
	assert.Equal(t, "/opt/headscale/db.sqlite", hs.DBPath)
	assert.True(t, hs.ACME)
	assert.Equal(t, "/opt/headscale/tls.crt", hs.TLSCertPath)
	assert.Equal(t, "/opt/headscale/tls.key", hs.TLSKeyPath)
	assert.Equal(t, 14, hs.CertExpiryWarnDays)
	assert.Equal(t, "2h", hs.PreAuthKeyExpiry)
	assert.Equal(t, "myuser", hs.User)
}

// TestHeadscaleServer_HostnameBackCompat asserts that the existing Hostname
// field in Server still parses correctly — no backward compatibility regression.
func TestHeadscaleServer_HostnameBackCompat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "compat.yaml")
	yaml := `version: 1
identity:
  email: ops@example.com
  unix_user: ops
tailnet:
  hostname: my-rig
server:
  hostname: "headscale.example.com"
`
	require.NoError(t, os.WriteFile(p, []byte(yaml), 0o600))

	cfg, err := config.Load(p)
	require.NoError(t, err)
	assert.Equal(t, "headscale.example.com", cfg.Server.Hostname,
		"Server.Hostname must still parse correctly for backward compatibility")
}
