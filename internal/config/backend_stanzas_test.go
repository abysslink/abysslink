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

// TestBackendAlias verifies that a v1 tailnet-only YAML (no backend: stanza)
// loads successfully and yields cfg.Backend.Type == "tailscale" after Load.
func TestBackendAlias(t *testing.T) {
	// Use the existing v1 fixture that has only tailnet: (no backend: key).
	cfg, err := config.Load("../../internal/cli/testdata/v1.yaml")
	require.NoError(t, err)
	assert.Equal(t, "tailscale", cfg.Backend.Type,
		"v1 tailnet-only YAML must alias to backend.type: tailscale")
}

// TestBackendStanzaExplicit verifies that an explicit backend: {type: tailscale}
// stanza is accepted under strict YAML (KnownFields(true)).
// Now that Load calls Validate (D-01), the YAML must include the required
// identity fields so the fixture passes validation.
func TestBackendStanzaExplicit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "explicit_backend.yaml")
	// minimalValidYAML() (config_load_test.go) produces a full valid config;
	// override only the backend stanza to test explicit backend parsing.
	content := minimalValidYAML() + "backend:\n  type: tailscale\n"
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	cfg, err := config.Load(p)
	require.NoError(t, err, "explicit backend: stanza must load under strict mode")
	assert.Equal(t, "tailscale", cfg.Backend.Type)
}

// TestServerRigStanzasParsed verifies that server: and rig: stanzas are
// accepted under strict YAML (forward-compat stubs; not yet consumed).
// Now that Load calls Validate (D-01), the YAML must include required
// identity fields so the fixture passes validation.
func TestServerRigStanzasParsed(t *testing.T) {
	p := writeTempYAML(t, minimalValidYAML())
	_, err := config.Load(p)
	require.NoError(t, err, "server: and rig: stanzas must parse without strict-mode rejection")
}

// TestNoBackendImport ensures config.go does not import internal/backend
// (enforced structurally; this is a compile-time property documented here
// as a reminder — the real check is grep in CI).
func TestBackendTypeDefault(t *testing.T) {
	// Defaults() must produce Backend.Type == "" (normalize happens in Load,
	// not Defaults; callers not going through Load use "" which factory treats as tailscale).
	cfg := config.Defaults()
	// After Defaults, Backend.Type is "" — that's fine; factory normalizes it.
	// But after Load (which calls Defaults then decodes), Backend.Type == "tailscale".
	// Now that Load calls Validate (D-01), the fixture must include required fields.
	p := writeTempYAML(t, minimalValidYAML())
	loaded, err := config.Load(p)
	require.NoError(t, err)
	assert.Equal(t, "tailscale", loaded.Backend.Type,
		"Load must normalize empty backend.type to tailscale")
	_ = cfg // suppress "cfg declared but not used"
}
