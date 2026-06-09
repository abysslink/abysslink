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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// writeDaemonCfg writes a valid config and returns its path.
func writeDaemonCfg(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))
	return cfgPath
}

// TestDaemonLifecycle_DryRunDefault asserts the CLI-07 gate: without --apply,
// daemon start/stop/enable/disable print a [plan] preview and execute NOTHING.
// The zero-scripted MockRunner errors on any external command, so a NoError
// result proves no launchctl/systemctl call was made.
func TestDaemonLifecycle_DryRunDefault(t *testing.T) {
	origNewRunner := newRunner
	newRunner = func() shell.Runner { return shell.NewMockRunner() }
	t.Cleanup(func() { newRunner = origNewRunner })

	cfgPath := writeDaemonCfg(t)

	cases := []struct {
		sub  string
		want string
	}{
		{"start", "[plan] would start the daemon"},
		{"stop", "[plan] would stop the daemon"},
		{"enable", "[plan] would install and start the daemon at login"},
		{"disable", "[plan] would stop and remove the daemon login service"},
	}
	for _, tc := range cases {
		root := buildRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"daemon", tc.sub, "--config", cfgPath})

		err := root.Execute()
		require.NoError(t, err, "daemon %s dry-run must not error (and must not shell out)", tc.sub)
		assert.Contains(t, out.String(), tc.want, "daemon %s must print a plan preview", tc.sub)
		assert.Contains(t, out.String(), "--apply", "daemon %s preview must point at --apply", tc.sub)
	}
}
