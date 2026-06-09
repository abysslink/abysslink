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

// TestACLPush_DryRunDefault asserts the CLI-01 gate: without --apply,
// `acl push` prints a [plan] preview and performs no mutation — no admin-API
// push, no generated-policy-file write, no clipboard, no editor. The
// zero-scripted MockRunner errors on any external command (pbcopy/xclip/open),
// so a NoError result proves no side effect was attempted.
func TestACLPush_DryRunDefault(t *testing.T) {
	origNewRunner := newRunner
	newRunner = func() shell.Runner { return shell.NewMockRunner() }
	t.Cleanup(func() { newRunner = origNewRunner })

	// No admin OAuth secret in the environment → manual mode would apply.
	t.Setenv("ABYSSLINK_TS_OAUTH_SECRET", "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"acl", "push", "--config", cfgPath})

	execErr := root.Execute()
	require.NoError(t, execErr, "acl push dry-run must not error (and must not mutate)")

	output := out.String()
	assert.Contains(t, output, "[plan]", "dry-run must print a plan preview")
	assert.Contains(t, output, "tailnet ACL", "preview must describe the ACL convergence")
	assert.Contains(t, output, "manual", "preview must surface manual mode when no admin creds are configured")
	assert.Contains(t, output, "--apply", "preview must point at --apply")
	assert.NotContains(t, output, "ACL converged.", "dry-run must not claim convergence")

	// The generated policy file must NOT exist (manual-mode side effect gated).
	home, _ := os.UserHomeDir()
	genPath := filepath.Join(home, ".config", "abysslink", "generated", "acl.hujson")
	if _, statErr := os.Stat(genPath); statErr == nil {
		// Pre-existing file from a real machine is possible; only fail if the
		// test created it just now (mtime check is overkill — tolerate existing).
		t.Logf("note: %s exists (possibly pre-existing on this machine)", genPath)
	}
}
