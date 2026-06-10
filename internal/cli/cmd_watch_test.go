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

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// writeWatchCfg writes a valid config with the given pane watchers and returns its path.
func writeWatchCfg(t *testing.T, panes ...string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	cfg.Modules.Watch.Panes = panes
	if len(panes) > 0 {
		cfg.Modules.Watch.Enabled = true
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))
	return cfgPath
}

// runWatch executes the watch command via the real root command tree.
func runWatch(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"watch"}, args...))
	err := root.Execute()
	return out.String(), err
}

// TestWatchAdd_DryRunDefault_NoWrite asserts the CLI-03 gate: without --apply,
// `watch add` prints a [plan] preview and writes nothing.
func TestWatchAdd_DryRunDefault_NoWrite(t *testing.T) {
	cfgPath := writeWatchCfg(t)
	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	out, err := runWatch(t, "add", "--pane", "dev", "--config", cfgPath)
	require.NoError(t, err)
	assert.Contains(t, out, "[plan] would add tmux pane watcher dev")

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "dry-run must not modify config")
}

// TestWatchAdd_Apply_Writes asserts that --apply persists the watcher and
// enables the watch module.
func TestWatchAdd_Apply_Writes(t *testing.T) {
	cfgPath := writeWatchCfg(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir()) // keep audit/backup writes inside the test sandbox

	out, err := runWatch(t, "add", "--pane", "dev", "--config", cfgPath, "--apply")
	require.NoError(t, err)
	assert.Contains(t, out, "add tmux pane watcher dev")
	assert.NotContains(t, out, "[plan]")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, cfg.Modules.Watch.Panes, "dev")
	assert.True(t, cfg.Modules.Watch.Enabled, "watch module must be enabled when a watcher exists")
}

// TestWatchRemove_DryRunDefault_NoWrite asserts the CLI-03 gate for remove.
func TestWatchRemove_DryRunDefault_NoWrite(t *testing.T) {
	cfgPath := writeWatchCfg(t, "dev")

	out, err := runWatch(t, "remove", "--pane", "dev", "--config", cfgPath)
	require.NoError(t, err)
	assert.Contains(t, out, "[plan] would remove pane watcher dev")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, cfg.Modules.Watch.Panes, "dev", "dry-run must not remove the watcher")
}

// TestWatchRemove_Apply_Removes asserts that --apply removes an existing watcher.
func TestWatchRemove_Apply_Removes(t *testing.T) {
	cfgPath := writeWatchCfg(t, "dev")
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	_, err := runWatch(t, "remove", "--pane", "dev", "--config", cfgPath, "--apply")
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.NotContains(t, cfg.Modules.Watch.Panes, "dev")
}

// TestWatchRemove_MissingTarget_Error asserts CLI-03: removing a watcher that
// does not exist is an error, never a silent success.
func TestWatchRemove_MissingTarget_Error(t *testing.T) {
	cfgPath := writeWatchCfg(t, "dev")

	// Pane that is not configured.
	_, err := runWatch(t, "remove", "--pane", "ghost", "--config", cfgPath, "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no pane watcher")

	// File watcher that is not configured.
	_, err = runWatch(t, "remove", "--file", "/no/such.log", "--config", cfgPath, "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no file watcher")

	// HTTP watcher that is not configured.
	_, err = runWatch(t, "remove", "--http", "https://example.com", "--config", cfgPath, "--apply")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no HTTP watcher")

	// The dry-run path must surface the same error (validation runs before the gate).
	_, err = runWatch(t, "remove", "--pane", "ghost", "--config", cfgPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no pane watcher")
}

// TestWatchList_MissingConfig_Degrades asserts CLI-23: `watch list` with no
// config file degrades to defaults and reports "No watchers configured."
func TestWatchList_MissingConfig_Degrades(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	out, err := runWatch(t, "list", "--config", missing)
	require.NoError(t, err, "watch list must not hard-fail on a missing config")
	assert.Contains(t, out, "No watchers configured.")
}

// TestWatchAdd_DuplicatePaneRejected asserts that adding a pane watcher that is
// already configured errors instead of registering a duplicate (which would
// fire duplicate notifications for every event).
func TestWatchAdd_DuplicatePaneRejected(t *testing.T) {
	cfgPath := writeWatchCfg(t, "dev")
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	_, err := runWatch(t, "add", "--pane", "dev", "--config", cfgPath, "--apply")
	require.Error(t, err, "duplicate pane watcher must be rejected")
	assert.Contains(t, err.Error(), "already configured")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	count := 0
	for _, pn := range cfg.Modules.Watch.Panes {
		if pn == "dev" {
			count++
		}
	}
	assert.Equal(t, 1, count, "the pane must not be registered twice")
}

// TestWatchRemove_LastWatcherDisablesModule asserts that removing the LAST
// watcher flips watch.enabled back to false — a lingering enabled:true with
// zero watchers is a config lie.
func TestWatchRemove_LastWatcherDisablesModule(t *testing.T) {
	cfgPath := writeWatchCfg(t, "dev")
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	_, err := runWatch(t, "remove", "--pane", "dev", "--config", cfgPath, "--apply")
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	assert.Empty(t, cfg.Modules.Watch.Panes)
	assert.False(t, cfg.Modules.Watch.Enabled,
		"removing the last watcher must set watch.enabled to false")
}
