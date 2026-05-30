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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeClaudeSettings writes a settings.json file into dir/.claude/settings.json.
func writeClaudeSettings(t *testing.T, dir string, v interface{}) string {
	t.Helper()
	claudeDir := filepath.Join(dir, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o750))
	data, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	data = append(data, '\n')
	p := filepath.Join(claudeDir, "settings.json")
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

// abysslinkHookEntry builds a hook entry map with the given abysslink notify command.
func abysslinkHookEntry(cmd string) map[string]interface{} {
	return map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": cmd},
		},
	}
}

// foreignHookEntry builds a hook entry map with a non-abysslink command.
func foreignHookEntry(cmd string) map[string]interface{} {
	return map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": cmd},
		},
	}
}

// TestClaudeCodeDisableCmd_DryRunNoop tests that when settings.json is absent
// the command exits 0 with a no-hooks message (dry-run by default).
func TestClaudeCodeDisableCmd_DryRunNoop(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	var outBuf bytes.Buffer
	rootCmd := buildRootCmd()
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{"claudecode", "disable"})

	err := rootCmd.ExecuteContext(context.Background())
	require.NoError(t, err)

	out := outBuf.String()
	// Should mention that no hooks were found.
	assert.True(t,
		strings.Contains(strings.ToLower(out), "no abysslink") ||
			strings.Contains(strings.ToLower(out), "not found") ||
			strings.Contains(strings.ToLower(out), "no") && strings.Contains(strings.ToLower(out), "hooks"),
		"output should indicate no hooks were found; got: %q", out)
}

// TestClaudeCodeDisableCmd_DryRunWithHooks tests that in dry-run mode the
// command reports which hooks would be removed without modifying settings.json.
func TestClaudeCodeDisableCmd_DryRunWithHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"Stop": []interface{}{
				abysslinkHookEntry(`abysslink notify "Claude stopped" "Session ended"`),
			},
		},
	}
	settingsPath := writeClaudeSettings(t, dir, settings)
	originalContent, err := os.ReadFile(settingsPath)
	require.NoError(t, err)

	var outBuf bytes.Buffer
	rootCmd := buildRootCmd()
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{"claudecode", "disable"}) // no --apply → dry-run

	execErr := rootCmd.ExecuteContext(context.Background())
	require.NoError(t, execErr)

	out := outBuf.String()
	assert.True(t,
		strings.Contains(strings.ToLower(out), "dry-run") || strings.Contains(strings.ToLower(out), "dry run"),
		"output should indicate dry-run mode; got: %q", out)
	assert.True(t,
		strings.Contains(out, "remove") || strings.Contains(strings.ToLower(out), "strip"),
		"output should list what would be removed; got: %q", out)

	// File must not be mutated.
	afterContent, readErr := os.ReadFile(settingsPath)
	require.NoError(t, readErr)
	assert.Equal(t, string(originalContent), string(afterContent),
		"dry-run must not modify settings.json")
}

// TestClaudeCodeDisableCmd_ApplyRemovesHooks tests that --apply removes only
// abysslink hooks while preserving foreign hooks.
func TestClaudeCodeDisableCmd_ApplyRemovesHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"Stop": []interface{}{
				abysslinkHookEntry(`abysslink notify "Claude stopped" "Session ended"`),
				foreignHookEntry("echo user-hook"),
			},
		},
		"other_key": "preserved",
	}
	settingsPath := writeClaudeSettings(t, dir, settings)

	var outBuf bytes.Buffer
	rootCmd := buildRootCmd()
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{"claudecode", "disable", "--apply"})

	execErr := rootCmd.ExecuteContext(context.Background())
	require.NoError(t, execErr)

	out := outBuf.String()
	assert.NotContains(t, strings.ToLower(out), "dry-run",
		"--apply output must not say dry-run")
	assert.True(t,
		strings.Contains(strings.ToLower(out), "done") || strings.Contains(strings.ToLower(out), "removed"),
		"output should confirm removal; got: %q", out)

	// settings.json must not contain the abysslink hook any longer.
	raw, readErr := os.ReadFile(settingsPath)
	require.NoError(t, readErr)
	assert.NotContains(t, string(raw), "abysslink notify",
		"abysslink hooks must be removed from settings.json")

	// The foreign hook and top-level key must be preserved.
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &result))
	assert.Equal(t, "preserved", result["other_key"],
		"top-level key other_key must be preserved")
	hooks := result["hooks"].(map[string]interface{})
	stopHooks, ok := hooks["Stop"].([]interface{})
	require.True(t, ok, "Stop key must remain because it still has foreign hooks")
	require.Len(t, stopHooks, 1, "only the abysslink entry should have been removed")
	stopEntry := stopHooks[0].(map[string]interface{})
	innerHooks := stopEntry["hooks"].([]interface{})
	innerHook := innerHooks[0].(map[string]interface{})
	assert.Equal(t, "echo user-hook", innerHook["command"],
		"foreign hook must survive the removal")
}

// TestClaudeCodeDisableCmd_InvalidJSON tests that a settings.json with invalid
// JSON causes the command to return a non-nil error without overwriting the file.
func TestClaudeCodeDisableCmd_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	claudeDir := filepath.Join(dir, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o750))
	settingsPath := filepath.Join(claudeDir, "settings.json")
	require.NoError(t, os.WriteFile(settingsPath, []byte("not json"), 0o600))

	rootCmd := buildRootCmd()
	rootCmd.SetArgs([]string{"claudecode", "disable", "--apply"})

	execErr := rootCmd.ExecuteContext(context.Background())
	assert.Error(t, execErr, "invalid JSON must cause a non-nil error")

	raw, readErr := os.ReadFile(settingsPath)
	require.NoError(t, readErr)
	assert.Equal(t, "not json", string(raw),
		"file must not be overwritten when JSON is invalid")
}
