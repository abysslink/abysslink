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

package claudecode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasStopHook(t *testing.T) {
	withHook := []byte(`{
	  "hooks": {
	    "Stop": [
	      {"matcher": "", "hooks": [{"type": "command", "command": "abysslink notify \"Claude stopped\" \"x\""}]}
	    ]
	  }
	}`)
	assert.True(t, hasStopHook(withHook))

	withoutHook := []byte(`{"hooks": {"Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "echo hi"}]}]}}`)
	assert.False(t, hasStopHook(withoutHook))

	assert.False(t, hasStopHook([]byte(`{}`)))
	assert.False(t, hasStopHook([]byte("not json")))
}

// TestMergeHookEntry_PreservesUserHooks verifies that mergeHookEntry keeps the
// user's own hook entries and only replaces abysslink's own entry.
func TestMergeHookEntry_PreservesUserHooks(t *testing.T) {
	userEntry := map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": "echo user-hook"},
		},
	}
	existing := []interface{}{userEntry}

	result := mergeHookEntry(existing, stopHookCommand)
	require.Len(t, result, 2, "user entry + abysslink entry must both be present")

	cmds := collectCommands(t, result)
	assert.Contains(t, cmds, "echo user-hook", "user hook must be preserved")
	assert.Contains(t, cmds, stopHookCommand, "abysslink hook must be added")
}

// TestMergeHookEntry_Idempotent verifies that running merge twice does not
// duplicate the abysslink hook entry.
func TestMergeHookEntry_Idempotent(t *testing.T) {
	first := mergeHookEntry(nil, stopHookCommand)
	second := mergeHookEntry(first, stopHookCommand)
	require.Len(t, second, 1, "abysslink entry must not be duplicated")
}

// TestMergeHookEntry_NilExisting verifies behaviour when there are no existing entries.
func TestMergeHookEntry_NilExisting(t *testing.T) {
	result := mergeHookEntry(nil, stopHookCommand)
	require.Len(t, result, 1)
	cmds := collectCommands(t, result)
	assert.Contains(t, cmds, stopHookCommand)
}

// TestMergeHookEntry_OtherEventTypesUntouched verifies a full settings.json
// merge does not delete unrelated hook event types (SessionStart, UserPromptSubmit, etc.).
func TestMergeHookEntry_OtherEventTypesUntouched(t *testing.T) {
	raw := []byte(`{
		"hooks": {
			"SessionStart":      [{"matcher":"","hooks":[{"type":"command","command":"echo session"}]}],
			"UserPromptSubmit":  [{"matcher":"","hooks":[{"type":"command","command":"echo prompt"}]}],
			"Stop": []
		}
	}`)
	var settings map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &settings))

	existingHooks, _ := settings["hooks"].(map[string]interface{})
	existingHooks["Stop"] = mergeHookEntry(existingHooks["Stop"], stopHookCommand)
	settings["hooks"] = existingHooks

	out, err := json.Marshal(settings)
	require.NoError(t, err)

	var merged map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &merged))

	hooks := merged["hooks"].(map[string]interface{})
	assert.Contains(t, hooks, "SessionStart", "SessionStart must survive merge")
	assert.Contains(t, hooks, "UserPromptSubmit", "UserPromptSubmit must survive merge")
	assert.Contains(t, hooks, "Stop", "Stop must be present after merge")
}

// collectCommands extracts every "command" string from a hook entry list.
func collectCommands(t *testing.T, entries []interface{}) []string {
	t.Helper()
	var cmds []string
	for _, e := range entries {
		eMap, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		hs, _ := eMap["hooks"].([]interface{})
		for _, h := range hs {
			hMap, ok := h.(map[string]interface{})
			if !ok {
				continue
			}
			if cmd, ok := hMap["command"].(string); ok {
				cmds = append(cmds, cmd)
			}
		}
	}
	return cmds
}

// settingsWithHooks builds a settings.json fixture with the given hook arrays.
// eventHooks maps event key (e.g. "Stop") to a list of hook entries.
// extraKeys are additional top-level keys to include.
func settingsWithHooks(t *testing.T, eventHooks map[string][]interface{}, extraKeys map[string]interface{}) []byte {
	t.Helper()
	settings := make(map[string]interface{})
	for k, v := range extraKeys {
		settings[k] = v
	}
	hooks := make(map[string]interface{})
	for event, entries := range eventHooks {
		hooks[event] = entries
	}
	settings["hooks"] = hooks
	data, err := json.MarshalIndent(settings, "", "  ")
	require.NoError(t, err)
	return append(data, '\n')
}

func abysslinkEntry(cmd string) map[string]interface{} {
	return map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": cmd},
		},
	}
}

func foreignEntry(cmd string) map[string]interface{} {
	return map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": cmd},
		},
	}
}

// TestRemoveHooks covers all six required cases for RemoveHooks.
func TestRemoveHooks(t *testing.T) {
	newModule := func() *Module {
		return New(modules.Deps{})
	}

	writeSettings := func(t *testing.T, dir string, content []byte) string {
		t.Helper()
		claudeDir := filepath.Join(dir, ".claude")
		require.NoError(t, os.MkdirAll(claudeDir, 0o750))
		p := filepath.Join(claudeDir, "settings.json")
		require.NoError(t, os.WriteFile(p, content, 0o600))
		return p
	}

	t.Run("a_strips_stop_and_notification", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t.Setenv("XDG_STATE_HOME", t.TempDir())

		fixture := settingsWithHooks(t, map[string][]interface{}{
			"Stop":         {abysslinkEntry(stopHookCommand)},
			"Notification": {abysslinkEntry(notifyHookCommand)},
		}, nil)
		writeSettings(t, dir, fixture)

		removed, err := newModule().RemoveHooks(context.Background(), false)
		require.NoError(t, err)
		assert.Len(t, removed, 2, "both Stop and Notification abysslink entries must be reported")

		raw, readErr := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
		require.NoError(t, readErr)
		assert.NotContains(t, string(raw), "abysslink notify", "abysslink hooks must not remain in file")
	})

	t.Run("b_preserves_foreign_and_other_event_keys", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t.Setenv("XDG_STATE_HOME", t.TempDir())

		fixture := settingsWithHooks(t, map[string][]interface{}{
			"Stop": {
				abysslinkEntry(stopHookCommand),
				foreignEntry("echo user-stop"),
			},
			"Notification": {
				abysslinkEntry(notifyHookCommand),
			},
			"SessionStart":     {foreignEntry("echo session")},
			"UserPromptSubmit": {foreignEntry("echo prompt")},
		}, nil)
		writeSettings(t, dir, fixture)

		removed, err := newModule().RemoveHooks(context.Background(), false)
		require.NoError(t, err)
		assert.Len(t, removed, 2, "only abysslink entries should be removed")

		raw, readErr := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
		require.NoError(t, readErr)
		s := string(raw)
		assert.Contains(t, s, "echo user-stop", "foreign Stop hook must be preserved")
		assert.Contains(t, s, "echo session", "SessionStart hook must be preserved")
		assert.Contains(t, s, "echo prompt", "UserPromptSubmit hook must be preserved")
		assert.NotContains(t, s, "abysslink notify")
	})

	t.Run("c_deletes_empty_event_key", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t.Setenv("XDG_STATE_HOME", t.TempDir())

		// Stop will become empty after removal; Notification has a foreign hook.
		fixture := settingsWithHooks(t, map[string][]interface{}{
			"Stop":         {abysslinkEntry(stopHookCommand)},
			"Notification": {abysslinkEntry(notifyHookCommand), foreignEntry("echo notif")},
		}, nil)
		writeSettings(t, dir, fixture)

		removed, err := newModule().RemoveHooks(context.Background(), false)
		require.NoError(t, err)
		assert.Len(t, removed, 2)

		raw, readErr := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
		require.NoError(t, readErr)

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &result))
		hooks := result["hooks"].(map[string]interface{})
		_, stopPresent := hooks["Stop"]
		assert.False(t, stopPresent, "Stop key must be deleted when its array becomes empty")
		_, notifPresent := hooks["Notification"]
		assert.True(t, notifPresent, "Notification key must remain because it has foreign hooks")
	})

	t.Run("d_missing_dir_or_file_is_noop", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		// Do NOT create ~/.claude/ or settings.json.

		removed, err := newModule().RemoveHooks(context.Background(), false)
		require.NoError(t, err)
		assert.Nil(t, removed, "missing file/dir must return nil, nil")
	})

	t.Run("e_invalid_json_returns_error_no_overwrite", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t.Setenv("XDG_STATE_HOME", t.TempDir())

		settingsPath := writeSettings(t, dir, []byte("not json"))

		_, err := newModule().RemoveHooks(context.Background(), false)
		assert.Error(t, err, "invalid JSON must return an error")

		raw, readErr := os.ReadFile(settingsPath)
		require.NoError(t, readErr)
		assert.Equal(t, "not json", string(raw), "file must not be overwritten on error")
	})

	t.Run("f_dryrun_computes_descriptors_no_mutation", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t.Setenv("XDG_STATE_HOME", t.TempDir())

		original := settingsWithHooks(t, map[string][]interface{}{
			"Stop":         {abysslinkEntry(stopHookCommand)},
			"Notification": {abysslinkEntry(notifyHookCommand)},
		}, nil)
		settingsPath := writeSettings(t, dir, original)

		removed, err := newModule().RemoveHooks(context.Background(), true /*dryRun*/)
		require.NoError(t, err)
		assert.Len(t, removed, 2, "dry-run must compute descriptors")

		// File must not be mutated.
		after, readErr := os.ReadFile(settingsPath)
		require.NoError(t, readErr)
		assert.Equal(t, string(original), string(after), "dry-run must not mutate settings.json")
	})
}
