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
	"encoding/json"
	"testing"

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
