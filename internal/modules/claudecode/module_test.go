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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
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
	// RemoveHooks writes through the INJECTED audit writer (modules.Deps.Audit),
	// never an inline audit.New(DefaultLogPath()) — review INFO.
	newModule := func(t *testing.T) *Module {
		t.Helper()
		return New(modules.Deps{Audit: audit.New(filepath.Join(t.TempDir(), "audit.log"))})
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

		removed, err := newModule(t).RemoveHooks(context.Background(), false)
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

		removed, err := newModule(t).RemoveHooks(context.Background(), false)
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

		removed, err := newModule(t).RemoveHooks(context.Background(), false)
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

		removed, err := newModule(t).RemoveHooks(context.Background(), false)
		require.NoError(t, err)
		assert.Nil(t, removed, "missing file/dir must return nil, nil")
	})

	t.Run("e_invalid_json_returns_error_no_overwrite", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t.Setenv("XDG_STATE_HOME", t.TempDir())

		settingsPath := writeSettings(t, dir, []byte("not json"))

		_, err := newModule(t).RemoveHooks(context.Background(), false)
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

		removed, err := newModule(t).RemoveHooks(context.Background(), true /*dryRun*/)
		require.NoError(t, err)
		assert.Len(t, removed, 2, "dry-run must compute descriptors")

		// File must not be mutated.
		after, readErr := os.ReadFile(settingsPath)
		require.NoError(t, readErr)
		assert.Equal(t, string(original), string(after), "dry-run must not mutate settings.json")
	})
}

// failingStore is a KeychainStore whose Get fails with a non-ErrNotFound error,
// simulating a locked login keychain after reboot.
type failingStore struct{}

func (failingStore) Set(_ context.Context, _, _, _ string) error { return nil }
func (failingStore) Get(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("keychain: interaction not allowed (locked)")
}
func (failingStore) Delete(_ context.Context, _, _ string) error { return nil }

func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.ClaudeCode.Enabled = true
	cfg.ClaudeCode.APIKeySource = "none" // skip keychain probing unless a test opts in
	return cfg
}

// TestApply_Disabled_NoMutation is the C3 regression test: Apply on a disabled
// claudecode module must mutate NOTHING — Runner.ApplyAll calls Apply for every
// module, so without the Enabled gate `abysslink disable claudecode` would be
// silently undone (hooks re-installed) by the next `up --apply`.
func TestApply_Disabled_NoMutation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := config.Defaults()
	cfg.ClaudeCode.Enabled = false
	m := New(modules.Deps{Cfg: cfg, Audit: audit.New(filepath.Join(t.TempDir(), "audit.log"))})

	require.NoError(t, m.Apply(context.Background()))
	_, err := os.Stat(filepath.Join(dir, ".claude"))
	assert.True(t, os.IsNotExist(err), "disabled module must not create ~/.claude/")
}

// TestApply_Disabled_DoesNotReinstallRemovedHooks proves the full disable
// round-trip: hooks installed, then removed, then a disabled Apply must NOT
// bring them back.
func TestApply_Disabled_DoesNotReinstallRemovedHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	a := audit.New(filepath.Join(t.TempDir(), "audit.log"))

	cfg := enabledCfg()
	m := New(modules.Deps{Cfg: cfg, Audit: a})
	require.NoError(t, m.Apply(context.Background()))

	removed, err := m.RemoveHooks(context.Background(), false)
	require.NoError(t, err)
	require.NotEmpty(t, removed)

	cfg.ClaudeCode.Enabled = false // simulate `abysslink disable claudecode --apply`
	require.NoError(t, m.Apply(context.Background()))

	raw, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "abysslink notify",
		"a disabled module's Apply must not re-install the removed hooks (C3)")
}

// TestApply_Enabled_InstallsHooksViaInjectedAudit verifies the happy path and
// that the write goes through the injected audit writer (nil writer errors).
func TestApply_Enabled_InstallsHooksViaInjectedAudit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	m := New(modules.Deps{Cfg: enabledCfg(), Audit: audit.New(filepath.Join(t.TempDir(), "audit.log"))})
	require.NoError(t, m.Apply(context.Background()))

	raw, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	require.NoError(t, err)
	assert.True(t, hasStopHook(raw), "Stop hook must be installed")
	assert.True(t, hasNotificationHook(raw), "Notification hook must be installed")
}

func TestApply_NilAudit_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	m := New(modules.Deps{Cfg: enabledCfg(), Audit: nil})
	err := m.Apply(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit not available")
}

// TestDetectKeychainState_NotFoundVsLocked is the W7 regression test: a key
// that was never stored (wrapped secrets.ErrNotFound) must produce the
// api_key_present finding (so Plan offers to store it), while any OTHER Get
// error must produce the api_key_keychain "locked keychain" finding.
func TestDetectKeychainState_NotFoundVsLocked(t *testing.T) {
	cfg := config.Defaults()
	cfg.ClaudeCode.APIKeySource = "keychain"

	t.Run("never_stored_is_api_key_present", func(t *testing.T) {
		m := New(modules.Deps{Cfg: cfg, Keychain: secrets.NewMockStore()})
		findings := m.detectKeychainState(context.Background())
		require.Len(t, findings, 1)
		assert.Equal(t, "api_key_present", findings[0].Check,
			"ErrNotFound means the key was never stored — not a locked keychain (W7)")
		assert.Contains(t, findings[0].Message, "ANTHROPIC_API_KEY")
	})

	t.Run("other_error_is_api_key_keychain", func(t *testing.T) {
		m := New(modules.Deps{Cfg: cfg, Keychain: failingStore{}})
		findings := m.detectKeychainState(context.Background())
		require.Len(t, findings, 1)
		assert.Equal(t, "api_key_keychain", findings[0].Check)
		assert.Contains(t, findings[0].Message, "locked")
	})

	t.Run("stored_key_is_clean", func(t *testing.T) {
		store := secrets.NewMockStore()
		require.NoError(t, store.Set(context.Background(), keychainService, keychainAccount, "sk-test"))
		m := New(modules.Deps{Cfg: cfg, Keychain: store})
		assert.Empty(t, m.detectKeychainState(context.Background()))
	})
}

// TestPlan_StoreKeyActionReachable proves the api_key_present plan action is
// reachable again (W7): with an empty keychain, Plan must offer to store the key.
func TestPlan_StoreKeyActionReachable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := config.Defaults()
	cfg.ClaudeCode.Enabled = true
	cfg.ClaudeCode.APIKeySource = "keychain"
	m := New(modules.Deps{Cfg: cfg, Keychain: secrets.NewMockStore()})

	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	var found bool
	for _, a := range actions {
		if a.Description == "store Anthropic API key in OS keychain (reads from $ANTHROPIC_API_KEY)" {
			found = true
		}
	}
	assert.True(t, found, "Plan must include the store-API-key action when the key was never stored")
}

// TestPlan_DedupesMergeAction verifies the UX fix: when both the Stop and
// Notification hooks are missing, Plan emits ONE merge action, not two
// identical ones.
func TestPlan_DedupesMergeAction(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	claudeDir := filepath.Join(dir, ".claude")
	require.NoError(t, os.MkdirAll(claudeDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte("{}\n"), 0o600))

	m := New(modules.Deps{Cfg: enabledCfg()})
	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)

	merges := 0
	for _, a := range actions {
		if a.Description == "merge abysslink notify hooks into ~/.claude/settings.json (preserves existing hooks)" {
			merges++
		}
	}
	assert.Equal(t, 1, merges, "identical merge actions must be deduplicated")
}

// TestPlan_Disabled_NoActions pins the existing Plan gate.
func TestPlan_Disabled_NoActions(t *testing.T) {
	cfg := config.Defaults()
	cfg.ClaudeCode.Enabled = false
	m := New(modules.Deps{Cfg: cfg})
	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	assert.Empty(t, actions)
}

// TestResolveHookBinary covers the absolute-path enhancement: hook commands
// embed the running binary's absolute path (Claude hook environments often
// lack the user's PATH) and fall back to the bare name when that is unsafe.
func TestResolveHookBinary(t *testing.T) {
	cases := []struct {
		name string
		exe  string
		err  error
		want string
	}{
		{"abysslink_absolute_path", "/usr/local/bin/abysslink", nil, "/usr/local/bin/abysslink"},
		{"os_executable_error", "", fmt.Errorf("boom"), "abysslink"},
		{"empty_path", "", nil, "abysslink"},
		{"test_binary_falls_back", "/tmp/go-build123/claudecode.test", nil, "abysslink"},
		{"path_with_space_falls_back", "/Users/My Name/bin/abysslink", nil, "abysslink"},
		{"path_with_quote_falls_back", `/tmp/a"b/abysslink`, nil, "abysslink"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveHookBinary(tc.exe, tc.err))
		})
	}
}

// TestHookCommands_RecognizableAsAbysslink pins the invariant the hook
// detection/removal substring matcher depends on: whatever binary token is
// chosen, the rendered commands must contain "abysslink notify".
func TestHookCommands_RecognizableAsAbysslink(t *testing.T) {
	assert.Contains(t, stopHookCommand, "abysslink notify")
	assert.Contains(t, notifyHookCommand, "abysslink notify")
	assert.True(t, hookEntryIsAbysslink(abysslinkEntry(stopHookCommand)))
	assert.True(t, hookEntryIsAbysslink(abysslinkEntry(notifyHookCommand)))
}

// enabledEnforcingCfg returns a config with ClaudeCode enabled and Gate.Enforcing=true.
func enabledEnforcingCfg() *config.Config {
	cfg := enabledCfg()
	cfg.Gate.Enforcing = true
	return cfg
}

// TestModule_PermissionRequestHook verifies that Apply() writes both PreToolUse
// and PermissionRequest hook entries containing "abysslink approve" when
// gate.enforcing=true (APPR-06).
func TestModule_PermissionRequestHook(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	m := New(modules.Deps{
		Cfg:   enabledEnforcingCfg(),
		Audit: audit.New(filepath.Join(t.TempDir(), "audit.log")),
	})
	require.NoError(t, m.Apply(context.Background()))

	raw, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	require.NoError(t, err)
	s := string(raw)
	assert.Contains(t, s, "abysslink approve", "PreToolUse or PermissionRequest hook must contain 'abysslink approve'")

	var settings map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &settings))
	hooks, _ := settings["hooks"].(map[string]interface{})
	require.NotNil(t, hooks, "hooks key must be present")
	assert.Contains(t, hooks, "PreToolUse", "PreToolUse hook must be written when gate.enforcing=true")
	assert.Contains(t, hooks, "PermissionRequest", "PermissionRequest hook must be written when gate.enforcing=true")
}

// TestModule_HookIdempotent verifies that calling Apply() twice does not
// duplicate the PreToolUse or PermissionRequest entries (idempotent merge).
func TestModule_HookIdempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	m := New(modules.Deps{
		Cfg:   enabledEnforcingCfg(),
		Audit: audit.New(filepath.Join(t.TempDir(), "audit.log")),
	})

	require.NoError(t, m.Apply(context.Background()))
	require.NoError(t, m.Apply(context.Background()))

	raw, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	require.NoError(t, err)

	var settings map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &settings))
	hooks, _ := settings["hooks"].(map[string]interface{})
	require.NotNil(t, hooks)

	countAbysslink := func(t *testing.T, eventKey string) int {
		t.Helper()
		entries, _ := hooks[eventKey].([]interface{})
		count := 0
		for _, e := range entries {
			if hookEntryIsAbysslink(e) {
				count++
			}
		}
		return count
	}

	assert.Equal(t, 1, countAbysslink(t, "PreToolUse"),
		"exactly one abysslink PreToolUse entry after two Apply() calls")
	assert.Equal(t, 1, countAbysslink(t, "PermissionRequest"),
		"exactly one abysslink PermissionRequest entry after two Apply() calls")
}

// TestModule_NoCoupling (static): verifies that the claudecode package imports
// do not include internal/approve or internal/gate (APPR-06 quarantine rule).
// All Claude-specific logic must be quarantined in this package; the approve
// loop is invoked via subprocess hook command, never via direct package import.
func TestModule_NoCoupling(t *testing.T) {
	// This test parses the package's imports statically (same pattern as
	// TestGate_NoOSExecImport in internal/gate/gate_test.go).
	// We check that neither "internal/approve" nor "internal/gate" appears
	// in the claudecode package's import graph.
	forbidden := []string{
		"github.com/abysslink/abysslink/internal/approve",
		"github.com/abysslink/abysslink/internal/gate",
	}
	pkgDir := "." // package claudecode (internal test, same package)
	_ = pkgDir    // used implicitly: we read module.go source
	src, err := os.ReadFile("module.go")
	require.NoError(t, err)
	for _, imp := range forbidden {
		assert.NotContains(t, string(src), imp,
			"claudecode/module.go must not import %q (APPR-06 quarantine)", imp)
	}
}
