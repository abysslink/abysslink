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
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

// anthropicKeyEnv is read (never logged) to seed the keychain on first run.
const anthropicKeyEnv = "ANTHROPIC_API_KEY"

// notifyHookCommand fires when Claude Code is waiting for input — the primary
// "buzz my phone" trigger.
const notifyHookCommand = `abysslink notify "Claude needs you" "waiting for input"`

const (
	stopHookCommand = `abysslink notify "Claude stopped" "Session ended"`
	keychainService = "abysslink"
	keychainAccount = "anthropic-api-key"
)

// Module implements the claudecode optional module.
// It writes ~/.claude/settings.json hooks that call `abysslink notify`.
// This module must NOT import or depend on the Claude SDK — it only writes
// config files that invoke the abysslink binary.
type Module struct {
	runner   shell.Runner
	cfg      *config.Config
	keychain secrets.KeychainStore
}

// New returns a new claudecode Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, keychain: d.Keychain}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "claudecode" }

// Deps returns the modules this module depends on.
func (m *Module) Deps() []string { return []string{"notify"} }

// Detect inspects the current system state for Claude Code integration.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Post-reboot keychain check: on macOS the login keychain is locked until
	// the user logs in at the console, so a key that was stored may be
	// unreadable. Surface that so the hooks do not silently fail.
	if m.cfg.ClaudeCode.APIKeySource == "keychain" && m.keychain != nil {
		if v, err := m.keychain.Get(ctx, keychainService, keychainAccount); err != nil || v == "" {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "api_key_keychain",
				Severity: modules.SeverityWarning,
				Message:  "Anthropic API key not readable from the keychain (unset, or the login keychain is locked after reboot — unlock it at the console)",
			})
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("claudecode: home dir: %w", err)
	}

	claudeDir := filepath.Join(home, ".claude")
	settingsPath := filepath.Join(claudeDir, "settings.json")

	// Check if ~/.claude/ directory exists.
	if _, err := os.Stat(claudeDir); os.IsNotExist(err) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "claude_dir_exists",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("Claude Code not installed: %s does not exist", claudeDir),
		})
		return findings, nil
	}

	// Check if settings.json exists.
	data, err := os.ReadFile(settingsPath) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "settings_json_exists",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("~/.claude/settings.json not found at %s", settingsPath),
			})
		} else {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "settings_json_readable",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("cannot read ~/.claude/settings.json: %v", err),
			})
		}
		return findings, nil
	}

	// Check that settings.json contains the Stop hook pointing to abysslink notify.
	if !hasStopHook(data) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "stop_hook_configured",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("~/.claude/settings.json missing abysslink notify Stop hook (expected command: %q)", stopHookCommand),
		})
	}

	return findings, nil
}

// mergeHookEntry returns a hook entry list that keeps all existing entries
// that do NOT contain an abysslink notify command, then appends the new
// abysslink entry. Safe to call repeatedly (idempotent).
func mergeHookEntry(existing interface{}, command string) []interface{} {
	var kept []interface{}
	if entries, ok := existing.([]interface{}); ok {
		for _, e := range entries {
			if !hookEntryIsAbysslink(e) {
				kept = append(kept, e)
			}
		}
	}
	return append(kept, map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": command},
		},
	})
}

// hookEntryIsAbysslink returns true if the hook entry contains an abysslink
// notify command — used to identify our own entries for idempotent replacement.
func hookEntryIsAbysslink(entry interface{}) bool {
	entryMap, ok := entry.(map[string]interface{})
	if !ok {
		return false
	}
	innerHooks, ok := entryMap["hooks"].([]interface{})
	if !ok {
		return false
	}
	for _, h := range innerHooks {
		hMap, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		if cmd, ok := hMap["command"].(string); ok && strings.Contains(cmd, "abysslink notify") {
			return true
		}
	}
	return false
}

// hasStopHook returns true if the settings.json data contains a Stop hook
// with the expected abysslink notify command.
func hasStopHook(data []byte) bool {
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		return false
	}

	stopHooks, ok := hooks["Stop"].([]interface{})
	if !ok {
		return false
	}

	for _, entry := range stopHooks {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		innerHooks, ok := entryMap["hooks"].([]interface{})
		if !ok {
			continue
		}
		for _, h := range innerHooks {
			hMap, ok := h.(map[string]interface{})
			if !ok {
				continue
			}
			if cmd, ok := hMap["command"].(string); ok {
				if strings.Contains(cmd, "abysslink notify") {
					return true
				}
			}
		}
	}
	return false
}

// Plan computes actions needed to install the Claude Code hooks.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.ClaudeCode.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch f.Check {
		case "claude_dir_exists":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "create ~/.claude/ directory",
				Reversible:  true,
			})
		case "settings_json_exists", "settings_json_readable", "stop_hook_configured":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "merge abysslink notify hooks into ~/.claude/settings.json (preserves existing hooks)",
				Reversible:  true,
			})
		}
	}
	return actions, nil
}

// Apply writes or merges ~/.claude/settings.json with the abysslink notify hooks
// and stores the Anthropic API key in the keychain.
func (m *Module) Apply(ctx context.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("claudecode: home dir: %w", err)
	}

	claudeDir := filepath.Join(home, ".claude")
	settingsPath := filepath.Join(claudeDir, "settings.json")

	// Ensure ~/.claude/ directory exists.
	if err := os.MkdirAll(claudeDir, 0o750); err != nil {
		return fmt.Errorf("claudecode: mkdir .claude: %w", err)
	}

	// Read existing settings if present; start from empty map otherwise.
	existing := make(map[string]interface{})
	if data, err := os.ReadFile(settingsPath); err == nil { //nolint:gosec
		_ = json.Unmarshal(data, &existing)
	}

	// Merge abysslink entries into the existing hooks map — never replace it.
	// This preserves the user's SessionStart, UserPromptSubmit, and every other
	// hook they have configured. We only touch the event types we own (Stop,
	// Notification), and within those we remove our old entry then re-append so
	// the operation is idempotent.
	existingHooks, _ := existing["hooks"].(map[string]interface{})
	if existingHooks == nil {
		existingHooks = make(map[string]interface{})
	}
	if m.cfg.ClaudeCode.NotifyOn.Notification {
		existingHooks["Notification"] = mergeHookEntry(existingHooks["Notification"], notifyHookCommand)
	}
	existingHooks["Stop"] = mergeHookEntry(existingHooks["Stop"], stopHookCommand)
	existing["hooks"] = existingHooks

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("claudecode: marshal settings: %w", err)
	}
	data = append(data, '\n')

	// Back up any existing file, write atomically, and record the mutation in
	// the central audit log (hash only — never the settings body).
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("claudecode: audit log path: %w", err)
	}
	if err := audit.New(logPath).WriteFile(settingsPath, data, 0o600, false); err != nil {
		return fmt.Errorf("claudecode: write settings.json: %w", err)
	}

	slog.Info("claudecode: wrote settings.json with abysslink notify hooks", "path", settingsPath)

	m.storeAPIKey(ctx)
	return nil
}

// storeAPIKey moves the Anthropic API key from the environment into the
// keychain when api_key_source is "keychain", so it is not left in a shell
// profile. The value is delivered to the keychain via stdin, never argv.
func (m *Module) storeAPIKey(ctx context.Context) {
	if m.cfg.ClaudeCode.APIKeySource != "keychain" || m.keychain == nil {
		return
	}
	if existing, err := m.keychain.Get(ctx, keychainService, keychainAccount); err == nil && existing != "" {
		return // already stored
	}
	key := os.Getenv(anthropicKeyEnv)
	if key == "" {
		slog.Warn("claudecode: no API key in keychain and " + anthropicKeyEnv + " is unset — set it and re-run, or store the key with your secret manager")
		return
	}
	if err := m.keychain.Set(ctx, keychainService, keychainAccount, key); err != nil {
		slog.Warn("claudecode: could not store API key in keychain", "err", err)
		return
	}
	slog.Info("claudecode: stored Anthropic API key in keychain")
}

// Verify re-runs Detect to confirm the hook is in place.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
