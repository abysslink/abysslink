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
	"errors"
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
var notifyHookCommand = hookBinary() + ` notify "Claude needs you" "waiting for input"`

// stopHookCommand fires when a Claude Code session ends.
var stopHookCommand = hookBinary() + ` notify "Claude stopped" "Session ended"`

const (
	keychainService = "abysslink"
	keychainAccount = "anthropic-api-key"
)

// hookBinary returns the binary token to embed in the hook command lines.
// Claude Code's hook environment frequently lacks the user's interactive PATH,
// so a bare "abysslink" silently fails — and a silent hook failure means no
// phone buzz, the module's core promise. Prefer the absolute path of the
// running binary; resolveHookBinary documents when we fall back to the bare name.
func hookBinary() string {
	exe, err := os.Executable()
	return resolveHookBinary(exe, err)
}

// resolveHookBinary picks the hook command binary token from os.Executable()'s
// result. Split out for testability. The absolute path is used only when it is
// actually the abysslink binary (base name "abysslink" — under `go test` the
// executable is the test binary) AND it is shell-safe to embed unquoted (no
// whitespace or quote characters); otherwise fall back to the bare name and
// rely on PATH. The "abysslink notify" substring that hook detection/removal
// keys on is preserved either way ("…/abysslink notify" contains it).
func resolveHookBinary(exe string, err error) string {
	const fallback = "abysslink"
	if err != nil || exe == "" {
		return fallback
	}
	if filepath.Base(exe) != "abysslink" {
		return fallback
	}
	if strings.ContainsAny(exe, " \t\n\"'\\$&;|<>()`") {
		return fallback
	}
	return exe
}

// Module implements the claudecode optional module.
// It writes ~/.claude/settings.json hooks that call `abysslink notify`.
// This module must NOT import or depend on the Claude SDK — it only writes
// config files that invoke the abysslink binary.
type Module struct {
	runner   shell.Runner
	cfg      *config.Config
	keychain secrets.KeychainStore
	audit    audit.AuditWriter
}

// New returns a new claudecode Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, keychain: d.Keychain, audit: d.Audit}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "claudecode" }

// Deps returns the modules this module depends on.
func (m *Module) Deps() []string { return []string{"notify"} }

// Detect inspects the current system state for Claude Code integration.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	findings := m.detectKeychainState(ctx)

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("claudecode: home dir: %w", err)
	}

	settingsFindings, data, done := m.detectSettingsFile(home)
	findings = append(findings, settingsFindings...)
	if done {
		return findings, nil
	}

	findings = append(findings, m.detectHooks(data)...)
	return findings, nil
}

// detectKeychainState checks both post-reboot keychain lock and missing API key.
func (m *Module) detectKeychainState(ctx context.Context) []modules.Finding {
	if m.cfg.ClaudeCode.APIKeySource != "keychain" || m.keychain == nil {
		return nil
	}
	v, err := m.keychain.Get(ctx, keychainService, keychainAccount)
	if err == nil && v != "" {
		return nil
	}

	// Distinguish: key was never stored vs keychain not readable. Every
	// KeychainStore.Get returns a wrapped secrets.ErrNotFound for a missing
	// item, so a bare err != nil check would misreport "never stored" as
	// "keychain locked" and make the api_key_present branch unreachable (W7).
	check, msg := "api_key_present",
		"Anthropic API key is not in the keychain — set ANTHROPIC_API_KEY and re-run `abysslink up --apply` to store it"
	if err != nil && !errors.Is(err, secrets.ErrNotFound) {
		check, msg = "api_key_keychain",
			"Anthropic API key not readable from the keychain (the login keychain may be locked after reboot — unlock it at the console)"
	}
	return []modules.Finding{{
		Module: "claudecode", Check: check,
		Severity: modules.SeverityWarning, Message: msg,
	}}
}

// detectSettingsFile checks that ~/.claude/ exists and settings.json is readable.
// done=true means the caller should stop and return (directory or file missing).
func (m *Module) detectSettingsFile(home string) (findings []modules.Finding, data []byte, done bool) {
	claudeDir := filepath.Join(home, ".claude")
	if _, err := os.Stat(claudeDir); os.IsNotExist(err) {
		return []modules.Finding{{
			Module: "claudecode", Check: "claude_dir_exists",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("Claude Code not installed: %s does not exist", claudeDir),
		}}, nil, true
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	raw, err := os.ReadFile(settingsPath) //nolint:gosec // G304: settingsPath is the Claude Code settings path resolved internally, not user input
	if err != nil {
		if os.IsNotExist(err) {
			return []modules.Finding{{
				Module: "claudecode", Check: "settings_json_exists",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("~/.claude/settings.json not found at %s", settingsPath),
			}}, nil, true
		}
		return []modules.Finding{{
			Module: "claudecode", Check: "settings_json_readable",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("cannot read ~/.claude/settings.json: %v", err),
		}}, nil, true
	}
	return nil, raw, false
}

// detectHooks checks that the required abysslink hooks are present in settings.json.
func (m *Module) detectHooks(data []byte) []modules.Finding {
	var findings []modules.Finding
	if !hasStopHook(data) {
		findings = append(findings, modules.Finding{
			Module: "claudecode", Check: "stop_hook_configured",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("~/.claude/settings.json missing abysslink notify Stop hook (expected command: %q)", stopHookCommand),
		})
	}
	if m.cfg.ClaudeCode.NotifyOn.Notification && !hasNotificationHook(data) {
		findings = append(findings, modules.Finding{
			Module: "claudecode", Check: "notification_hook_configured",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("~/.claude/settings.json missing abysslink notify Notification hook (expected command: %q)", notifyHookCommand),
		})
	}
	return findings
}

// hasNotificationHook returns true if the settings.json contains a Notification
// hook with the expected abysslink notify command.
func hasNotificationHook(data []byte) bool {
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		return false
	}
	notifHooks, ok := hooks["Notification"].([]interface{})
	if !ok {
		return false
	}
	for _, entry := range notifHooks {
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
			if cmd, ok := hMap["command"].(string); ok && strings.Contains(cmd, "abysslink notify") {
				return true
			}
		}
	}
	return false
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
	mergePlanned := false // several findings map to ONE merge action — dedupe (UX)
	for _, f := range findings {
		switch f.Check {
		case "claude_dir_exists":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "create ~/.claude/ directory",
				Reversible:  true,
			})
		case "settings_json_exists", "settings_json_readable",
			"stop_hook_configured", "notification_hook_configured":
			if mergePlanned {
				continue
			}
			mergePlanned = true
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "merge abysslink notify hooks into ~/.claude/settings.json (preserves existing hooks)",
				Reversible:  true,
			})
		case "api_key_present":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "store Anthropic API key in OS keychain (reads from $ANTHROPIC_API_KEY)",
				Reversible:  true,
			})
		}
	}
	return actions, nil
}

// Apply writes or merges ~/.claude/settings.json with the abysslink notify hooks
// and stores the Anthropic API key in the keychain.
//
// It MUST gate on ClaudeCode.Enabled (C3): Runner.ApplyAll calls Apply on every
// module regardless of planned actions, so without this gate a disabled module
// would still install hooks into ~/.claude/settings.json — silently undoing
// `abysslink disable claudecode` on the next `up --apply` and mutating a file
// the dry-run preview never showed.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.ClaudeCode.Enabled {
		slog.Debug("claudecode module disabled, skipping apply")
		return nil
	}

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
	// If the file exists but contains invalid JSON, return an error rather than
	// silently overwriting it — that would destroy the user's settings.
	existing := make(map[string]interface{})
	if data, err := os.ReadFile(settingsPath); err == nil { //nolint:gosec // G304: settingsPath is the Claude Code settings path resolved internally, not user input
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("claudecode: settings.json is not valid JSON (%w); "+
				"back it up and remove it, then re-run to reset", err)
		}
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
	// the central audit log (hash only — never the settings body). The writer
	// is the injected modules.Deps.Audit — never constructed inline — so tests
	// can capture mutations and SignedAudit injection works (review INFO).
	if m.audit == nil {
		return fmt.Errorf("claudecode: audit not available")
	}
	if err := m.audit.WriteFile(settingsPath, data, 0o600, false); err != nil {
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

// RemoveHooks strips only the abysslink notify entries from
// ~/.claude/settings.json. It is the inverse of Apply for the hook writes only.
//
// Returns the list of human-readable descriptors for removed entries, or nil if
// no abysslink hooks were present (or the file/dir is missing).
// If dryRun is true, descriptors are computed but no file is written.
// Returns a non-nil error if settings.json contains invalid JSON — the file is
// never overwritten in that case.
//
// context.Context is accepted for forward-compatibility; not yet used internally.
func (m *Module) RemoveHooks(ctx context.Context, dryRun bool) ([]string, error) {
	_ = ctx // reserved for future cancellation support

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("claudecode: home dir: %w", err)
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")
	raw, err := readSettingsForRemoval(home, settingsPath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil // missing dir or file — graceful no-op
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, fmt.Errorf("claudecode: settings.json is not valid JSON (%w); "+
			"back it up and remove it, then re-run to reset", err)
	}

	existingHooks, _ := settings["hooks"].(map[string]interface{})
	if existingHooks == nil {
		return nil, nil // no hooks key — nothing to remove
	}

	removed := pruneAbysslinkHooks(existingHooks)
	if len(removed) == 0 {
		return nil, nil // already clean, no write needed
	}

	if len(existingHooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = existingHooks
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("claudecode: marshal settings: %w", err)
	}
	data = append(data, '\n')

	if m.audit == nil {
		return nil, fmt.Errorf("claudecode: audit not available")
	}
	if err := m.audit.WriteFile(settingsPath, data, 0o600, dryRun); err != nil {
		return nil, fmt.Errorf("claudecode: write settings.json: %w", err)
	}

	if !dryRun {
		slog.Info("claudecode: removed abysslink notify hooks from settings.json",
			"path", settingsPath, "count", len(removed))
	}

	return removed, nil
}

// readSettingsForRemoval reads ~/.claude/settings.json for the removal path.
// Returns (nil, nil) when the directory or file does not exist (graceful no-op).
func readSettingsForRemoval(home, settingsPath string) ([]byte, error) {
	if _, statErr := os.Stat(filepath.Join(home, ".claude")); os.IsNotExist(statErr) {
		return nil, nil
	}
	raw, err := os.ReadFile(settingsPath) //nolint:gosec // G304: settingsPath is the Claude Code settings path resolved internally, not user input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("claudecode: read settings.json: %w", err)
	}
	return raw, nil
}

// pruneAbysslinkHooks removes abysslink notify entries from the given hooks map
// (mutates in place) for the "Stop" and "Notification" event keys.
// Returns human-readable descriptors for each removed entry.
// Event keys whose arrays become empty are deleted from the map.
func pruneAbysslinkHooks(hooks map[string]interface{}) []string {
	var removed []string
	for _, eventKey := range []string{"Stop", "Notification"} {
		entries, ok := hooks[eventKey].([]interface{})
		if !ok {
			continue
		}
		kept, descs := partitionHookEntries(eventKey, entries)
		removed = append(removed, descs...)
		if len(kept) == 0 {
			delete(hooks, eventKey)
		} else {
			hooks[eventKey] = kept
		}
	}
	return removed
}

// partitionHookEntries splits a hook entry list into kept (non-abysslink) entries
// and a list of descriptors for removed (abysslink) entries.
func partitionHookEntries(eventKey string, entries []interface{}) (kept []interface{}, removed []string) {
	for _, entry := range entries {
		if hookEntryIsAbysslink(entry) {
			removed = append(removed, hookEntryDescriptor(eventKey, entry))
		} else {
			kept = append(kept, entry)
		}
	}
	return kept, removed
}

// hookEntryDescriptor builds a human-readable descriptor for an abysslink hook entry.
func hookEntryDescriptor(eventKey string, entry interface{}) string {
	entryMap, ok := entry.(map[string]interface{})
	if !ok {
		return eventKey + ": abysslink notify"
	}
	innerHooks, ok := entryMap["hooks"].([]interface{})
	if !ok {
		return eventKey + ": abysslink notify"
	}
	for _, h := range innerHooks {
		hMap, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		if cmd, ok := hMap["command"].(string); ok {
			return eventKey + ": " + cmd
		}
	}
	return eventKey + ": abysslink notify"
}

// Verify is a no-op for the claudecode module — all checks run in Detect.
// Pitfall 4 (Doctor double-emission): do NOT call Detect here — runner.Doctor
// calls both Detect and Verify, so re-running Detect would double-emit every
// Detect finding per doctor pass (NET-18). Verify adds no new information
// beyond Detect; returning nil avoids the duplication (mirrors ssh/ntfy).
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
