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
	"github.com/abysslink/abysslink/internal/shell"
)

const (
	stopHookCommand    = `abysslink notify "Claude stopped" "Session ended"`
	keychainService    = "abysslink"
	keychainAccount    = "anthropic-api-key"
	auditLogFilename   = "claudecode-audit.log"
)

// Module implements the claudecode optional module.
// It writes ~/.claude/settings.json hooks that call `abysslink notify`.
// This module must NOT import or depend on the Claude SDK — it only writes
// config files that invoke the abysslink binary.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new claudecode Module.
func New(runner shell.Runner, cfg *config.Config) *Module {
	return &Module{runner: runner, cfg: cfg}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "claudecode" }

// Deps returns the modules this module depends on.
func (m *Module) Deps() []string { return []string{"notify"} }

// Detect inspects the current system state for Claude Code integration.
func (m *Module) Detect(_ context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

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
				Description: "write ~/.claude/settings.json with abysslink notify hooks",
				Reversible:  true,
			})
		}
	}
	return actions, nil
}

// Apply writes or merges ~/.claude/settings.json with the abysslink notify Stop hook.
func (m *Module) Apply(_ context.Context) error {
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

	// Build the desired hooks section (overwrite Stop hook).
	hookConfig := map[string]interface{}{
		"Stop": []interface{}{
			map[string]interface{}{
				"matcher": "",
				"hooks": []interface{}{
					map[string]interface{}{
						"type":    "command",
						"command": stopHookCommand,
					},
				},
			},
		},
	}

	existing["hooks"] = hookConfig

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("claudecode: marshal settings: %w", err)
	}
	data = append(data, '\n')

	// Record the mutation in the audit log before writing.
	auditLogPath := filepath.Join(claudeDir, auditLogFilename)
	a := audit.New(auditLogPath)
	if err := a.Append("write", settingsPath, data, false); err != nil {
		// Non-fatal: log but continue so the write is not blocked by an audit error.
		slog.Warn("claudecode: audit log failed", "err", err)
	}

	if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
		return fmt.Errorf("claudecode: write settings.json: %w", err)
	}

	slog.Info("claudecode: wrote settings.json with abysslink notify hooks", "path", settingsPath)
	return nil
}

// Verify re-runs Detect to confirm the hook is in place.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
