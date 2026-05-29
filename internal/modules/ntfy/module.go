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

package ntfy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

const serverConfigPath = ".config/ntfy/server.yml"

// Module implements the ntfy module.
type Module struct {
	runner   shell.Runner
	cfg      *config.Config
	audit    *audit.Audit
	plat     platform.Platform
	keychain secrets.KeychainStore
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, audit: d.Audit, plat: d.Platform, keychain: d.Keychain}
}

const (
	keychainService = "abysslink"
	keychainAccount = "ntfy-password"
)

// Name returns the module name.
func (m *Module) Name() string { return "ntfy" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// ntfyBinPath returns the path to use when running ntfy server commands.
// On macOS the Homebrew formula and GitHub release binaries are client-only
// (the ntfy server is not officially supported on macOS — see
// https://docs.ntfy.sh/install/). Users who manually install a server build
// should place it at ~/.local/bin/ntfy so abysslink finds it.
// On Linux the system package installs a full server binary on PATH.
func (m *Module) ntfyBinPath() string {
	if m.plat.OS() != "darwin" {
		return "ntfy"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "ntfy"
	}
	return filepath.Join(home, ".local", "bin", "ntfy")
}

// ntfyInstalled returns true when the ntfy binary exists and lists 'serve' as
// a top-level subcommand. Client-only builds (Homebrew, darwin release) only
// advertise 'publish' and 'subscribe'. We avoid matching "server" (substring
// of "serve") by checking that 'serve' appears at the start of a help line
// followed by a space or comma.
func (m *Module) ntfyInstalled(ctx context.Context) bool {
	res, err := m.runner.Run(ctx, m.ntfyBinPath(), "--help")
	if err != nil || res.ExitCode != 0 {
		return false
	}
	out := res.Stdout + res.Stderr
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "serve") && len(t) > 5 && (t[5] == ' ' || t[5] == ',') {
			return true
		}
	}
	return false
}

// Detect checks whether ntfy is installed and configured correctly.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.ntfyInstalled(ctx) {
		sev := modules.SeverityFatal
		msg := "ntfy is not installed or not on PATH"
		if m.plat.OS() == "darwin" {
			// ntfy server is not officially supported on macOS — not a fatal
			// error; use ntfy.sh cloud or a Linux machine as the broker.
			sev = modules.SeverityWarning
			msg = "ntfy server not supported on macOS — configure ntfy.sh in abysslink.yaml (https://ntfy.sh)"
		}
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: sev,
			Message:  msg,
		})
		return findings, nil
	}
	slog.Debug("ntfy installed", "bin", m.ntfyBinPath())

	home, err := os.UserHomeDir()
	if err != nil {
		return findings, fmt.Errorf("ntfy detect: get home dir: %w", err)
	}
	cfgPath := filepath.Join(home, serverConfigPath)

	data, err := os.ReadFile(cfgPath) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "config_exists",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("ntfy server config not found at %s", cfgPath),
			})
			return findings, nil
		}
		return findings, fmt.Errorf("ntfy detect: read config: %w", err)
	}

	cfgContent := string(data)
	if strings.Contains(cfgContent, "0.0.0.0") || hasWildcardListen(cfgContent) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "listen_address",
			Severity: modules.SeverityFatal,
			Message:  "ntfy server.yml binds to 0.0.0.0 — must bind to tailnet IP only",
		})
	}

	return findings, nil
}

// hasWildcardListen returns true if the config contains a listen-http line with just a port (":PORT").
func hasWildcardListen(cfgContent string) bool {
	for _, line := range strings.Split(cfgContent, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "listen-http:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "listen-http:"))
			val = strings.Trim(val, `"'`)
			if strings.HasPrefix(val, ":") {
				return true
			}
		}
	}
	return false
}

// Plan computes actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Ntfy.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch f.Check {
		case "installed":
			if m.plat.OS() == "darwin" {
				actions = append(actions, modules.Action{
					Module:      m.Name(),
					Description: "ACTION REQUIRED: configure ntfy.sh cloud in abysslink.yaml (server not supported on macOS)",
					Reversible:  false,
				})
			} else {
				actions = append(actions, modules.Action{
					Module:      m.Name(),
					Description: "install ntfy",
					Reversible:  false,
				})
			}
		case "config_exists", "listen_address":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "write ntfy server.yml bound to tailnet IP",
				Reversible:  true,
			})
		}
	}

	hasInstallFinding := false
	for _, f := range findings {
		if f.Check == "installed" {
			hasInstallFinding = true
		}
	}
	if !hasInstallFinding {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "install ntfy service (launchd/systemd)",
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply installs ntfy if missing and writes the server.yml config bound to the
// tailnet IP. On macOS, server installation is skipped with a warning because
// ntfy does not officially support a macOS server binary; the user must
// configure ntfy.sh or another external broker.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Ntfy.Enabled {
		return nil
	}

	if !m.ntfyInstalled(ctx) {
		if m.plat.OS() == "darwin" {
			slog.Warn("ntfy: server not supported on macOS — add your ntfy.sh topic URL to abysslink.yaml and re-run",
				"docs", "https://docs.ntfy.sh/install/")
			return nil
		}
		slog.Info("ntfy apply: installing ntfy push server")
		if err := m.plat.InstallPackage(ctx, "ntfy"); err != nil {
			return fmt.Errorf("ntfy apply: install ntfy: %w", err)
		}
	}

	tailnetIP, err := m.getTailnetIP(ctx)
	if err != nil {
		return fmt.Errorf("ntfy apply: get tailnet IP: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("ntfy apply: get home dir: %w", err)
	}
	cfgPath := filepath.Join(home, serverConfigPath)

	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("ntfy apply: mkdir %s: %w", filepath.Dir(cfgPath), err)
	}

	data := m.generateServerConfig(tailnetIP, home)
	slog.Info("ntfy apply: writing server config", "path", cfgPath)
	if err := m.audit.WriteFile(cfgPath, data, 0o600, false); err != nil {
		return fmt.Errorf("ntfy apply: write config: %w", err)
	}

	if err := m.ensureAdminUser(ctx); err != nil {
		return fmt.Errorf("ntfy apply: provision admin user: %w", err)
	}

	ntfyBin := m.ntfyBinPath()
	if err := m.plat.ServiceInstall(ctx, platform.ServiceSpec{
		Label:      "dev.abysslink.ntfy",
		Args:       []string{ntfyBin, "serve", "--config", cfgPath},
		KeepAlive:  true,
		RunAtLoad:  true,
		StdoutPath: filepath.Join(home, ".local", "state", "abysslink", "ntfy.log"),
	}); err != nil {
		return fmt.Errorf("ntfy apply: install service: %w", err)
	}

	return nil
}

// generateServerConfig returns the ntfy server.yml contents bound to tailnetIP.
func (m *Module) generateServerConfig(tailnetIP, home string) []byte {
	port := fmt.Sprintf("%d", m.cfg.Modules.Ntfy.ListenPort())
	return []byte(fmt.Sprintf(`# ntfy server config — managed by abysslink
listen-http: "%s:%s"
base-url: "http://%s:%s"
auth-file: "%s/.local/state/abysslink/ntfy/user.db"
auth-default-access: "deny-all"
behind-proxy: false
`, tailnetIP, port, tailnetIP, port, home))
}

// ensureAdminUser provisions the ntfy admin account. Password is stored in the
// keychain and delivered to `ntfy user add` over stdin — never on argv.
func (m *Module) ensureAdminUser(ctx context.Context) error {
	if m.keychain == nil {
		return fmt.Errorf("no keychain backend to store the ntfy admin password")
	}
	pw, err := m.keychain.Get(ctx, keychainService, keychainAccount)
	if err != nil || pw == "" {
		pw, err = modules.GenPassword()
		if err != nil {
			return err
		}
		if err := m.keychain.Set(ctx, keychainService, keychainAccount, pw); err != nil {
			return fmt.Errorf("store ntfy password: %w", err)
		}
	}
	ntfyBin := m.ntfyBinPath()
	res, err := m.runner.RunWithStdin(ctx, strings.NewReader(pw+"\n"+pw+"\n"),
		ntfyBin, "user", "add", "--role=admin", "admin")
	if err != nil {
		return fmt.Errorf("ntfy user add: %w", err)
	}
	if res.ExitCode != 0 && !strings.Contains(res.Stdout+res.Stderr, "already exists") {
		return fmt.Errorf("ntfy user add exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// getTailnetIP runs tailscale ip to get the tailnet IP address.
func (m *Module) getTailnetIP(ctx context.Context) (string, error) {
	res, err := m.runner.Run(ctx, "tailscale", "ip", "--4")
	if err != nil {
		return "", fmt.Errorf("tailscale ip: %w", err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("tailscale ip exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	ip := strings.TrimSpace(res.Stdout)
	if ip == "" {
		return "", fmt.Errorf("tailscale ip returned empty output")
	}
	return ip, nil
}

// Verify checks that server.yml does not bind to 0.0.0.0.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-writes the correct config.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
