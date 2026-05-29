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

const (
	serverConfigPath = ".config/ntfy/server.yml"
)

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

// Detect checks whether ntfy is installed and configured correctly.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Check if ntfy is installed.
	res, err := m.runner.Run(ctx, "ntfy", "version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: modules.SeverityFatal,
			Message:  "ntfy is not installed or not on PATH",
		})
		return findings, nil
	}
	slog.Debug("ntfy version", "output", strings.TrimSpace(res.Stdout))

	// Check if server config exists.
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

	// Security check: verify the listen address does NOT bind to 0.0.0.0.
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
			// A value like ":8080" (no host) binds to all interfaces.
			if strings.HasPrefix(val, ":") {
				return true
			}
		}
	}
	return false
}

// installNtfyBinary installs the ntfy push-notification server.
// On macOS, `brew install ntfy` installs a different unrelated tool; the
// correct package is in the ntfy tap: brew tap ntfy-sh/ntfy + brew install ntfy-sh/ntfy/ntfy.
func (m *Module) installNtfyBinary(ctx context.Context) error {
	if m.plat.OS() == "darwin" {
		return m.installNtfyBinaryDarwin(ctx)
	}
	return m.plat.InstallPackage(ctx, "ntfy")
}

// installNtfyBinaryDarwin taps ntfy-sh/ntfy and installs the ntfy push server
// on macOS. It clones the tap via git directly (not via `brew tap`) so that
// credential suppression flags are applied on the git binary we control.
//
// IMPORTANT: if the tap clone fails we must NOT fall through to
// m.plat.InstallPackage — brew auto-taps on install, which invokes git through
// brew's sanitized environment (GIT_* vars stripped), reproducing the
// credential prompt we are trying to eliminate.
func (m *Module) installNtfyBinaryDarwin(ctx context.Context) error {
	if err := m.cloneNtfyTap(ctx); err != nil {
		return fmt.Errorf("ntfy apply: tap clone failed — install ntfy manually (https://docs.ntfy.sh/install/): %w", err)
	}
	return m.plat.InstallPackage(ctx, "ntfy-sh/ntfy/ntfy")
}

// cloneNtfyTap clones the ntfy Homebrew tap directly via git instead of via
// `brew tap ntfy/ntfy`, eliminating the "Username for 'https://github.com':"
// credential prompt that persists even when GIT_TERMINAL_PROMPT=0 and
// GIT_CONFIG_COUNT env vars are set.
//
// Root cause of the prompt: Homebrew's Ruby runtime sanitizes the subprocess
// environment before forking git — it resets PATH and strips GIT_* env vars.
// Every env-based approach (GIT_TERMINAL_PROMPT, GIT_CONFIG_COUNT, git wrapper
// in PATH) is therefore ineffective for brew-internal git calls. Calling git
// ourselves with -c credential.helper= works because the -c flag is parsed by
// git itself before any external config and cannot be stripped by brew.
//
// After this function cloneNtfyTap succeeds, brew install reads the formula
// from the already-present tap directory without invoking git again (Homebrew
// skips git operations on taps when HOMEBREW_NO_AUTO_UPDATE=1, which abysslink
// sets at startup).
func (m *Module) cloneNtfyTap(ctx context.Context) error {
	res, err := m.runner.Run(ctx, "brew", "--repository")
	if err != nil {
		return fmt.Errorf("brew --repository: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("brew --repository exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	// Tap directory for `brew tap ntfy-sh/ntfy`.
	// The Homebrew convention maps tap "user/repo" →
	//   clone URL: https://github.com/user/homebrew-repo.git
	//   local dir: $(brew --repository)/Library/Taps/user/homebrew-repo
	// Using ntfy-sh/ntfy (not the older ntfy/ntfy): the ntfy/homebrew-ntfy
	// GitHub repo does not exist as a public repo — GitHub returns 401 for
	// non-existent repos (to prevent enumeration), triggering the git
	// credential prompt even though no real authentication is needed.
	tapDir := filepath.Join(strings.TrimSpace(res.Stdout), "Library", "Taps", "ntfy-sh", "homebrew-ntfy")
	if _, statErr := os.Stat(tapDir); statErr == nil {
		return nil // tap already present; brew install will use it as-is
	}
	if err := os.MkdirAll(filepath.Dir(tapDir), 0o755); err != nil {
		return fmt.Errorf("create tap parent dir: %w", err)
	}
	res, err = m.runner.RunWithEnv(ctx,
		map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		"git",
		"-c", "credential.helper=",
		"-c", "http.prompt=false",
		"clone", "--depth=1", "--quiet",
		"https://github.com/ntfy-sh/homebrew-ntfy.git",
		tapDir,
	)
	if err != nil {
		return fmt.Errorf("git clone ntfy tap: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("git clone ntfy tap exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// generateServerConfig returns the ntfy server.yml contents bound to tailnetIP.
// home must be an absolute path (from os.UserHomeDir) so the auth-file path is
// correct even when HOME is unset (e.g. launchd agent context).
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
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install ntfy",
				Reversible:  false,
			})
		case "config_exists", "listen_address":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "write ntfy server.yml bound to tailnet IP",
				Reversible:  true,
			})
		}
	}

	// Plan service install only when the binary is present (hasInstallFinding means
	// the binary is MISSING, so we skip service install — can't install a service
	// for a binary that doesn't exist yet; Apply handles it in order).
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
// tailnet IP.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Ntfy.Enabled {
		return nil
	}

	// Install the ntfy push server if it is not on PATH.
	if res, verErr := m.runner.Run(ctx, "ntfy", "serve", "--help"); verErr != nil || res.ExitCode != 0 {
		slog.Info("ntfy apply: installing ntfy push server")
		if err := m.installNtfyBinary(ctx); err != nil {
			return fmt.Errorf("ntfy apply: install ntfy: %w", err)
		}
	}

	// Retrieve the tailnet IP from tailscale status.
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

	if err := m.plat.ServiceInstall(ctx, platform.ServiceSpec{
		Label:      "dev.abysslink.ntfy",
		Args:       []string{"ntfy", "serve", "--config", cfgPath},
		KeepAlive:  true,
		RunAtLoad:  true,
		StdoutPath: filepath.Join(home, ".local", "state", "abysslink", "ntfy.log"),
	}); err != nil {
		return fmt.Errorf("ntfy apply: install service: %w", err)
	}

	return nil
}

// ensureAdminUser provisions the ntfy admin account, generating a password
// stored in the keychain. The password is delivered to `ntfy user add` over
// stdin (twice, for confirmation) — never on argv. Idempotent: a pre-existing
// keychain password is reused and an already-present user is left alone.
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
	// `ntfy user add --role=admin admin` reads the password from stdin twice.
	res, err := m.runner.RunWithStdin(ctx, strings.NewReader(pw+"\n"+pw+"\n"),
		"ntfy", "user", "add", "--role=admin", "admin")
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
