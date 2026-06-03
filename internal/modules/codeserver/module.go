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

package codeserver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

const (
	codeServerPort       = "8080"
	codeServerConfigPath = ".config/code-server/config.yaml"
)

// isBindAddrTailnetOnly returns true when addr is bound to a specific tailnet IP
// (not empty, not 0.0.0.0, not 127.0.0.1).
func isBindAddrTailnetOnly(addr string) bool {
	return addr != "" &&
		!strings.HasPrefix(addr, "0.0.0.0:") &&
		!strings.HasPrefix(addr, "127.0.0.1:")
}

// codeServerConfig represents the code-server config.yaml structure.
type codeServerConfig struct {
	BindAddr string `yaml:"bind-addr"`
	Auth     string `yaml:"auth"`
	Password string `yaml:"password,omitempty"`
	Cert     bool   `yaml:"cert"`
}

// Module implements the code-server optional module.
type Module struct {
	runner   shell.Runner
	cfg      *config.Config
	plat     platform.Platform
	keychain secrets.KeychainStore
	audit    audit.AuditWriter
}

// New returns a new code-server Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, plat: d.Platform, keychain: d.Keychain, audit: d.Audit}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "code-server" }

// Deps returns the modules this module depends on.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect inspects the current system state for the code-server installation.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.cfg.Modules.CodeServer.Enabled {
		slog.Debug("code-server module disabled, skipping detect")
		return nil, nil
	}

	// Check whether code-server binary is installed.
	res, err := m.runner.Run(ctx, "code-server", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "code_server_installed",
			Severity: modules.SeverityFatal,
			Message:  "code-server binary not found — install code-server manually",
		})
		// Cannot check config without the binary; return early.
		return findings, nil
	}

	slog.Debug("code-server version", "output", strings.TrimSpace(res.Stdout))

	// Check the config file.
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("code-server: home dir: %w", err)
	}
	cfgPath := filepath.Join(home, codeServerConfigPath)

	data, err := os.ReadFile(cfgPath) //nolint:gosec // G304: cfgPath is the module config path resolved internally, not user input
	if err != nil {
		if os.IsNotExist(err) {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "config_exists",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("code-server config not found at %s", cfgPath),
			})
		} else {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "config_readable",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("cannot read code-server config at %s: %v", cfgPath, err),
			})
		}
		return findings, nil
	}

	var csCfg codeServerConfig
	if err := yaml.Unmarshal(data, &csCfg); err != nil {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "config_valid",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("code-server config at %s is not valid YAML: %v", cfgPath, err),
		})
		return findings, nil
	}

	// Validate bind-addr: must not be 0.0.0.0 or 127.0.0.1.
	bindAddr := csCfg.BindAddr
	if !isBindAddrTailnetOnly(bindAddr) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "bind_addr_tailnet",
			Severity: modules.SeverityWarning,
			Message: fmt.Sprintf(
				"code-server bind-addr %q must be set to <tailnetIP>:%s (not 0.0.0.0 or 127.0.0.1)",
				bindAddr, codeServerPort,
			),
		})
	}

	return findings, nil
}

// Plan computes the actions needed to reach the desired state.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.CodeServer.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch f.Check {
		case "code_server_installed":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install code-server (see https://coder.com/docs/code-server/install)",
				Reversible:  false,
			})
		case "config_exists", "config_readable", "config_valid", "bind_addr_tailnet":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: fmt.Sprintf("write code-server config with bind-addr <tailnetIP>:%s", codeServerPort),
				Reversible:  true,
			})
		}
	}

	// Always include the ACL reminder.
	actions = append(actions, modules.Action{
		Module:      m.Name(),
		Description: fmt.Sprintf("grant ACL tcp/%s for code-server in Tailscale policy", codeServerPort),
		Reversible:  false,
	})

	return actions, nil
}

// Apply installs code-server, writes a tailnet-bound config with a keychain
// password, and installs the background service.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.CodeServer.Enabled {
		return nil
	}

	if res, err := m.runner.Run(ctx, "code-server", "--version"); err != nil || res.ExitCode != 0 {
		slog.Info("code-server apply: installing code-server")
		if err := m.plat.InstallPackage(ctx, "code-server"); err != nil {
			return fmt.Errorf("code-server apply: install: %w", err)
		}
	}

	ip, err := modules.TailnetIP(ctx, m.runner)
	if err != nil {
		return fmt.Errorf("code-server apply: %w", err)
	}

	pw, err := m.ensurePassword(ctx)
	if err != nil {
		return fmt.Errorf("code-server apply: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("code-server apply: home dir: %w", err)
	}
	cfgPath := filepath.Join(home, codeServerConfigPath)
	if err := os.MkdirAll(filepath.Join(home, ".config", "code-server"), 0o700); err != nil {
		return fmt.Errorf("code-server apply: mkdir config: %w", err)
	}
	// #nosec G117 -- code-server's own config file legitimately stores its auth
	// password (generated/keychain-sourced, written 0o600); this is the config
	// format code-server requires, not a hardcoded credential.
	data, err := yaml.Marshal(codeServerConfig{
		BindAddr: ip + ":" + codeServerPort,
		Auth:     "password",
		Password: pw,
		Cert:     false,
	})
	if err != nil {
		return fmt.Errorf("code-server apply: marshal config: %w", err)
	}
	if err := m.audit.WriteFile(cfgPath, data, 0o600, false); err != nil {
		return fmt.Errorf("code-server apply: write config: %w", err)
	}

	if err := m.plat.ServiceInstall(ctx, platform.ServiceSpec{
		Label:     "dev.abysslink.codeserver",
		Args:      []string{"code-server"},
		KeepAlive: true,
		RunAtLoad: true,
	}); err != nil {
		return fmt.Errorf("code-server apply: install service: %w", err)
	}
	slog.Info("code-server apply: configured and service installed", "bind", ip+":"+codeServerPort)
	return nil
}

// ensurePassword returns the code-server password from the keychain, generating
// and storing one on first run. Never placed on argv (keychain uses stdin).
func (m *Module) ensurePassword(ctx context.Context) (string, error) {
	if m.keychain == nil {
		return "", fmt.Errorf("no keychain backend available to store the code-server password")
	}
	if pw, err := m.keychain.Get(ctx, "abysslink", "code-server-password"); err == nil && pw != "" {
		return pw, nil
	}
	pw, err := modules.GenPassword()
	if err != nil {
		return "", err
	}
	if err := m.keychain.Set(ctx, "abysslink", "code-server-password", pw); err != nil {
		return "", fmt.Errorf("store code-server password: %w", err)
	}
	return pw, nil
}

// Verify re-runs Detect to confirm code-server is correctly configured.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
