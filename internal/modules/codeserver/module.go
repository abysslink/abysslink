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
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
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

// isBindAddrTailnetOnly returns true when addr is bound to a specific
// (non-wildcard, non-loopback) host — the only acceptable value is a tailnet
// IP or MagicDNS name. It rejects:
//   - empty addr
//   - empty host (":8080" — IPv4 all-interfaces)
//   - unspecified IPs ("0.0.0.0", "::", "[::]:8080", with or without port)
//   - loopback IPs ("127.0.0.1", "::1") and the "localhost" hostname
//
// Parsing goes through net.SplitHostPort / net.ParseIP rather than string
// prefixes so variants like "[::]:8080", bare "0.0.0.0", or "localhost:8080"
// cannot slip through (NET-09; mirrors ntfy's hasWildcardListen intent).
func isBindAddrTailnetOnly(addr string) bool {
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port (e.g. bare "0.0.0.0", "::", "localhost") or malformed —
		// evaluate the whole string as the host so wildcards without a port
		// are still rejected. Strip IPv6 brackets ("[::]") so ParseIP sees
		// the literal.
		host = addr
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	if host == "" {
		return false // ":8080" binds all interfaces
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsLoopback()
	}
	// Non-IP hostname: reject the well-known loopback name; anything else
	// (e.g. a MagicDNS name) is accepted as a specific host.
	return !strings.EqualFold(host, "localhost")
}

// codeServerConfig represents the code-server config.yaml structure.
// abysslink writes hashed-password (argon2id PHC string) — never the plaintext
// password — so no secret sits at rest in config.yaml; the plaintext lives
// only in the OS keychain. Password is still parsed for legacy/user-managed
// configs.
type codeServerConfig struct {
	BindAddr       string `yaml:"bind-addr"`
	Auth           string `yaml:"auth"`
	Password       string `yaml:"password,omitempty"`
	HashedPassword string `yaml:"hashed-password,omitempty"`
	Cert           bool   `yaml:"cert"`
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

	// Flag a plaintext password at rest: abysslink writes hashed-password
	// (argon2id) only; a plaintext `password:` key is a downgrade worth a
	// doctor warning (it is remediated on the next apply).
	if csCfg.Password != "" {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "plaintext_password",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("code-server config at %s stores a plaintext password — run `abysslink up --apply` to convert it to hashed-password (argon2id)", cfgPath),
		})
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
		case "config_exists", "config_readable", "config_valid", "bind_addr_tailnet", "plaintext_password":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: fmt.Sprintf("write code-server config with bind-addr <tailnetIP>:%s and hashed-password (argon2id)", codeServerPort),
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

// Apply installs code-server, writes a tailnet-bound config whose
// hashed-password (argon2id) derives from the keychain password, and installs
// the background service. The config is only rewritten when it has drifted
// from the desired state (no audit/backup churn on a converged system).
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
	if err := m.writeConfigIfNeeded(cfgPath, ip, pw); err != nil {
		return err
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

// writeConfigIfNeeded writes the code-server config.yaml only when the
// on-disk config does not already converge to the desired state. The desired
// state stores hashed-password (argon2id), never the plaintext, and the hash
// is salted — so a naive byte-compare would differ on every run and cause
// audit/backup churn (the bug this guards against). Convergence means:
// same bind-addr, password auth, no cert, no plaintext password, and a
// hashed-password that verifies against the keychain password.
func (m *Module) writeConfigIfNeeded(cfgPath, ip, pw string) error {
	bindAddr := ip + ":" + codeServerPort

	if existing, err := os.ReadFile(cfgPath); err == nil { //nolint:gosec // G304: module config path resolved internally
		var cur codeServerConfig
		if yaml.Unmarshal(existing, &cur) == nil &&
			cur.BindAddr == bindAddr &&
			cur.Auth == "password" &&
			!cur.Cert &&
			cur.Password == "" &&
			verifyArgon2id(cur.HashedPassword, pw) {
			slog.Debug("code-server apply: config already converged, not rewriting", "path", cfgPath)
			return nil
		}
	}

	hashed, err := hashArgon2id(pw)
	if err != nil {
		return fmt.Errorf("code-server apply: hash password: %w", err)
	}
	data, err := yaml.Marshal(codeServerConfig{
		BindAddr:       bindAddr,
		Auth:           "password",
		HashedPassword: hashed,
		Cert:           false,
	})
	if err != nil {
		return fmt.Errorf("code-server apply: marshal config: %w", err)
	}
	if err := m.audit.WriteFile(cfgPath, data, 0o600, false); err != nil {
		return fmt.Errorf("code-server apply: write config: %w", err)
	}
	return nil
}

// argon2id parameters for the code-server hashed-password (x/crypto/argon2
// recommended interactive parameters).
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// hashArgon2id returns pw hashed as a PHC-format argon2id string, the format
// code-server accepts for hashed-password. Writing the hash instead of the
// plaintext removes the at-rest secret from config.yaml.
func hashArgon2id(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyArgon2id reports whether the PHC-format argon2id hash matches pw. Any
// parse failure or non-argon2id variant returns false (caller then rewrites
// the config with a fresh hash).
func verifyArgon2id(phc, pw string) bool {
	parts := strings.Split(phc, "$")
	// "" / "argon2id" / "v=19" / "m=…,t=…,p=…" / salt / hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var mem, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, time, mem, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ensurePassword returns the code-server password from the keychain. Only a
// definitive miss (secrets.ErrNotFound, or a successful Get returning an
// empty value) triggers generation of a fresh password. Any other Get failure
// — keychain locked, backend missing, transient error — aborts: generating
// and storing a NEW password while config.yaml still holds the hash of the
// old one would desync the two (NET-12; mirrors ntfy's
// getOrCreateAdminPassword). Never placed on argv (keychain uses stdin).
func (m *Module) ensurePassword(ctx context.Context) (string, error) {
	if m.keychain == nil {
		return "", fmt.Errorf("no keychain backend available to store the code-server password")
	}
	pw, err := m.keychain.Get(ctx, "abysslink", "code-server-password")
	switch {
	case err == nil && pw != "":
		return pw, nil
	case err == nil || errors.Is(err, secrets.ErrNotFound):
		// Definitively absent — safe to generate and store a new password.
		pw, err = modules.GenPassword()
		if err != nil {
			return "", err
		}
		if err := m.keychain.Set(ctx, "abysslink", "code-server-password", pw); err != nil {
			return "", fmt.Errorf("store code-server password: %w", err)
		}
		return pw, nil
	default:
		return "", fmt.Errorf("code-server: keychain unavailable — refusing to generate a new password "+
			"(would desync the keychain and config.yaml): %w", err)
	}
}

// Verify is a no-op for the codeserver module — all checks run in Detect.
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
