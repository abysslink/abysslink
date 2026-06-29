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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

const (
	serverConfigPath       = ".config/ntfy/server.yml"
	dockerServerConfigPath = ".config/ntfy/server-docker.yml"
	dockerContainerName    = "abysslink-ntfy"
	// stateDirPath is the auth-file parent directory (relative to $HOME) shared
	// by the native and Docker paths. The native server.yml points its auth-file
	// here, so it MUST exist before `ntfy serve` starts.
	stateDirPath = ".local/state/abysslink/ntfy"
	// dockerImage is pinned by manifest-list digest (supply chain): a floating
	// `latest` tag could silently swap the image under us. The tag is kept for
	// human readability; the digest is authoritative for docker pull/run.
	dockerImage = "binwiederhier/ntfy:v2.24@sha256:f8a9b104313b87cc24ae4f775f39e6328205b57dff6ede3eaf098a91e5d79f59"
)

// Module implements the ntfy module.
type Module struct {
	runner   shell.Runner
	cfg      *config.Config
	audit    audit.AuditWriter
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

// ntfyBinPath returns the full path to a native ntfy server binary.
// On macOS, users who manually install a server build should place it at
// ~/.local/bin/ntfy; abysslink prefers Docker on macOS when Docker is
// available. On Linux the system package installs the binary on PATH.
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

// ntfyBinaryPresent returns true when the ntfy binary exists and includes
// the 'serve' subcommand (server build, not client-only).
func (m *Module) ntfyBinaryPresent(ctx context.Context) bool {
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

// dockerAvailable returns true when the Docker CLI is on PATH and the daemon
// is reachable. Docker Desktop on macOS provides this.
func (m *Module) dockerAvailable(ctx context.Context) bool {
	res, err := m.runner.Run(ctx, "docker", "info")
	return err == nil && res.ExitCode == 0
}

// ntfyDockerRunning returns true when the abysslink-ntfy container exists and
// is in the running state.
func (m *Module) ntfyDockerRunning(ctx context.Context) bool {
	res, err := m.runner.Run(ctx, "docker", "inspect",
		"--format={{.State.Running}}", dockerContainerName)
	return err == nil && res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "true"
}

// ntfyDockerExists returns true when the abysslink-ntfy container exists in any
// state (running or stopped) — used by Teardown, which must remove a stopped
// container too, not only a running one.
func (m *Module) ntfyDockerExists(ctx context.Context) bool {
	res, err := m.runner.Run(ctx, "docker", "inspect",
		"--format={{.Id}}", dockerContainerName)
	return err == nil && res.ExitCode == 0
}

// Teardown removes the abysslink-ntfy Docker container — a non-file resource
// that uninstall's file-backup reversal cannot undo (the original guide's docker
// mode on macOS). It is best-effort and idempotent: when Docker is unavailable
// or the container is already gone it returns no items and no error. Native
// (non-Docker) ntfy is service- and file-backed, so it is reversed by the audit
// log and needs no teardown here. Third-party packages are intentionally left
// installed (see uninstall's removeAbysslinkDirs note).
func (m *Module) Teardown(ctx context.Context, dryRun bool) ([]string, error) {
	if !m.dockerAvailable(ctx) || !m.ntfyDockerExists(ctx) {
		return nil, nil
	}
	desc := "docker container " + dockerContainerName
	if dryRun {
		return []string{desc}, nil
	}
	res, err := m.runner.Run(ctx, "docker", "rm", "-f", dockerContainerName)
	if err != nil {
		return nil, fmt.Errorf("ntfy teardown: docker rm: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("ntfy teardown: docker rm exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return []string{"removed " + desc}, nil
}

// ntfyDockerIPDrift returns true when the running container's port binding
// does not include the current tailnet IP — meaning the IP changed since the
// container was created and it must be recreated.
func (m *Module) ntfyDockerIPDrift(ctx context.Context, tailnetIP string) bool {
	port := fmt.Sprintf("%d", m.cfg.Modules.Ntfy.ListenPort())
	res, err := m.runner.Run(ctx, "docker", "inspect",
		"--format={{range $k,$v := .NetworkSettings.Ports}}{{range $v}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}",
		dockerContainerName)
	if err != nil || res.ExitCode != 0 {
		return false
	}
	want := tailnetIP + ":" + port
	return !strings.Contains(res.Stdout, want)
}

// ntfyInstalled returns true when either a native server binary is available
// or the Docker container is running.
func (m *Module) ntfyInstalled(ctx context.Context) bool {
	return m.ntfyBinaryPresent(ctx) || m.ntfyDockerRunning(ctx)
}

// Detect checks whether ntfy is installed and configured correctly.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.ntfyInstalled(ctx) {
		sev := modules.SeverityFatal
		msg := "ntfy is not installed or not on PATH"
		if m.plat.OS() == "darwin" {
			if m.dockerAvailable(ctx) {
				sev = modules.SeverityWarning
				msg = "ntfy server not running — will install via Docker on apply"
			} else {
				sev = modules.SeverityWarning
				msg = "ntfy server not supported on macOS without Docker — install Docker Desktop or configure ntfy.sh in abysslink.yaml"
			}
		}
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: sev,
			Message:  msg,
		})
		return findings, nil
	}
	slog.Debug("ntfy available", "docker", m.ntfyDockerRunning(ctx))

	home, err := os.UserHomeDir()
	if err != nil {
		return findings, fmt.Errorf("ntfy detect: get home dir: %w", err)
	}
	cfgPath := filepath.Join(home, serverConfigPath)

	data, err := os.ReadFile(cfgPath) //nolint:gosec // G304: cfgPath is the module config path resolved internally, not user input
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
	if strings.Contains(cfgContent, "0.0.0.0") || strings.Contains(cfgContent, "[::]") || hasWildcardListen(cfgContent) {
		// Docker mode intentionally uses 0.0.0.0 inside the container; port
		// binding to the tailnet IP is enforced by the docker -p flag.
		if !m.ntfyDockerRunning(ctx) {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "listen_address",
				Severity: modules.SeverityFatal,
				Message:  "ntfy server.yml binds to 0.0.0.0 — must bind to tailnet IP only (or use Docker mode)",
			})
		}
	} else {
		// Emit explicit OK so "check ran and passed" is distinguishable from
		// "check never ran" in the threat-model tri-state (D-03 / DOC-01).
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "listen_address",
			Severity: modules.SeverityOK,
			Message:  "listen_address: ntfy server.yml binds to tailnet IP only",
		})
	}

	// Reachability probe — the universal fix for the macOS Docker-Desktop trap.
	// A container can be running and its config can name the tailnet IP, yet the
	// port never actually publishes (config-only checks all pass), so phone
	// notifications are silently dropped. Catch it by dialing the tailnet IP:port.
	if f := m.reachabilityFinding(ctx); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// reachabilityFinding probes whether ntfy actually answers on the tailnet
// IP:port and returns the matching finding (nil when the tailnet IP cannot be
// resolved — e.g. tailscale not up). Extracted from Detect to keep it under the
// gocyclo ceiling.
func (m *Module) reachabilityFinding(ctx context.Context) *modules.Finding {
	ip, err := m.getTailnetIP(ctx)
	if err != nil || ip == "" {
		return nil
	}
	port := m.cfg.Modules.Ntfy.ListenPort()
	if m.probeNtfyReachable(ctx, ip, port) {
		return &modules.Finding{
			Module:   m.Name(),
			Check:    "reachable",
			Severity: modules.SeverityOK,
			Message:  fmt.Sprintf("reachable: ntfy answers on the tailnet at %s:%d", ip, port),
		}
	}
	msg := fmt.Sprintf("ntfy is configured for %s:%d but is UNREACHABLE there — phone notifications are being silently dropped", ip, port)
	if m.plat.OS() == "darwin" && m.ntfyDockerRunning(ctx) {
		msg += ". On Docker Desktop for Mac a container cannot publish to a host interface IP; run ntfy natively bound to the tailnet IP, or bridge " +
			fmt.Sprintf("%s:%d -> 127.0.0.1:%d", ip, port, port)
	}
	return &modules.Finding{
		Module:   m.Name(),
		Check:    "reachable",
		Severity: modules.SeverityWarning,
		Message:  msg,
	}
}

// probeNtfyReachable reports whether the ntfy server actually answers on
// ip:port over the tailnet. It GETs the health endpoint with a short timeout;
// any transport error or non-2xx means unreachable. This is an HTTP request,
// not a shell command, so it does not go through shell.Runner.
func (m *Module) probeNtfyReachable(ctx context.Context, ip string, port int) bool {
	url := "http://" + net.JoinHostPort(ip, strconv.Itoa(port)) + "/v1/health"
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: health probe to the tailnet IP (from `tailscale ip`) + configured port; tailnet-only internal reachability check
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// hasWildcardListen returns true if the config contains a listen-http line that
// binds to all interfaces. It detects:
//   - bare ":PORT" (IPv4 all-interfaces)
//   - "[::]:PORT" or bare "::" (IPv6 wildcard)
func hasWildcardListen(cfgContent string) bool {
	for _, line := range strings.Split(cfgContent, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "listen-http:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "listen-http:"))
			val = strings.Trim(val, `"'`)
			// Bare ":PORT" — IPv4 all-interfaces.
			if strings.HasPrefix(val, ":") && !strings.HasPrefix(val, "::") && !strings.HasPrefix(val, "[::]") {
				return true
			}
			// "[::]:PORT" or bare "::" — IPv6 wildcard.
			if val == "::" || strings.HasPrefix(val, "[::]") {
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
		// SeverityOK findings are the healthy tri-state signal (D-03) — they
		// confirm a check ran and passed. Planning remediation for them would
		// schedule a config rewrite forever on a correctly configured ntfy
		// (non-convergent plan).
		if f.Severity == modules.SeverityOK {
			continue
		}
		switch f.Check {
		case "installed":
			desc := "install ntfy"
			if m.plat.OS() == "darwin" {
				if m.dockerAvailable(ctx) {
					desc = "run ntfy server in Docker (docker pull + docker run)"
				} else {
					desc = "ACTION REQUIRED: install Docker Desktop or configure ntfy.sh in abysslink.yaml"
				}
			}
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: desc,
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

	hasInstallFinding := false
	for _, f := range findings {
		if f.Check == "installed" {
			hasInstallFinding = true
		}
	}
	// Docker mode on macOS manages the container itself; no launchd/systemd service needed.
	dockerMode := m.plat.OS() == "darwin" && m.ntfyDockerRunning(ctx)
	if !hasInstallFinding && !dockerMode {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "install ntfy service (launchd/systemd)",
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply installs ntfy if missing and writes the server config.
// On macOS: uses Docker if available; otherwise skips with a warning.
// On Linux: installs via system package manager.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Ntfy.Enabled {
		return nil
	}
	tailnetIP, err := m.getTailnetIP(ctx)
	if err != nil {
		return fmt.Errorf("ntfy apply: get tailnet IP: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("ntfy apply: get home dir: %w", err)
	}
	return m.applyNative(ctx, tailnetIP, home)
}

// applyNative handles the install path for both Docker (macOS) and native (Linux) modes.
func (m *Module) applyNative(ctx context.Context, tailnetIP, home string) error {
	if m.plat.OS() == "darwin" && m.ntfyDockerRunning(ctx) {
		if m.ntfyDockerIPDrift(ctx, tailnetIP) {
			slog.Info("ntfy: tailnet IP changed — recreating Docker container", "ip", tailnetIP)
			if _, err := m.runner.Run(ctx, "docker", "rm", "-f", dockerContainerName); err != nil {
				slog.Warn("ntfy: docker rm cleanup (best-effort)", "err", err)
			}
			return m.applyDocker(ctx, tailnetIP, home)
		}
		return nil
	}
	if !m.ntfyInstalled(ctx) {
		return m.install(ctx, tailnetIP, home)
	}
	return m.configureNative(ctx, tailnetIP, home)
}

// install sets up ntfy from scratch (first run).
func (m *Module) install(ctx context.Context, tailnetIP, home string) error {
	switch {
	case m.plat.OS() == "darwin" && m.dockerAvailable(ctx):
		if err := m.applyDocker(ctx, tailnetIP, home); err != nil {
			return fmt.Errorf("ntfy apply: docker: %w", err)
		}
		return nil
	case m.plat.OS() == "darwin":
		slog.Warn("ntfy: Docker not available; install Docker Desktop or configure ntfy.sh",
			"docs", "https://docs.docker.com/desktop/install/mac-install/")
		return nil
	default:
		slog.Info("ntfy apply: installing ntfy push server")
		if err := m.plat.InstallPackage(ctx, "ntfy"); err != nil {
			return fmt.Errorf("ntfy apply: install ntfy: %w", err)
		}
		return m.configureNative(ctx, tailnetIP, home)
	}
}

// configureNative writes config and registers the service for native (non-Docker) installs.
func (m *Module) configureNative(ctx context.Context, tailnetIP, home string) error {
	cfgPath := filepath.Join(home, serverConfigPath)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("ntfy apply: mkdir %s: %w", filepath.Dir(cfgPath), err)
	}
	// The generated server.yml points auth-file at the state dir; ntfy will not
	// create the parent itself, so a missing dir breaks `ntfy user add` and the
	// server's auth DB on first run.
	stateDir := filepath.Join(home, stateDirPath)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("ntfy apply: mkdir %s: %w", stateDir, err)
	}
	data := m.generateServerConfig(tailnetIP, home)
	slog.Info("ntfy apply: writing server config", "path", cfgPath)
	if err := m.audit.WriteFile(cfgPath, data, 0o600, false); err != nil {
		return fmt.Errorf("ntfy apply: write config: %w", err)
	}
	if err := m.ensureAdminUser(ctx, cfgPath); err != nil {
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

// applyDocker sets up the ntfy server as a Docker container on macOS.
// The container is bound to the tailnet IP via -p, so ntfy can listen on
// 0.0.0.0 inside the container without violating the "tailnet IP only" rule.
func (m *Module) applyDocker(ctx context.Context, tailnetIP, home string) error {
	port := fmt.Sprintf("%d", m.cfg.Modules.Ntfy.ListenPort())

	// Write a Docker-specific config: ntfy listens on all interfaces inside the
	// container; Docker's -p flag restricts the host binding to the tailnet IP.
	cfgPath := filepath.Join(home, dockerServerConfigPath)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	dataDir := filepath.Join(home, stateDirPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}
	// Use MagicDNS hostname for base-url so the phone URL survives IP changes.
	// Guard the empty case (status ok-but-empty AND the IP fallback failed):
	// an empty hostname would render a useless `base-url: "http://:2586"`.
	// tailnetIP is always non-empty here (Apply resolved it before calling us).
	hostname := m.getTailnetHostname(ctx)
	if hostname == "" {
		hostname = tailnetIP
	}
	dockerCfg := fmt.Sprintf(`# ntfy Docker config — managed by abysslink
listen-http: "0.0.0.0:80"
base-url: "http://%s:%s"
upstream-base-url: "https://ntfy.sh"
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "deny-all"
behind-proxy: false
`, hostname, port)
	if err := m.audit.WriteFile(cfgPath, []byte(dockerCfg), 0o600, false); err != nil {
		return fmt.Errorf("write docker config: %w", err)
	}

	slog.Info("ntfy: pulling Docker image", "image", dockerImage)
	pullRes, err := m.runner.Run(ctx, "docker", "pull", dockerImage)
	if err != nil {
		return fmt.Errorf("docker pull: %w", err)
	}
	if pullRes.ExitCode != 0 {
		return fmt.Errorf("docker pull exited %d: %s", pullRes.ExitCode, strings.TrimSpace(pullRes.Stderr))
	}

	// Remove any existing container before (re)creating.
	if _, err := m.runner.Run(ctx, "docker", "rm", "-f", dockerContainerName); err != nil {
		slog.Warn("ntfy: docker rm cleanup (best-effort)", "err", err)
	}

	slog.Info("ntfy: starting Docker container", "name", dockerContainerName, "bind", tailnetIP+":"+port)
	runRes, err := m.runner.Run(ctx, "docker", "run", "-d",
		"--name", dockerContainerName,
		"--restart", "always",
		"-p", fmt.Sprintf("%s:%s:80", tailnetIP, port),
		"-v", cfgPath+":/etc/ntfy/server.yml:ro",
		"-v", dataDir+":/var/lib/ntfy",
		dockerImage,
		"serve",
		"--config", "/etc/ntfy/server.yml",
	)
	if err != nil {
		return fmt.Errorf("docker run: %w", err)
	}
	if runRes.ExitCode != 0 {
		return fmt.Errorf("docker run exited %d: %s", runRes.ExitCode, strings.TrimSpace(runRes.Stderr))
	}

	if err := m.ensureAdminUserDocker(ctx); err != nil {
		return fmt.Errorf("provision admin user: %w", err)
	}

	return nil
}

// ensureAdminUserDocker provisions the ntfy admin account inside the Docker
// container using `docker exec`. Password is read from keychain and piped via
// stdin — never placed on argv.
func (m *Module) ensureAdminUserDocker(ctx context.Context) error {
	pw, err := m.getOrCreateAdminPassword(ctx)
	if err != nil {
		return err
	}
	res, err := m.runner.RunWithStdin(ctx, strings.NewReader(pw+"\n"+pw+"\n"),
		"docker", "exec", "-i", dockerContainerName,
		"ntfy", "user", "add", "--role=admin", "admin",
	)
	if err != nil {
		return fmt.Errorf("docker exec ntfy user add: %w", err)
	}
	if res.ExitCode != 0 {
		if !strings.Contains(res.Stdout+res.Stderr, "already exists") {
			return fmt.Errorf("ntfy user add exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		// Admin already exists: force the server-side password to match the
		// keychain so user.db and keychain cannot diverge (NET-12).
		cres, cerr := m.runner.RunWithStdin(ctx, strings.NewReader(pw+"\n"+pw+"\n"),
			"docker", "exec", "-i", dockerContainerName,
			"ntfy", "user", "change-pass", "admin",
		)
		if cerr != nil {
			return fmt.Errorf("docker exec ntfy user change-pass: %w", cerr)
		}
		if cres.ExitCode != 0 {
			return fmt.Errorf("ntfy user change-pass exited %d: %s", cres.ExitCode, strings.TrimSpace(cres.Stderr))
		}
	}
	return nil
}

// getOrCreateAdminPassword returns the ntfy admin password from the keychain.
// Only a definitive miss (secrets.ErrNotFound, or a successful Get returning
// an empty value) triggers generation of a fresh password. Any other Get
// failure — keychain locked, backend missing, transient error — aborts:
// generating and storing a NEW password while the ntfy user.db still holds
// the old one would desync the two permanently, because `ntfy user add` on an
// existing admin is tolerated as "already exists" and never updates the
// server-side password (NET-12).
func (m *Module) getOrCreateAdminPassword(ctx context.Context) (string, error) {
	if m.keychain == nil {
		return "", fmt.Errorf("no keychain backend to store the ntfy admin password")
	}
	pw, err := m.keychain.Get(ctx, keychainService, keychainAccount)
	switch {
	case err == nil && pw != "":
		return pw, nil
	case err == nil || errors.Is(err, secrets.ErrNotFound):
		// Definitively absent — safe to generate and store a new password.
		pw, err = modules.GenPassword()
		if err != nil {
			return "", err
		}
		if err := m.keychain.Set(ctx, keychainService, keychainAccount, pw); err != nil {
			return "", fmt.Errorf("store ntfy password: %w", err)
		}
		return pw, nil
	default:
		return "", fmt.Errorf("ntfy: keychain unavailable — refusing to generate a new admin password "+
			"(would desync the keychain and the ntfy user.db): %w", err)
	}
}

// generateServerConfig returns the ntfy server.yml for native (non-Docker) installs.
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

// ensureAdminUser provisions the ntfy admin account for native installs.
//
// Both user commands MUST carry `--config cfgPath`: without it the ntfy CLI
// reads its default /etc/ntfy/server.yml, so the admin user would land in the
// wrong auth DB (or the command would fail outright) while the abysslink
// server — launched with `--config ~/.config/ntfy/server.yml` — keeps serving
// an empty user.db against auth-default-access deny-all.
func (m *Module) ensureAdminUser(ctx context.Context, cfgPath string) error {
	pw, err := m.getOrCreateAdminPassword(ctx)
	if err != nil {
		return err
	}
	ntfyBin := m.ntfyBinPath()
	res, err := m.runner.RunWithStdin(ctx, strings.NewReader(pw+"\n"+pw+"\n"),
		ntfyBin, "user", "add", "--config", cfgPath, "--role=admin", "admin")
	if err != nil {
		return fmt.Errorf("ntfy user add: %w", err)
	}
	if res.ExitCode != 0 {
		if !strings.Contains(res.Stdout+res.Stderr, "already exists") {
			return fmt.Errorf("ntfy user add exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		// Admin already exists: force the server-side password to match the
		// keychain so user.db and keychain cannot diverge (NET-12).
		cres, cerr := m.runner.RunWithStdin(ctx, strings.NewReader(pw+"\n"+pw+"\n"),
			ntfyBin, "user", "change-pass", "--config", cfgPath, "admin")
		if cerr != nil {
			return fmt.Errorf("ntfy user change-pass: %w", cerr)
		}
		if cres.ExitCode != 0 {
			return fmt.Errorf("ntfy user change-pass exited %d: %s", cres.ExitCode, strings.TrimSpace(cres.Stderr))
		}
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
	// `tailscale ip --4` can print multiple addresses, one per line. Take only
	// the first: TrimSpace alone would leave an embedded newline that corrupts
	// the generated server.yml listen/base-url lines.
	ip := strings.TrimSpace(res.Stdout)
	if i := strings.IndexByte(ip, '\n'); i >= 0 {
		ip = strings.TrimSpace(ip[:i])
	}
	if ip == "" {
		return "", fmt.Errorf("tailscale ip returned empty output")
	}
	return ip, nil
}

// getTailnetHostname returns the MagicDNS hostname of this machine (e.g.
// "vaultofmac.tailXXXX.ts.net"). Falls back to the tailnet IP if unavailable.
//
// The output is parsed with json.Unmarshal and only Self.DNSName is read —
// string-matching the first "DNSName" line would return a Peer's hostname
// whenever a Peer entry happens to precede Self in the JSON (NET-19).
func (m *Module) getTailnetHostname(ctx context.Context) string {
	res, err := m.runner.Run(ctx, "tailscale", "status", "--json")
	if err != nil || res.ExitCode != 0 {
		ip, _ := m.getTailnetIP(ctx)
		return ip
	}
	var status struct {
		Self struct {
			DNSName string `json:"DNSName"`
		} `json:"Self"`
	}
	if jsonErr := json.Unmarshal([]byte(res.Stdout), &status); jsonErr == nil && status.Self.DNSName != "" {
		return strings.TrimSuffix(status.Self.DNSName, ".")
	}
	ip, _ := m.getTailnetIP(ctx)
	return ip
}

// Verify is a no-op for the ntfy module — all listen_address checks run in Detect.
//
// Pitfall 4: do NOT call Detect here — runner.Doctor calls both Detect and Verify;
// re-running Detect would double every Detect finding (including listen_address OK
// and listen_address Fatal). ntfy Verify adds no new information beyond Detect;
// returning nil avoids double-emission.
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair re-applies configuration.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
