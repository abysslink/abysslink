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

package ssh

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// sshdDropInPath is where the hardened openssh-fallback config is installed.
const sshdDropInPath = "/etc/ssh/sshd_config.d/99-abysslink.conf"

// Module implements the ssh module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	audit  audit.AuditWriter
	// ca is the read-only device-store view used to wire TrustedUserCAKeys +
	// RevokedKeys. nil ⇒ no CA wiring: the hardened drop-in renders exactly as
	// the legacy config (fail-safe, never blocks `up`).
	ca CAProvider
}

// Option configures a Module at construction time.
type Option func(*Module)

// WithCAProvider injects a read-only device-store view so the hardened sshd
// drop-in can reference the device CA (TrustedUserCAKeys) and a KRL built from
// the revoked serials (RevokedKeys). A nil provider keeps the legacy drop-in.
func WithCAProvider(ca CAProvider) Option {
	return func(m *Module) { m.ca = ca }
}

// New returns a new Module. Options are applied after the base construction so
// New(deps) remains call-compatible (the variadic is back-compatible).
func New(d modules.Deps, opts ...Option) *Module {
	m := &Module{runner: d.Runner, cfg: d.Cfg, audit: d.Audit}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// sshUser returns the configured UNIX user, falling back to $USER.
func (m *Module) sshUser() string {
	if m.cfg.Identity.UnixUser != "" {
		return m.cfg.Identity.UnixUser
	}
	return os.Getenv("USER")
}

// Name returns the module name.
func (m *Module) Name() string { return "ssh" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect inspects the current SSH configuration state.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.SSH.Enabled {
		slog.Debug("ssh module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	switch runtime.GOOS {
	case "darwin":
		findings = append(findings, m.detectDarwin(ctx)...)
	case "linux":
		findings = append(findings, m.detectLinux(ctx)...)
	default:
		slog.Warn("ssh detect: unsupported OS", "os", runtime.GOOS)
	}

	// openssh-fallback mode requires the hardened drop-in config to be installed.
	if m.cfg.Modules.SSH.Mode == "openssh-fallback" {
		if _, err := os.Stat(sshdDropInPath); err != nil {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "fallback_config",
				Severity: modules.SeverityWarning,
				Message:  "hardened sshd config " + sshdDropInPath + " is not installed",
			})
		}
	}

	return findings, nil
}

// detectDarwin checks macOS Remote Login state.
func (m *Module) detectDarwin(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "systemsetup", "-getremotelogin")
	if err != nil {
		slog.Warn("ssh detect: systemsetup failed", "error", err)
		return findings
	}

	// systemsetup may print extra note lines (Full Disk Access warnings etc.)
	// on stdout, so a fuzzy substring match would misread an error message as
	// state. Only the exact "Remote Login: On"/"Remote Login: Off" line is
	// trusted; anything else — including a non-zero exit — is unknown (W4).
	state := parseRemoteLogin(res.Stdout)
	if !res.Ok() {
		state = remoteLoginUnknown
	}
	slog.Debug("ssh detect darwin", "remote_login", state, "exit_code", res.ExitCode)

	if m.cfg.Modules.SSH.Mode == "tailscale" {
		switch state {
		case remoteLoginOn:
			// When using Tailscale SSH, Remote Login (openssh daemon) should be off.
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "remote_login",
				Severity: modules.SeverityWarning,
				Message:  "Remote Login is On — when mode=tailscale, macOS sshd should be disabled",
			})
		case remoteLoginOff:
			// Emit explicit OK so "check ran and passed" is distinguishable from
			// "check never ran" in the threat-model tri-state (D-03 / DOC-01).
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "remote_login",
				Severity: modules.SeverityOK,
				Message:  "remote_login: Remote Login (sshd) is correctly off — Tailscale SSH is the active transport",
			})
		default:
			// Unknown state: WARN but take NO action. The check name is distinct
			// from "remote_login" so neither Plan nor Apply maps it to the
			// `systemsetup -setremotelogin off` mutation.
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "remote_login_unknown",
				Severity: modules.SeverityWarning,
				Message: "could not determine macOS Remote Login state from systemsetup output — " +
					"check System Settings → General → Sharing → Remote Login manually",
			})
		}
	}

	return findings
}

// Remote Login states parsed from `systemsetup -getremotelogin`.
const (
	remoteLoginUnknown = "unknown"
	remoteLoginOn      = "on"
	remoteLoginOff     = "off"
)

// parseRemoteLogin scans systemsetup output line-by-line for the exact
// "Remote Login: On" / "Remote Login: Off" status line. Any other content
// (permission notes, error text) yields remoteLoginUnknown.
func parseRemoteLogin(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		switch strings.TrimSpace(line) {
		case "Remote Login: On":
			return remoteLoginOn
		case "Remote Login: Off":
			return remoteLoginOff
		}
	}
	return remoteLoginUnknown
}

// detectLinux checks if sshd is running on Linux.
func (m *Module) detectLinux(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "systemctl", "is-active", "sshd")
	if err != nil || strings.TrimSpace(res.Stdout) != "active" {
		// Fall back to ssh.service whenever the sshd unit did not report
		// "active" — NOT only on exec error. On distros that ship only
		// ssh.service (Debian/Ubuntu), `systemctl is-active sshd` exits
		// non-zero with "inactive"/"unknown" on stdout but WITHOUT an exec
		// error, so gating the fallback on err != nil alone reports a running
		// daemon as correctly off and Apply never disables it (NET-08).
		res2, err2 := m.runner.Run(ctx, "systemctl", "is-active", "ssh")
		switch {
		case err2 == nil:
			res = res2
		case err != nil:
			// Both probes failed to execute — cannot determine state.
			slog.Warn("ssh detect: systemctl failed", "error", err)
			return findings
		default:
			// First probe executed (not active), second failed to execute:
			// keep the first result.
		}
	}

	active := strings.TrimSpace(res.Stdout) == "active"
	slog.Debug("ssh detect linux", "sshd_active", active)

	if m.cfg.Modules.SSH.Mode == "tailscale" {
		if active {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "sshd_running",
				Severity: modules.SeverityWarning,
				Message:  "sshd is running — when mode=tailscale, consider disabling the openssh daemon",
			})
		} else {
			// Emit explicit OK so "check ran and passed" is distinguishable from
			// "check never ran" in the threat-model tri-state (D-03 / DOC-01).
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "sshd_running",
				Severity: modules.SeverityOK,
				Message:  "sshd_running: OpenSSH daemon is correctly off — Tailscale SSH is the active transport",
			})
		}
	}

	return findings
}

// Plan computes the actions needed to reach the desired state.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.SSH.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		if f.Severity == modules.SeverityOK {
			continue // OK findings represent passing checks; no action needed
		}
		switch m.cfg.Modules.SSH.Mode {
		case "tailscale":
			if f.Check == "remote_login" || f.Check == "sshd_running" {
				actions = append(actions, modules.Action{
					Module:      m.Name(),
					Description: "disable Remote Login (use Tailscale SSH)",
					Reversible:  true,
				})
			}
		case "openssh-fallback":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "write hardened sshd_config.d/99-abysslink.conf",
				Reversible:  true,
			})
		}
	}

	return actions, nil
}

// Apply executes planned changes.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.SSH.Enabled {
		return nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return fmt.Errorf("ssh apply: detect: %w", err)
	}

	for _, f := range findings {
		if f.Severity == modules.SeverityOK {
			continue // OK findings represent passing checks; no action needed
		}
		switch f.Check {
		case "remote_login":
			// Disable macOS Remote Login — Tailscale SSH handles auth.
			slog.Info("ssh apply: disabling macOS Remote Login")
			res, err := m.runner.Run(ctx, "sudo", "systemsetup", "-setremotelogin", "off")
			if err != nil {
				return fmt.Errorf("ssh apply: disable remote login: %w", err)
			}
			if res.ExitCode != 0 {
				return fmt.Errorf("ssh apply: disable remote login exited %d: %s", res.ExitCode, res.Stderr)
			}
		case "sshd_running":
			if err := m.disableSSHDUnits(ctx); err != nil {
				return err
			}
		case "fallback_config":
			if err := m.installHardenedSSHD(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

// disableSSHDUnits stops and disables sshd on Linux — Tailscale SSH handles
// auth. Both unit names are tried (distros differ); it errors only when both
// fail, reporting the real exec error rather than a fabricated exit code.
func (m *Module) disableSSHDUnits(ctx context.Context) error {
	slog.Info("ssh apply: stopping sshd (Tailscale SSH mode)")
	var disableErr error
	for _, unit := range []string{"sshd", "ssh"} {
		res, err := m.runner.Run(ctx, "sudo", "systemctl", "disable", "--now", unit)
		if err == nil && res.Ok() {
			return nil
		}
		if err != nil {
			disableErr = fmt.Errorf("systemctl disable %s: %w", unit, err)
		} else {
			disableErr = fmt.Errorf("systemctl disable %s: exit %d: %s", unit, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}
	return fmt.Errorf("ssh apply: could not disable sshd (tried sshd and ssh units): %w", disableErr)
}

// hardenedSSHDConfig returns the sshd drop-in for openssh-fallback mode. It
// disables passwords and agent/TCP/X11 forwarding (so a compromised phone
// cannot pivot through a forwarded agent) and restricts logins to one user.
//
// When caWired is true, two ADDITIVE directives are appended:
// TrustedUserCAKeys (so device certs minted by the device CA are trusted —
// DEVC-05) and RevokedKeys (so revoked serials are rejected via the KRL —
// DEVC-06). The immutable hardened block above is unchanged in both renders;
// the two directives are additive only and never weaken an existing default.
func hardenedSSHDConfig(user string, caWired bool) string {
	cfg := fmt.Sprintf(`# Managed by abysslink — hardened sshd (openssh-fallback mode). Do not edit.
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
AllowUsers %s
`, user)
	if caWired {
		cfg += "TrustedUserCAKeys " + caTrustDest + "\n"
		cfg += "RevokedKeys " + krlDest + "\n"
	}
	return cfg
}

// installHardenedSSHD renders the hardened config, records it in the audit log,
// installs it as root, validates it with `sshd -t`, and reloads sshd. The
// config is validated BEFORE reload so a bad config never takes effect, and an
// invalid drop-in is removed again so the NEXT sshd restart (reboot, package
// upgrade) cannot fail to start either (W2 — deferred remote lockout).
func (m *Module) installHardenedSSHD(ctx context.Context) error {
	user := m.sshUser()
	// Defense in depth (W3): config.Validate already rejects unsafe unix_user
	// values at load time, but this value is interpolated into a root-owned
	// sshd config ("AllowUsers %s") and may also come from $USER via the
	// fallback — never render a name that could smuggle extra directives.
	if err := config.ValidateUnixUser(user); err != nil {
		return fmt.Errorf("ssh apply: refusing to render sshd config: %w", err)
	}

	// Stage + validate + install the device CA pub and KRL BEFORE the drop-in
	// that references them: RevokedKeys/TrustedUserCAKeys targets must exist
	// before sshd parses the config (and a missing/garbage RevokedKeys target
	// fails pubkey auth closed for ALL users). caWired is false (no error) when
	// no CA is wired or CAPublicKey errors — the legacy drop-in then renders
	// with neither directive, so `up` is never blocked.
	caWired, err := m.installCAAndKRL(ctx)
	if err != nil {
		return err
	}

	content := hardenedSSHDConfig(user, caWired)

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("ssh apply: home dir: %w", err)
	}
	staged := filepath.Join(home, ".config", "abysslink", "generated", "99-abysslink.conf")
	if err := os.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
		return fmt.Errorf("ssh apply: mkdir generated: %w", err)
	}
	if err := m.audit.WriteFile(staged, []byte(content), 0o600, false); err != nil {
		return fmt.Errorf("ssh apply: stage config: %w", err)
	}

	slog.Info("ssh apply: installing hardened sshd config", "dest", sshdDropInPath)
	if res, err := m.runner.Run(ctx, "sudo", "install", "-m", "600", staged, sshdDropInPath); err != nil {
		return fmt.Errorf("ssh apply: install config: %w", err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("ssh apply: install config exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	// Validate before reloading — never activate a broken sshd config. On
	// failure the freshly-installed drop-in MUST be removed again: leaving it
	// in place would make sshd fail to start on the next restart/reboot, which
	// is exactly the remote lockout this validation exists to prevent (W2).
	if res, err := m.runner.Run(ctx, "sudo", "sshd", "-t"); err != nil {
		return m.rollbackDropIn(ctx, fmt.Errorf("ssh apply: validate sshd config: %w", err))
	} else if !res.Ok() {
		return m.rollbackDropIn(ctx, fmt.Errorf("ssh apply: sshd config invalid, not reloading: %s", strings.TrimSpace(res.Stderr)))
	}

	return m.reloadSSHD(ctx)
}

// rollbackDropIn removes the just-installed sshd drop-in after a failed
// `sshd -t` validation so a broken config never survives to the next sshd
// restart. It returns cause, annotated with the rollback outcome.
func (m *Module) rollbackDropIn(ctx context.Context, cause error) error {
	slog.Warn("ssh apply: sshd validation failed — removing the drop-in so the next sshd restart stays bootable",
		"path", sshdDropInPath, "cause", cause)
	res, err := m.runner.Run(ctx, "sudo", "rm", "-f", sshdDropInPath)
	if err != nil {
		return fmt.Errorf("%w (ROLLBACK FAILED: could not remove %s: %v — remove it manually before the next sshd restart)",
			cause, sshdDropInPath, err)
	}
	if !res.Ok() {
		return fmt.Errorf("%w (ROLLBACK FAILED: rm %s exited %d: %s — remove it manually before the next sshd restart)",
			cause, sshdDropInPath, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return fmt.Errorf("%w (the invalid drop-in %s was removed again — sshd keeps its previous config)", cause, sshdDropInPath)
}

// reloadSSHD reloads the sshd daemon using the appropriate mechanism for the
// current OS: launchctl on macOS, systemctl on Linux.
func (m *Module) reloadSSHD(ctx context.Context) error {
	if runtime.GOOS == "darwin" {
		// macOS sshd is managed by launchd; kickstart -k stops then relaunches it.
		res, err := m.runner.Run(ctx, "sudo", "launchctl", "kickstart", "-k", "system/com.openssh.sshd")
		if err != nil {
			return fmt.Errorf("ssh apply: reload sshd (launchctl): %w", err)
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("ssh apply: launchctl kickstart sshd exited %d: %s",
				res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		return nil
	}
	// Linux: try both common unit names (sshd.service and ssh.service vary by distro).
	var reloadErr error
	for _, unit := range []string{"sshd", "ssh"} {
		res, err := m.runner.Run(ctx, "sudo", "systemctl", "reload", unit)
		if err == nil && res.ExitCode == 0 {
			return nil
		}
		if err != nil {
			reloadErr = err
		} else {
			reloadErr = fmt.Errorf("reload %s exited %d: %s", unit, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}
	if reloadErr != nil {
		return fmt.Errorf("ssh apply: could not reload sshd: %w", reloadErr)
	}
	return nil
}

// Verify is a no-op for the ssh module — all checks run in Detect.
// Pitfall 4: do NOT call Detect here — runner.Doctor calls both Detect and Verify;
// re-running Detect would produce duplicate remote_login/sshd_running findings per
// doctor pass. ssh Verify adds no new information beyond Detect; returning nil
// avoids double-emission.
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}
