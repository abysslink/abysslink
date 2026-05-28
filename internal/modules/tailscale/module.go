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

package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// tailscaleStatus is the subset of `tailscale status --json` we care about.
type tailscaleStatus struct {
	BackendState string `json:"BackendState"`
	Self         struct {
		Capabilities []string `json:"Capabilities"`
	} `json:"Self"`
	// SSH is reported under the "ssh" capability or TailscaleSSH field.
	TailscaleSSH bool `json:"TailscaleSSH"`
}

// Module implements the tailscale module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	plat   platform.Platform
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, plat: d.Platform}
}

// Name returns the module name.
func (m *Module) Name() string { return "tailscale" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{} }

// Detect inspects the current Tailscale state.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Check if tailscale is installed.
	res, err := m.runner.Run(ctx, "tailscale", "version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: modules.SeverityFatal,
			Message:  "tailscale is not installed or not on PATH",
		})
		return findings, nil
	}
	versionOut := strings.TrimSpace(res.Stdout)
	slog.Debug("tailscale version", "output", versionOut)
	sandboxed := isSandboxedGUI(versionOut)
	if sandboxed {
		slog.Info("tailscale detect: sandboxed GUI build detected — Tailscale SSH not supported")
	}

	// Check backend state.
	statusRes, err := m.runner.Run(ctx, "tailscale", "status", "--json")
	if err != nil {
		return findings, fmt.Errorf("tailscale detect: run status: %w", err)
	}

	if statusRes.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "running",
			Severity: modules.SeverityWarning,
			Message:  "tailscale status returned non-zero; daemon may not be running",
		})
		return findings, nil
	}

	var status tailscaleStatus
	if err := json.Unmarshal([]byte(statusRes.Stdout), &status); err != nil {
		return findings, fmt.Errorf("tailscale detect: parse status JSON: %w", err)
	}

	if status.BackendState != "Running" {
		check := "running"
		if status.BackendState == "NeedsLogin" {
			check = "needs_login"
		}
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("tailscale backend state is %q (expected Running)", status.BackendState),
		})
	}

	findings = append(findings, m.sshFindings(&status, sandboxed)...)

	return findings, nil
}

// sshFindings reports whether Tailscale SSH is enabled for the current config,
// accounting for sandboxed GUI builds that cannot run the SSH server.
func (m *Module) sshFindings(status *tailscaleStatus, sandboxed bool) []modules.Finding {
	if !m.cfg.Tailnet.SSH {
		return nil
	}
	if sandboxed {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "ssh_sandboxed",
			Severity: modules.SeverityWarning,
			Message:  "Tailscale SSH is not available in the sandboxed GUI build; install the CLI: brew install tailscale",
		}}
	}
	if status.TailscaleSSH {
		return nil
	}
	for _, capability := range status.Self.Capabilities {
		if strings.Contains(capability, "ssh") {
			return nil
		}
	}
	return []modules.Finding{{
		Module:   m.Name(),
		Check:    "ssh",
		Severity: modules.SeverityWarning,
		Message:  "tailscale SSH is not enabled; run: tailscale up --ssh",
	}}
}

// Plan computes actions needed to reach desired state.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
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
				Description: "install tailscale",
				Explain:     "Tailscale is not on PATH. Install from https://tailscale.com/download then re-run abysslink up --apply.",
				Reversible:  false,
			})
		case "needs_login":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "ACTION REQUIRED: run `tailscale login` to authenticate (opens browser), then re-run `abysslink up --apply`",
				Explain:     "Tailscale requires authentication before it can join your tailnet. A browser will open; return here after signing in.",
				Reversible:  false,
			})
		case "running":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "run tailscale up --ssh",
				Explain:     "Brings Tailscale up and enables the SSH server so devices on your tailnet can connect without a VPN or open port.",
				Reversible:  false,
			})
		case "ssh":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "run tailscale up --ssh",
				Explain:     "Activates Tailscale SSH so devices on your tailnet can connect securely without a VPN or port forward.",
				Reversible:  false,
			})
		}
	}

	// Check hostname mismatch.
	if m.cfg.Tailnet.Hostname != "" {
		hostnameRes, err := m.runner.Run(ctx, "tailscale", "status", "--json")
		if err == nil && hostnameRes.ExitCode == 0 {
			var status struct {
				Self struct {
					HostName string `json:"HostName"`
				} `json:"Self"`
			}
			if json.Unmarshal([]byte(hostnameRes.Stdout), &status) == nil {
				if status.Self.HostName != "" && status.Self.HostName != m.cfg.Tailnet.Hostname {
					actions = append(actions, modules.Action{
						Module:      m.Name(),
						Description: fmt.Sprintf("set hostname to %q", m.cfg.Tailnet.Hostname),
						Reversible:  true,
					})
				}
			}
		}
	}

	return actions, nil
}

// Apply installs Tailscale if missing, authenticates (interactive browser SSO
// when needed), enables Tailscale SSH, turns on auto-update, and sets the
// configured hostname.
func (m *Module) Apply(ctx context.Context) error {
	if err := m.ensureInstalled(ctx); err != nil {
		return err
	}

	verRes, _ := m.runner.Run(ctx, "tailscale", "version")
	sandboxed := isSandboxedGUI(strings.TrimSpace(verRes.Stdout))

	findings, err := m.Detect(ctx)
	if err != nil {
		return fmt.Errorf("tailscale apply: detect: %w", err)
	}

	var needsLogin, notRunning, sshMissing bool
	for _, f := range findings {
		switch f.Check {
		case "needs_login":
			needsLogin = true
		case "running":
			notRunning = true
		case "ssh":
			sshMissing = true
		}
	}

	upArgs := m.upArgs(sandboxed)
	switch {
	case needsLogin:
		// Interactive: `tailscale up` prints the login URL, opens the browser,
		// and blocks until the user completes SSO authentication.
		slog.Info("tailscale apply: launching browser login (`tailscale up`)")
		if err := m.runner.RunInteractive(ctx, "tailscale", upArgs...); err != nil {
			return fmt.Errorf("tailscale apply: interactive login: %w", err)
		}
	case notRunning || sshMissing:
		if err := m.runUp(ctx, upArgs); err != nil {
			return err
		}
	}

	// Enable auto-update (best-effort — unsupported on some builds/distros).
	if res, err := m.runner.Run(ctx, "tailscale", "set", "--auto-update"); err != nil || res.ExitCode != 0 {
		slog.Warn("tailscale apply: could not enable auto-update (non-fatal)")
	}

	return m.ensureHostname(ctx)
}

// ensureInstalled installs the tailscale binary via the platform package
// manager when it is not already on PATH.
func (m *Module) ensureInstalled(ctx context.Context) error {
	if res, err := m.runner.Run(ctx, "tailscale", "version"); err == nil && res.ExitCode == 0 {
		return nil
	}
	slog.Info("tailscale apply: installing tailscale")
	if err := m.plat.InstallPackage(ctx, "tailscale"); err != nil {
		return fmt.Errorf("tailscale apply: install tailscale: %w", err)
	}
	return nil
}

// upArgs builds the `tailscale up` argument list, omitting --ssh on sandboxed
// GUI builds that cannot run the SSH server.
func (m *Module) upArgs(sandboxed bool) []string {
	args := []string{"up"}
	if m.cfg.Tailnet.SSH && !sandboxed {
		args = append(args, "--ssh")
	}
	if m.cfg.Tailnet.Hostname != "" {
		args = append(args, "--hostname="+m.cfg.Tailnet.Hostname)
	}
	return args
}

// runUp runs `tailscale up` non-interactively (already logged in). A sandboxed
// GUI build that rejects --ssh is downgraded to a warning rather than an error.
func (m *Module) runUp(ctx context.Context, args []string) error {
	slog.Info("tailscale apply: running tailscale up", "args", args)
	res, err := m.runner.Run(ctx, "tailscale", args...)
	if err != nil {
		return fmt.Errorf("tailscale apply: tailscale up: %w", err)
	}
	if res.ExitCode == 0 {
		return nil
	}
	if strings.Contains(res.Stdout+res.Stderr, "sandboxed") {
		slog.Warn("tailscale apply: sandboxed GUI build cannot enable Tailscale SSH; install CLI: brew install tailscale")
		return nil
	}
	return fmt.Errorf("tailscale apply: tailscale up exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
}

// ensureHostname sets the MagicDNS hostname when it differs from config.
func (m *Module) ensureHostname(ctx context.Context) error {
	if m.cfg.Tailnet.Hostname == "" {
		return nil
	}
	statusRes, err := m.runner.Run(ctx, "tailscale", "status", "--json")
	if err != nil || statusRes.ExitCode != 0 {
		return nil
	}
	var st struct {
		Self struct {
			HostName string `json:"HostName"`
		} `json:"Self"`
	}
	if json.Unmarshal([]byte(statusRes.Stdout), &st) != nil {
		return nil
	}
	if st.Self.HostName == "" || st.Self.HostName == m.cfg.Tailnet.Hostname {
		return nil
	}
	slog.Info("tailscale apply: setting hostname", "hostname", m.cfg.Tailnet.Hostname)
	res, err := m.runner.Run(ctx, "tailscale", "set", "--hostname="+m.cfg.Tailnet.Hostname)
	if err != nil {
		return fmt.Errorf("tailscale apply: set hostname: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("tailscale apply: set hostname exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// Verify re-runs Detect and additionally refuses public exposure: it returns a
// fatal finding if Tailscale Funnel is active (which exposes a service to the
// public internet) and a warning if Serve is active. Preventing public exposure
// is the product's core promise, so a node is never "healthy" while Funnel is on.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	findings, err := m.Detect(ctx)
	if err != nil {
		return findings, err
	}
	return append(findings, m.checkNoPublicExposure(ctx)...), nil
}

// checkNoPublicExposure inspects `tailscale funnel status` and `tailscale serve
// status`. Detection is conservative — it only flags clearly-active configs to
// avoid false positives on healthy machines.
func (m *Module) checkNoPublicExposure(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	if m.funnelActive(ctx) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "funnel",
			Severity: modules.SeverityFatal,
			Message:  "Tailscale Funnel is enabled — this exposes a service to the public internet; disable it with `tailscale funnel reset`",
		})
	}
	if m.serveActive(ctx) {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "serve",
			Severity: modules.SeverityWarning,
			Message:  "Tailscale Serve is active — confirm this is intended; reset with `tailscale serve reset`",
		})
	}
	return findings
}

// funnelActive reports whether `tailscale funnel status` shows an active funnel.
func (m *Module) funnelActive(ctx context.Context) bool {
	res, err := m.runner.Run(ctx, "tailscale", "funnel", "status")
	if err != nil || res.ExitCode != 0 {
		return false
	}
	out := strings.ToLower(res.Stdout + res.Stderr)
	// Inactive output is e.g. "Funnel is not configured." / "No serve config".
	// Active output contains "(funnel on)" beside the exposed URL.
	return strings.Contains(out, "funnel on")
}

// serveActive reports whether `tailscale serve status` shows an active proxy.
func (m *Module) serveActive(ctx context.Context) bool {
	res, err := m.runner.Run(ctx, "tailscale", "serve", "status")
	if err != nil || res.ExitCode != 0 {
		return false
	}
	out := strings.ToLower(res.Stdout + res.Stderr)
	if strings.Contains(out, "no serve config") || strings.TrimSpace(out) == "" {
		return false
	}
	// Active serve output lists proxied targets (a tree with "|--" / "proxy").
	return strings.Contains(out, "proxy") || strings.Contains(out, "|--")
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}

// isSandboxedGUI returns true when the tailscale binary is the sandboxed
// macOS App Store / GUI build, which rejects --ssh and other daemon flags.
// Detected by reading the wrapper script at the binary path — the GUI ships
// a /usr/local/bin/tailscale shell script that delegates to Tailscale.app.
func isSandboxedGUI(versionOutput string) bool {
	// Fast path: version output sometimes contains a clue.
	lower := strings.ToLower(versionOutput)
	if strings.Contains(lower, "tailscale-ipn") ||
		strings.Contains(lower, "tailscale.app") ||
		strings.Contains(lower, "sandboxed") {
		return true
	}

	// Reliable path: read the resolved binary and check for .app bundle.
	bin, err := exec.LookPath("tailscale")
	if err != nil {
		return false
	}
	// Read up to 256 bytes to check for the wrapper script pattern.
	f, err := os.Open(bin) //nolint:gosec // reading known binary path
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	content := strings.ToLower(string(buf[:n]))
	return strings.Contains(content, "tailscale.app")
}
