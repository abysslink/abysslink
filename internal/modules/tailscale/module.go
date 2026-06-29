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
// NOTE: SSH-enabled state is deliberately NOT read from here — `tailscale status`
// exposes no RunSSH field, and Self.Capabilities always lists the tailnet-granted
// ".../cap/ssh" capability whether or not the SSH server is running. Tailscale
// SSH state is read from the RunSSH pref instead (see tailscaleRunSSH).
type tailscaleStatus struct {
	BackendState string `json:"BackendState"`
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

	findings = append(findings, m.sshFindings(ctx, sandboxed)...)

	return findings, nil
}

// tailscaleRunSSH reports whether Tailscale SSH is ACTUALLY enabled on this node,
// read from the RunSSH preference (`tailscale debug prefs`). This is the only
// reliable signal: `tailscale status --json` exposes no SSH-running field, and
// the node's Capabilities list ALWAYS carries the tailnet-granted ".../cap/ssh"
// whether or not the SSH server runs. Detecting from status therefore false-
// greened ("SSH enabled" for every node), so `up --apply` never ran
// `tailscale set --ssh` and the rig was left with NO SSH listener — every
// phone connect got "connection refused". A probe failure returns false so
// Apply idempotently (re-)runs `tailscale set --ssh`.
func (m *Module) tailscaleRunSSH(ctx context.Context) bool {
	res, err := m.runner.Run(ctx, "tailscale", "debug", "prefs")
	if err != nil || res.ExitCode != 0 {
		return false
	}
	var prefs struct {
		RunSSH bool `json:"RunSSH"`
	}
	if json.Unmarshal([]byte(res.Stdout), &prefs) != nil {
		return false
	}
	return prefs.RunSSH
}

// sshFindings reports whether Tailscale SSH is enabled for the current config,
// accounting for sandboxed GUI builds that cannot run the SSH server.
func (m *Module) sshFindings(ctx context.Context, sandboxed bool) []modules.Finding {
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
	// Enabled iff the RunSSH pref is actually set (status/capabilities are not a
	// valid signal — see tailscaleRunSSH).
	if m.tailscaleRunSSH(ctx) {
		return nil
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
				Description: "run tailscale up (reconnect), then tailscale set --ssh",
				Explain:     "Reconnects Tailscale and enables the SSH server so devices on your tailnet can connect without a VPN or open port.",
				Reversible:  false,
			})
		case "ssh":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "run tailscale set --ssh",
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

	var needsLogin, notRunning bool
	for _, f := range findings {
		switch f.Check {
		case "needs_login":
			needsLogin = true
		case "running":
			notRunning = true
		}
	}

	if err := m.ensureConnected(ctx, needsLogin, notRunning); err != nil {
		return err
	}

	// Apply SSH via `tailscale set --ssh` (incremental; idempotent if already on).
	// `tailscale set` modifies only the specified flag; it does not require
	// re-stating --accept-routes or other user-configured non-defaults.
	if m.cfg.Tailnet.SSH {
		if err := m.enableSSH(ctx, sandboxed); err != nil {
			return err
		}
	}

	// Enable auto-update (best-effort — unsupported on some builds/distros).
	if res, err := m.runner.Run(ctx, "tailscale", "set", "--auto-update"); err != nil || res.ExitCode != 0 {
		slog.Warn("tailscale apply: could not enable auto-update (non-fatal)")
	}

	return m.ensureHostname(ctx)
}

// enableSSH enables Tailscale SSH via `tailscale set --ssh`. Using `set` rather
// than `up` avoids the requirement to re-state all non-default flags that the
// user may have set (e.g. --accept-routes, --exit-node).
func (m *Module) enableSSH(ctx context.Context, sandboxed bool) error {
	if sandboxed {
		slog.Warn("tailscale apply: sandboxed GUI build cannot enable Tailscale SSH; install CLI: brew install tailscale")
		return nil
	}
	slog.Info("tailscale apply: enabling Tailscale SSH (tailscale set --ssh)")
	res, err := m.runner.Run(ctx, "tailscale", "set", "--ssh")
	if err != nil {
		return fmt.Errorf("tailscale apply: enable SSH: %w", err)
	}
	if res.ExitCode == 0 {
		return nil
	}
	if strings.Contains(res.Stdout+res.Stderr, "sandboxed") {
		slog.Warn("tailscale apply: sandboxed GUI build cannot enable SSH; install CLI: brew install tailscale")
		return nil
	}
	return fmt.Errorf("tailscale apply: tailscale set --ssh exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
}

// ensureConnected handles the auth and reconnect cases before settings are applied.
// needsLogin: open browser via `tailscale login` (no flags — avoids the
// "must re-state all non-defaults" error that `tailscale up` triggers).
// notRunning: reconnect with `tailscale up` (no flags — preserves --accept-routes etc.).
func (m *Module) ensureConnected(ctx context.Context, needsLogin, notRunning bool) error {
	switch {
	case needsLogin:
		slog.Info("tailscale apply: launching browser login (tailscale login)")
		if err := m.runner.RunInteractive(ctx, "tailscale", "login"); err != nil {
			return fmt.Errorf("tailscale apply: interactive login: %w", err)
		}
	case notRunning:
		slog.Info("tailscale apply: reconnecting tailscale (tailscale up)")
		if res, err := m.runner.Run(ctx, "tailscale", "up"); err != nil {
			return fmt.Errorf("tailscale apply: reconnect: %w", err)
		} else if res.ExitCode != 0 {
			return fmt.Errorf("tailscale apply: reconnect exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}
	return nil
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

// ensureHostname sets the MagicDNS hostname when it differs from config.
func (m *Module) ensureHostname(ctx context.Context) error {
	if m.cfg.Tailnet.Hostname == "" {
		return nil
	}
	// D-03: defense-in-depth re-check before passing hostname to argv. This fires
	// even when Config is constructed programmatically without going through Load.
	if err := config.ValidateHostname(m.cfg.Tailnet.Hostname); err != nil {
		return fmt.Errorf("tailscale apply: %w", err)
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
	if err := json.Unmarshal([]byte(statusRes.Stdout), &st); err != nil {
		slog.Warn("tailscale apply: could not parse status JSON for hostname check — hostname may not be set", "err", err)
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

// Verify refuses public exposure: it returns a fatal finding if Tailscale Funnel
// is active (which exposes a service to the public internet) and a warning if
// Serve is active. Preventing public exposure is the product's core promise, so
// a node is never "healthy" while Funnel is on.
//
// Pitfall 4: do NOT call Detect here — runner.Doctor calls both Detect and
// Verify; re-running Detect would double every Detect finding.
// checkNoPublicExposure is Verify's exclusive contribution; Detect handles
// running/installed/ssh etc.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.checkNoPublicExposure(ctx), nil
}

// checkNoPublicExposure inspects `tailscale funnel status` and `tailscale serve
// status`. Detection is conservative — it only flags clearly-active configs to
// avoid false positives on healthy machines.
//
// Three cases for the funnel probe (D-04, D-05, D-07):
//  1. Probe failure (exec error or non-zero exit): emit SeverityWarning with
//     Check="funnel-probe-fail" (distinct from "funnel" so the threat-model row
//     renders — not ✗). Return immediately; no funnel/serve findings.
//  2. Confirmed active: emit SeverityFatal with Check="funnel".
//  3. Confirmed inactive: emit SeverityOK with Check="funnel" so the threat-model
//     row renders ✓ (D-05 — "check ran and passed" is distinguishable from "check
//     never ran" in the tri-state).
//
// Three cases for the serve probe (IN-01, CR-02):
//  1. Probe failure (exec error or non-zero exit): emit SeverityWarning with
//     Check="serve-probe-fail" (distinct from "serve" so the threat-model row
//     renders — not ✗). Does NOT return early — funnel findings are already
//     appended above.
//  2. Confirmed active: emit SeverityWarning with Check="serve".
//  3. Confirmed inactive: no serve finding (correct — serve-inactive has no
//     distinct sentinel, unlike funnel).
func (m *Module) checkNoPublicExposure(ctx context.Context) []modules.Finding {
	var findings []modules.Finding

	active, probeOK := m.funnelActive(ctx)
	if !probeOK {
		// Probe failure: command unavailable or returned non-zero exit.
		// Use a distinct check ID so the threat-model "No public exposure"
		// row stays at — (did-not-run) rather than flipping to ✗ (D-04).
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "funnel-probe-fail",
			Severity: modules.SeverityWarning,
			Message:  "could not determine Funnel state — tailscale funnel command unavailable or returned non-zero exit; re-run after: tailscale status",
		})
		return findings
	}

	if active {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "funnel",
			Severity: modules.SeverityFatal,
			Message:  "Tailscale Funnel is enabled — this exposes a service to the public internet; disable it with `tailscale funnel reset`",
		})
	} else {
		// Emit explicit OK so "check ran and passed" is distinguishable from
		// "check never ran" in the threat-model tri-state (D-03 / DOC-01).
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "funnel",
			Severity: modules.SeverityOK,
			Message:  "funnel: no public exposure — Funnel/Serve disabled or not configured",
		})
	}

	serveOn, serveProbeOK := m.serveActive(ctx)
	if !serveProbeOK {
		// Probe failure: command unavailable or returned non-zero exit.
		// Use a distinct check ID so the threat-model row stays at —
		// (did-not-run) rather than flipping to ✗ (IN-01 / CR-02).
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "serve-probe-fail",
			Severity: modules.SeverityWarning,
			Message:  "could not determine Serve state — tailscale serve command unavailable; re-run after: tailscale status",
		})
	} else if serveOn {
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
// Returns (active, probeOK): probeOK is false when the command cannot be run
// (exec error) or exits non-zero (daemon not available), so the caller can
// distinguish a confirmed-inactive funnel from a probe failure (WR-02).
func (m *Module) funnelActive(ctx context.Context) (bool, bool) {
	res, err := m.runner.Run(ctx, "tailscale", "funnel", "status")
	if err != nil || res.ExitCode != 0 {
		return false, false
	}
	out := strings.ToLower(res.Stdout + res.Stderr)
	// Inactive output is e.g. "Funnel is not configured." / "No serve config".
	// Active output contains "(funnel on)" beside the exposed URL.
	return strings.Contains(out, "funnel on"), true
}

// serveActive reports whether `tailscale serve status` shows an active proxy.
// Returns (active, probeOK): probeOK is false when the command cannot be run
// (exec error) or exits non-zero (daemon not available), so the caller can
// distinguish a confirmed-inactive serve from a probe failure (CR-02 / IN-01).
func (m *Module) serveActive(ctx context.Context) (active, probeOK bool) {
	res, err := m.runner.Run(ctx, "tailscale", "serve", "status")
	if err != nil || res.ExitCode != 0 {
		return false, false
	}
	out := strings.ToLower(res.Stdout + res.Stderr)
	if strings.Contains(out, "no serve config") || strings.TrimSpace(out) == "" {
		return false, true
	}
	// Active serve output lists proxied targets as a tree, each leaf prefixed
	// with the "|--" tree marker (e.g. "|-- /  proxy http://127.0.0.1:8080").
	// Key on that structural marker rather than the bare word "proxy" (IN-03):
	// help/hint text that merely mentions "proxy" must not be misread as an
	// active serve (false-positive Warning).
	return strings.Contains(out, "|--"), true
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
