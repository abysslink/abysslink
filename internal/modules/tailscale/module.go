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
}

// New returns a new Module.
func New(runner shell.Runner, cfg *config.Config) *Module {
	return &Module{runner: runner, cfg: cfg}
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
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "running",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("tailscale backend state is %q (expected Running)", status.BackendState),
		})
	}

	// Check SSH capability — skip for sandboxed GUI builds where --ssh is unsupported.
	if m.cfg.Tailnet.SSH && !sandboxed && !status.TailscaleSSH {
		sshEnabled := false
		for _, cap := range status.Self.Capabilities {
			if strings.Contains(cap, "ssh") {
				sshEnabled = true
				break
			}
		}
		if !sshEnabled {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "ssh",
				Severity: modules.SeverityWarning,
				Message:  "tailscale SSH is not enabled; run: tailscale up --ssh",
			})
		}
	} else if m.cfg.Tailnet.SSH && sandboxed {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ssh_sandboxed",
			Severity: modules.SeverityWarning,
			Message:  "Tailscale SSH is not available in the sandboxed GUI build; install the CLI: brew install tailscale",
		})
	}

	return findings, nil
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
				Reversible:  false,
			})
		case "running":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "run tailscale up --ssh",
				Reversible:  false,
			})
		case "ssh":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "run tailscale up --ssh",
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

// Apply executes planned changes.
func (m *Module) Apply(ctx context.Context) error {
	// Detect sandboxed GUI build upfront — affects which flags are valid.
	verRes, _ := m.runner.Run(ctx, "tailscale", "version")
	sandboxed := isSandboxedGUI(strings.TrimSpace(verRes.Stdout))

	findings, err := m.Detect(ctx)
	if err != nil {
		return fmt.Errorf("tailscale apply: detect: %w", err)
	}

	for _, f := range findings {
		switch f.Check {
		case "installed":
			return fmt.Errorf("tailscale apply: tailscale is not installed; install it from https://tailscale.com/download and re-run")
		case "ssh_sandboxed":
			slog.Warn("tailscale apply: skipping --ssh flag — sandboxed GUI build does not support Tailscale SSH; install CLI: brew install tailscale")
		case "running":
			args := []string{"up"}
			if m.cfg.Tailnet.SSH && !sandboxed {
				args = append(args, "--ssh")
			}
			if m.cfg.Tailnet.Hostname != "" {
				args = append(args, "--hostname="+m.cfg.Tailnet.Hostname)
			}
			slog.Info("tailscale apply: running tailscale up", "args", args)
			res, err := m.runner.Run(ctx, "tailscale", args...)
			if err != nil {
				return fmt.Errorf("tailscale apply: tailscale up: %w", err)
			}
			if res.ExitCode != 0 {
				combined := res.Stdout + res.Stderr
				if strings.Contains(combined, "sandboxed") {
					slog.Warn("tailscale apply: GUI build detected at runtime — retrying without --ssh; install CLI: brew install tailscale")
					args2 := []string{"up"}
					if m.cfg.Tailnet.Hostname != "" {
						args2 = append(args2, "--hostname="+m.cfg.Tailnet.Hostname)
					}
					res2, err2 := m.runner.Run(ctx, "tailscale", args2...)
					if err2 != nil {
						return fmt.Errorf("tailscale apply: tailscale up (no-ssh retry): %w", err2)
					}
					if res2.ExitCode != 0 {
						return fmt.Errorf("tailscale apply: tailscale up exited %d: %s", res2.ExitCode, res2.Stderr)
					}
				} else {
					return fmt.Errorf("tailscale apply: tailscale up exited %d: %s", res.ExitCode, res.Stderr)
				}
			}
		case "ssh":
			if sandboxed {
				slog.Warn("tailscale apply: skipping --ssh — sandboxed GUI build; install CLI: brew install tailscale")
				continue
			}
			args := []string{"up", "--ssh"}
			if m.cfg.Tailnet.Hostname != "" {
				args = append(args, "--hostname="+m.cfg.Tailnet.Hostname)
			}
			slog.Info("tailscale apply: enabling tailscale SSH", "args", args)
			res, err := m.runner.Run(ctx, "tailscale", args...)
			if err != nil {
				return fmt.Errorf("tailscale apply: enable SSH: %w", err)
			}
			if res.ExitCode != 0 {
				combined := res.Stdout + res.Stderr
				if strings.Contains(combined, "sandboxed") {
					slog.Warn("tailscale apply: GUI build — cannot enable Tailscale SSH; install CLI: brew install tailscale")
				} else {
					return fmt.Errorf("tailscale apply: enable SSH exited %d: %s", res.ExitCode, res.Stderr)
				}
			}
		}
	}

	// Set hostname if configured and currently different.
	if m.cfg.Tailnet.Hostname != "" {
		statusRes, err := m.runner.Run(ctx, "tailscale", "status", "--json")
		if err == nil && statusRes.ExitCode == 0 {
			var st struct {
				Self struct {
					HostName string `json:"HostName"`
				} `json:"Self"`
			}
			if json.Unmarshal([]byte(statusRes.Stdout), &st) == nil {
				if st.Self.HostName != "" && st.Self.HostName != m.cfg.Tailnet.Hostname {
					slog.Info("tailscale apply: setting hostname", "hostname", m.cfg.Tailnet.Hostname)
					res, err := m.runner.Run(ctx, "tailscale", "set", "--hostname="+m.cfg.Tailnet.Hostname)
					if err != nil {
						return fmt.Errorf("tailscale apply: set hostname: %w", err)
					}
					if res.ExitCode != 0 {
						return fmt.Errorf("tailscale apply: set hostname exited %d: %s", res.ExitCode, res.Stderr)
					}
				}
			}
		}
	}

	return nil
}

// Verify re-runs Detect and returns findings.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	return m.Detect(ctx)
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
