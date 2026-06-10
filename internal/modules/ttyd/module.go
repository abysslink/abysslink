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

package ttyd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

const ttydPort = "7681"

// Module implements the ttyd optional module.
// ttyd provides a web-based terminal, bound to the tailnet IP only.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	plat   platform.Platform
}

// New returns a new ttyd Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, plat: d.Platform}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "ttyd" }

// Deps returns the modules this module depends on.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect inspects the current system state for the ttyd installation.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.cfg.Modules.Ttyd.Enabled {
		slog.Debug("ttyd module disabled, skipping detect")
		return nil, nil
	}

	// Check whether ttyd binary is installed.
	res, err := m.runner.Run(ctx, "ttyd", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ttyd_installed",
			Severity: modules.SeverityFatal,
			Message:  "ttyd binary not found — install ttyd manually (see https://github.com/tsl0922/ttyd)",
		})
		return findings, nil
	}

	slog.Debug("ttyd version", "output", strings.TrimSpace(res.Stdout))

	// Surface the auth trade-off as a doctor finding, not just a log line:
	// ttyd has no stdin credential path (only --credential on argv, which the
	// no-secrets-on-argv rule forbids), so the abysslink-managed ttyd runs
	// WITHOUT basic auth and the tailnet ACL is the only access control.
	findings = append(findings, modules.Finding{
		Module:   m.Name(),
		Check:    "ttyd_no_auth",
		Severity: modules.SeverityWarning,
		Message: "ttyd runs without basic auth (credentials would leak on argv) — the tailnet ACL is the " +
			"only access control for tcp/" + ttydPort + "; never expose this port beyond the tailnet",
	})

	// Check if ttyd is running and bound to the tailnet IP. We inspect each
	// running ttyd invocation's argv: a ttyd started without an explicit
	// `-i <addr>` binds 0.0.0.0 by default — the most common insecure case —
	// and when -i IS present its value must not be a wildcard or loopback
	// address (NET-10). Naive substring greps for "0.0.0.0"/"::" miss the
	// default-bind case entirely and false-positive on IPv6 literals.
	res, err = m.runner.Run(ctx, "pgrep", m.pgrepListArgs()...)
	if err == nil && res.ExitCode == 0 {
		findings = append(findings, m.bindFindings(res.Stdout)...)
	}

	return findings, nil
}

// pgrepListArgs returns the pgrep argv (after the command name) that yields
// one "PID full-argv" line per ttyd process on this platform. The flags
// genuinely differ:
//   - Linux (procps-ng): `-a/--list-full` prints PID + full command line
//     (`-fl` prints only the process name since procps-ng 3.3).
//   - macOS/BSD: `-a` means "include ancestors" and prints PIDs only — which
//     made the NET-10 bind check dead code there; `-fl` prints PID + full
//     argument list (and `-f` matches against it).
func (m *Module) pgrepListArgs() []string {
	if m.plat != nil && m.plat.OS() == "darwin" {
		return []string{"-fl", "ttyd"}
	}
	return []string{"-a", "ttyd"}
}

// bindFindings parses `pgrep -a ttyd` output (one "PID argv..." line per
// process) and returns a finding for every ttyd process that is not bound to
// a specific non-wildcard, non-loopback address.
func (m *Module) bindFindings(pgrepOut string) []modules.Finding {
	var findings []modules.Finding
	for _, line := range strings.Split(pgrepOut, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		// fields[0] is the PID, fields[1] the command path. pgrep matches on
		// process name, but be defensive: only inspect real ttyd commands.
		if filepath.Base(fields[1]) != "ttyd" {
			continue
		}
		pid := fields[0]
		addr, hasFlag := ttydInterfaceArg(fields[2:])
		switch {
		case !hasFlag:
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "ttyd_bind_tailnet",
				Severity: modules.SeverityWarning,
				Message: fmt.Sprintf(
					"ttyd (pid %s) is running without -i — it binds 0.0.0.0 by default; restart it bound to the tailnet IP only", pid),
			})
		case isWildcardOrLoopbackAddr(addr):
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "ttyd_bind_tailnet",
				Severity: modules.SeverityWarning,
				Message: fmt.Sprintf(
					"ttyd (pid %s) is bound to %q — it must bind to the tailnet IP only (not a wildcard or loopback address)", pid, addr),
			})
		}
	}
	return findings
}

// ttydInterfaceArg extracts the value of the -i/--interface flag from a ttyd
// argv. The second return value reports whether the flag is present at all —
// absence means ttyd is using its insecure 0.0.0.0 default.
func ttydInterfaceArg(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-i" || a == "--interface":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", true // flag present but value missing — treated as wildcard
		case strings.HasPrefix(a, "--interface="):
			return strings.TrimPrefix(a, "--interface="), true
		case strings.HasPrefix(a, "-i="):
			return strings.TrimPrefix(a, "-i="), true
		}
	}
	return "", false
}

// isWildcardOrLoopbackAddr reports whether addr is an all-interfaces wildcard
// or a loopback address. Interface names (e.g. "tailscale0") and non-loopback
// hostnames are accepted — they cannot be classified without resolving them.
func isWildcardOrLoopbackAddr(addr string) bool {
	if addr == "" {
		return true
	}
	if strings.EqualFold(addr, "localhost") {
		return true
	}
	host := addr
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsUnspecified() || ip.IsLoopback()
	}
	return false
}

// Plan computes the actions needed to reach the desired state.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Ttyd.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch f.Check {
		case "ttyd_installed":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install ttyd (see https://github.com/tsl0922/ttyd#installation)",
				Reversible:  false,
			})
		case "ttyd_bind_tailnet":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "restart ttyd bound to tailnet IP only (not 0.0.0.0)",
				Reversible:  true,
			})
		}
	}

	// Plan text MUST match what Apply actually does (no TLS, no basic auth):
	// Apply installs a plain-HTTP ttyd service bound to the tailnet IP, with
	// the tailnet (WireGuard) as the encrypted transport and the tailnet ACL
	// as the only access control. The auth gap is surfaced as a doctor
	// finding (ttyd_no_auth) in Detect.
	actions = append(actions, modules.Action{
		Module:      m.Name(),
		Description: "install ttyd service bound to tailnet IP only, plain HTTP on tcp/" + ttydPort + ", writable terminal (-W)",
		Reversible:  true,
	})
	actions = append(actions, modules.Action{
		Module:      m.Name(),
		Description: "WARNING: ttyd runs without basic auth or its own TLS — the tailnet ACL is the only access control; never expose tcp/" + ttydPort + " beyond the tailnet",
		Reversible:  false,
	})

	return actions, nil
}

// Apply installs ttyd and runs it bound to the tailnet IP only. ttyd has no
// stdin credential path (only --credential on argv, which would leak), so
// access control is the tailnet ACL rather than basic auth — surfaced as the
// ttyd_no_auth doctor finding in Detect. Never bind to 0.0.0.0.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Ttyd.Enabled {
		return nil
	}

	if res, err := m.runner.Run(ctx, "ttyd", "--version"); err != nil || res.ExitCode != 0 {
		slog.Info("ttyd apply: installing ttyd")
		if err := m.plat.InstallPackage(ctx, "ttyd"); err != nil {
			return fmt.Errorf("ttyd apply: install: %w", err)
		}
	}

	ip, err := modules.TailnetIP(ctx, m.runner)
	if err != nil {
		return fmt.Errorf("ttyd apply: %w", err)
	}

	// -W is an EXPLICIT decision: ttyd >= 1.7 starts read-only by default, so
	// without it the browser terminal cannot type anything and the feature is
	// useless for its purpose. Write access is acceptable because the listener
	// is bound to the tailnet IP and gated by the tailnet ACL (the same trust
	// boundary as ssh); the missing-basic-auth trade-off is surfaced by the
	// ttyd_no_auth doctor finding.
	if err := m.plat.ServiceInstall(ctx, platform.ServiceSpec{
		Label:     "dev.abysslink.ttyd",
		Args:      []string{"ttyd", "-W", "-i", ip, "-p", ttydPort, "bash"},
		KeepAlive: true,
		RunAtLoad: true,
	}); err != nil {
		return fmt.Errorf("ttyd apply: install service: %w", err)
	}
	slog.Warn("ttyd apply: bound to " + ip + ":" + ttydPort + " with NO basic auth — access is limited to the tailnet ACL; never expose this port publicly")
	return nil
}

// Verify is a no-op for the ttyd module — all checks run in Detect.
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
