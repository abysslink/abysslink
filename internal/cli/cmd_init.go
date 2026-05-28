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

package cli

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/platform"
	platformauto "github.com/abysslink/abysslink/internal/platform/auto"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// initTool describes a binary that init checks and optionally installs before writing config.
type initTool struct {
	name     string   // display name
	binary   string   // executable to probe
	verArgs  []string // args that emit version info
	pkg      string   // package name for the platform installer
	optional bool     // optional tools print a hint rather than blocking
}

// toolCheckResult holds the outcome of probing a single tool.
type toolCheckResult struct {
	tool    initTool
	version string // empty string means binary was not found
	found   bool
}

// versionRe extracts a semver-like token from command output.
var versionRe = regexp.MustCompile(`\d+\.\d+[\w.\-]*`)

// nameColW is the fixed display width for the tool name column.
const nameColW = 11

// styleNameCol is the lipgloss style used to pad tool names to nameColW.
var styleNameCol = lipgloss.NewStyle().Width(nameColW)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactive bootstrap — generates abysslink.yaml for this machine",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			p := newPrinter(cmd)
			autoYes, _ := cmd.Flags().GetBool("yes")

			header := styleBold.Render("abysslink init") + "  " + styleMuted.Render("first-run setup")
			printerInfo(p, styleHeaderBox.Render(header))
			printerInfo(p, "")

			runner := &shell.ExecRunner{}
			plat, err := platformauto.New(runner)
			if err != nil {
				return fmt.Errorf("init: platform detection: %w", err)
			}

			// Phase 1 — Show what's already installed (never mutates anything).
			toolStatus := runToolCheck(ctx, p, runner)
			printerInfo(p, "")

			// Phase 2 — Tailscale binary + daemon are hard requirements.
			if err := ensureTailscale(ctx, p, runner, plat, toolStatus, autoYes); err != nil {
				return err
			}

			// Phase 3 — Config questions.
			cfg, err := runInitForm(cmd, autoYes)
			if err != nil {
				return err
			}

			// Phase 4 — Install missing tools for the user's chosen modules.
			if err := installModuleTools(ctx, p, runner, plat, cfg, toolStatus, autoYes); err != nil {
				return err
			}

			// Phase 5 — Write config.
			configPath := resolveConfigPath(cmd)
			if err := config.Write(configPath, cfg); err != nil {
				return fmt.Errorf("init: write config: %w", err)
			}

			printerInfo(p, "")
			printerInfo(p, fmt.Sprintf("  %s  Config written to %s", iconDoneStr(), styleCode.Render(configPath)))
			printerInfo(p, "  "+styleMuted.Render("Next: ")+styleCode.Render("abysslink up --apply"))
			printerInfo(p, "")
			return nil
		},
	}
	cmd.Flags().Bool("yes", false, "Non-interactive: accept defaults and install missing tools automatically")
	return cmd
}

// runToolCheck prints the prerequisites table and returns results keyed by tool name.
// It never installs anything — that happens in later phases.
func runToolCheck(ctx context.Context, p Printer, runner shell.Runner) map[string]toolCheckResult {
	printerInfo(p, "  "+styleBold.Render("Prerequisites"))
	printerInfo(p, "")

	tools := []initTool{
		{name: "tailscale", binary: "tailscale", verArgs: []string{"version"}, pkg: "tailscale"},
		{name: "tmux", binary: "tmux", verArgs: []string{"-V"}, pkg: "tmux"},
		{name: "mosh", binary: "mosh", verArgs: []string{"--version"}, pkg: "mosh"},
		{name: "ntfy", binary: "ntfy", verArgs: []string{"--version"}, pkg: "ntfy"},
		{name: "cosign", binary: "cosign", verArgs: []string{"version"}, pkg: "cosign", optional: true},
	}

	out := make(map[string]toolCheckResult, len(tools)+1)
	for _, t := range tools {
		ver, found := probeVersion(ctx, runner, t)
		out[t.name] = toolCheckResult{tool: t, version: ver, found: found}
		printerInfo(p, fmtToolRow(t.name, ver, found, t.optional))
	}

	// Tailscale daemon gets a separate row — the CLI binary can be present but
	// the daemon socket missing (common after a fresh brew install).
	daemonOK := probeTailscaleDaemon(ctx, runner)
	out["tailscaled"] = toolCheckResult{found: daemonOK}
	printerInfo(p, fmtDaemonRow(daemonOK))

	return out
}

// probeVersion runs the tool's version command and returns (version, true) on success.
// Returns ("", false) only when the binary is absent (exec error, not exit-code error).
func probeVersion(ctx context.Context, runner shell.Runner, t initTool) (string, bool) {
	res, err := runner.Run(ctx, t.binary, t.verArgs...)
	if err != nil {
		return "", false // binary not on PATH
	}
	combined := res.Stdout + res.Stderr
	if m := versionRe.FindString(combined); m != "" {
		return m, true
	}
	return "?", true // binary exists, version string unparseable
}

// probeTailscaleDaemon returns true when the local tailscaled socket is reachable.
func probeTailscaleDaemon(ctx context.Context, runner shell.Runner) bool {
	res, err := runner.Run(ctx, "tailscale", "status")
	return err == nil && res.ExitCode == 0
}

// fmtToolRow renders one row of the prerequisites table.
func fmtToolRow(name, version string, found, optional bool) string {
	nameCol := styleNameCol.Render(name)
	switch {
	case found:
		return fmt.Sprintf("  %s  %s  %s", iconDoneStr(), nameCol, styleMuted.Render(version))
	case optional:
		return fmt.Sprintf("  %s  %s  %s",
			styleMuted.Render("○"), nameCol,
			styleMuted.Render("not found  (optional — needed for upgrade --apply)"))
	default:
		return fmt.Sprintf("  %s  %s  %s",
			iconFatalStr(), nameCol, styleWarn.Render("not found"))
	}
}

// fmtDaemonRow renders the tailscaled daemon status row.
func fmtDaemonRow(running bool) string {
	nameCol := styleNameCol.Render("tailscaled")
	if running {
		return fmt.Sprintf("  %s  %s  %s", iconDoneStr(), nameCol, styleMuted.Render("running"))
	}
	return fmt.Sprintf("  %s  %s  %s", iconWarnStr(), nameCol, styleWarn.Render("not running"))
}

// ensureTailscale makes sure the tailscale binary is installed and the daemon is running.
// Both are hard requirements; init aborts (with a clear message) if either cannot be satisfied.
func ensureTailscale(ctx context.Context, p Printer, runner shell.Runner, plat platform.Platform, status map[string]toolCheckResult, autoYes bool) error {
	if ts := status["tailscale"]; !ts.found {
		t := initTool{name: "tailscale", binary: "tailscale", verArgs: []string{"version"}, pkg: "tailscale"}
		if err := installTool(ctx, p, runner, plat, t, autoYes); err != nil {
			return err
		}
	}
	if daemon := status["tailscaled"]; !daemon.found {
		if err := startTailscaleDaemon(ctx, p, runner, plat, autoYes); err != nil {
			return err
		}
	}
	return nil
}

// startTailscaleDaemon prompts (or auto-proceeds with --yes) then issues the
// platform-specific start command. The function is non-fatal if the daemon
// can't be verified after start — the user may need to open the Tailscale app
// manually on sandboxed macOS builds.
func startTailscaleDaemon(ctx context.Context, p Printer, runner shell.Runner, plat platform.Platform, autoYes bool) error {
	start := autoYes
	if !autoYes {
		printerInfo(p, "")
		if err := huh.NewConfirm().
			Title("Start the Tailscale daemon?").
			Description("tailscaled is not running — it is required for all remote access.").
			Value(&start).Run(); err != nil {
			return err
		}
	}
	if !start {
		return fmt.Errorf("init: tailscaled is required; start it then re-run `abysslink init`")
	}

	printerInfo(p, fmt.Sprintf("  %s  Starting tailscaled...", iconSpinStr()))

	if err := doStartTailscaleDaemon(ctx, runner, plat); err != nil {
		// Non-fatal: print guidance and continue so the user can start it manually.
		printerInfo(p, "  "+iconWarnStr()+"  "+styleMuted.Render("Could not start daemon automatically:"))
		printerInfo(p, "  "+styleMuted.Render("  macOS:  brew services start tailscale"))
		printerInfo(p, "  "+styleMuted.Render("  Linux:  sudo systemctl enable --now tailscaled"))
		printerInfo(p, "  "+styleMuted.Render("Start it, then re-run `abysslink up --apply`."))
		return nil
	}

	printerInfo(p, fmt.Sprintf("  %s  Waiting for tailscaled...", iconSpinStr()))
	if !waitForDaemon(ctx, runner) {
		printerInfo(p, "  "+iconWarnStr()+"  "+styleMuted.Render("Daemon did not respond within 15s — check with: tailscale status"))
		return nil
	}
	printerInfo(p, fmt.Sprintf("  %s  %s  ready", iconDoneStr(), styleNameCol.Render("tailscaled")))
	return nil
}

// waitForDaemon polls tailscale status until it responds or the 15s deadline passes.
func waitForDaemon(ctx context.Context, runner shell.Runner) bool {
	const (
		maxWait  = 15 * time.Second
		interval = time.Second
	)
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if probeTailscaleDaemon(ctx, runner) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(interval):
		}
	}
	return false
}

// doStartTailscaleDaemon issues the OS-specific daemon start command.
func doStartTailscaleDaemon(ctx context.Context, runner shell.Runner, plat platform.Platform) error {
	switch plat.OS() {
	case "darwin":
		_, err := runner.Run(ctx, "brew", "services", "start", "tailscale")
		return err
	default: // linux
		_, err := runner.Run(ctx, "sudo", "systemctl", "enable", "--now", "tailscaled")
		return err
	}
}

// installTool prompts (or auto-installs with --yes) a single missing binary.
func installTool(ctx context.Context, p Printer, runner shell.Runner, plat platform.Platform, t initTool, autoYes bool) error {
	doInstall := autoYes
	if !autoYes {
		printerInfo(p, "")
		desc := fmt.Sprintf("Installs via %s.", plat.PackageManager())
		if !t.optional {
			desc = "Required for abysslink. " + desc
		}
		if err := huh.NewConfirm().
			Title(fmt.Sprintf("Install %s?", t.name)).
			Description(desc).
			Value(&doInstall).Run(); err != nil {
			return err
		}
	}
	if !doInstall {
		if t.optional {
			return nil
		}
		return fmt.Errorf("init: %s is required — aborting", t.name)
	}

	printerInfo(p, fmt.Sprintf("  %s  Installing %s...", iconSpinStr(), t.name))
	if err := plat.InstallPackage(ctx, t.pkg); err != nil {
		return fmt.Errorf("init: install %s: %w", t.name, err)
	}

	ver, found := probeVersion(ctx, runner, t)
	if !found {
		return fmt.Errorf("init: %s installed but binary not found — check your PATH", t.name)
	}
	printerInfo(p, fmt.Sprintf("  %s  %s  %s", iconDoneStr(), styleNameCol.Render(t.name), styleMuted.Render(ver)))
	return nil
}

// installModuleTools installs any tools that are missing for the user's enabled modules.
func installModuleTools(ctx context.Context, p Printer, runner shell.Runner, plat platform.Platform, cfg *config.Config, status map[string]toolCheckResult, autoYes bool) error {
	candidates := []struct {
		enabled bool
		tool    initTool
	}{
		{cfg.Modules.Tmux.Enabled, initTool{name: "tmux", binary: "tmux", verArgs: []string{"-V"}, pkg: "tmux"}},
		{cfg.Modules.Mosh.Enabled, initTool{name: "mosh", binary: "mosh", verArgs: []string{"--version"}, pkg: "mosh"}},
		{cfg.Modules.Ntfy.Enabled, initTool{name: "ntfy", binary: "ntfy", verArgs: []string{"--version"}, pkg: "ntfy"}},
	}

	var missing []initTool
	for _, c := range candidates {
		if !c.enabled {
			continue
		}
		if r, ok := status[c.tool.name]; ok && r.found {
			continue
		}
		missing = append(missing, c.tool)
	}
	if len(missing) == 0 {
		return nil
	}

	printerInfo(p, "")
	printerInfo(p, "  "+styleBold.Render("Missing module tools"))
	printerInfo(p, "")
	for _, t := range missing {
		if err := installTool(ctx, p, runner, plat, t, autoYes); err != nil {
			return err
		}
	}
	return nil
}

// runInitForm runs the interactive questionnaire and returns the resulting Config.
func runInitForm(cmd *cobra.Command, autoYes bool) (*config.Config, error) {
	var (
		email      string
		hostname   string
		enableSSH  = true
		enableTmux = true
		enableMosh = true
		enableNtfy = true
	)
	hostname, _ = os.Hostname()

	if !autoYes {
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Tailscale account email").
					Description("The email you signed into Tailscale with").
					Value(&email).
					Validate(func(s string) error {
						if !strings.Contains(s, "@") {
							return fmt.Errorf("must be a valid email address")
						}
						return nil
					}),
				huh.NewInput().
					Title("Rig hostname").
					Description("This machine's Tailscale hostname (pre-filled from OS)").
					Value(&hostname),
			),
			huh.NewGroup(
				huh.NewConfirm().
					Title("Enable Tailscale SSH?").
					Description("Replaces macOS Remote Login with Tailscale's hardened SSH").
					Value(&enableSSH),
				huh.NewConfirm().
					Title("Enable tmux?").
					Description("Persistent terminal session — survives network drops").
					Value(&enableTmux),
				huh.NewConfirm().
					Title("Enable mosh?").
					Description("Roaming shell — reconnects automatically on IP change").
					Value(&enableMosh),
				huh.NewConfirm().
					Title("Enable ntfy notifications?").
					Description("Push notifications to your phone when tasks complete").
					Value(&enableNtfy),
			),
		)
		if err := form.Run(); err != nil {
			return nil, fmt.Errorf("init: %w", err)
		}
	}

	cfg := config.Defaults()
	cfg.Identity.Email = email
	cfg.Identity.UnixUser = currentUnixUser()
	cfg.Tailnet.Hostname = hostname
	cfg.Tailnet.SSH = enableSSH
	cfg.Modules.SSH.Enabled = enableSSH
	cfg.Modules.SSH.Mode = "tailscale"
	cfg.Modules.Tmux.Enabled = enableTmux
	cfg.Modules.Mosh.Enabled = enableMosh
	cfg.Modules.Ntfy.Enabled = enableNtfy
	cfg.Modules.Notify.Enabled = enableNtfy
	return cfg, nil
}

// currentUnixUser returns the current UNIX login name from the environment.
func currentUnixUser() string {
	for _, key := range []string{"USER", "LOGNAME"} {
		if u := os.Getenv(key); u != "" {
			return u
		}
	}
	return "user"
}
