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
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/platform"
	platformauto "github.com/abysslink/abysslink/internal/platform/auto"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tui"
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
		Short: "Interactive bootstrap — generates abysslink.yaml and guides the full 8-stage setup",
		Example: `  # Interactive wizard — creates abysslink.yaml and runs the 8-stage journey
  abysslink init

  # Non-interactive (CI / scripted) — accept all defaults; --email is required
  abysslink init --yes --email you@example.com

  # Resume a previously interrupted setup
  abysslink init --resume`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			p := newPrinter(cmd)
			autoYes, _ := cmd.Flags().GetBool("yes")
			resume, _ := cmd.Flags().GetBool("resume")
			jsonOut, _ := cmd.Flags().GetBool("json")

			// Fail-closed consent gate (W1): a non-interactive session (pipe,
			// CI, --json) must NEVER self-promote to auto-yes — init installs
			// packages and runs sudo mutations. Explicit --yes is required.
			if !autoYes && !interactive(false, jsonOut) {
				return fmt.Errorf("init: %w (init installs packages and changes system settings; non-interactive runs need explicit consent)", errMissingInput("yes"))
			}

			header := styleBold.Render("abysslink init") + "  " + styleMuted.Render("first-run setup")
			printerInfo(p, styleHeaderBox.Render(header))
			printerInfo(p, "")

			// D-38: route every init exec through the gate-decorated runner
			// (and the newRunner test seam) — never a raw ExecRunner.
			runner := newRunner()
			plat, err := platformauto.New(runner)
			if err != nil {
				return fmt.Errorf("init: platform detection: %w", err)
			}

			configPath := resolveConfigPath(cmd)
			stateFile := abysslinkStateDir() + "/" + journeyStageFile
			resumeFrom := 0
			if resume {
				resumeFrom, _ = readJourneyState(stateFile)
			}

			// --resume with completed wizard state: when at least one journey
			// stage finished AND the config it wrote still loads, skip the
			// already-completed wizard stages (tool check, security fixes,
			// form, config write) and continue the journey directly (U9).
			var cfg *config.Config
			skipWizard := false
			if resumeFrom > 0 {
				if loaded, lerr := config.Load(configPath); lerr == nil {
					cfg = loaded
					skipWizard = true
					printerInfo(p, fmt.Sprintf("  %s  Resuming from stage %d — existing config at %s reused.",
						iconDoneStr(), resumeFrom+1, styleCode.Render(configPath)))
					printerInfo(p, "")
				} else {
					printerInfo(p, "  "+iconWarnStr()+"  "+styleMuted.Render(
						"Resume state found but config could not be loaded — re-running the setup wizard."))
					printerInfo(p, "")
				}
			}

			if !skipWizard {
				cfg, err = runInitWizard(ctx, cmd, p, runner, plat, configPath, autoYes)
				if err != nil {
					return err
				}
				if cfg == nil {
					// User declined the config write — wizard aborted cleanly.
					return nil
				}
			}

			stages := journeyStages(jsonOut, cfg, runner, autoYes)
			if err := runJourney(ctx, p, stages, resumeFrom, stateFile, autoYes); err != nil {
				return fmt.Errorf("init: journey: %w", err)
			}

			if !autoYes {
				printerInfo(p, "  "+styleMuted.Render("Next: ")+styleCode.Render("abysslink up --apply"))
			}
			printerInfo(p, "")
			return nil
		},
	}
	cmd.Flags().Bool("yes", false, "Non-interactive: accept defaults and install missing tools automatically")
	cmd.Flags().Bool("resume", false, "Continue from the last completed stage (reads journey-state.json)")
	cmd.Flags().String("email", "", "Account email written to the config (required with --yes; env ABYSSLINK_EMAIL also accepted)")
	cmd.Flags().String("hostname", "", "Rig hostname written to the config (default: sanitized OS hostname)")
	return cmd
}

// runInitWizard runs the pre-journey wizard stages: tool check, tailscale
// install/start, security fixes, the config form, module tool installs, and
// the config preview + write. Returns the written config, or (nil, nil) when
// the user declined the config write. Extracted from the RunE so --resume can
// skip it wholesale when the journey state and config already exist (U9).
func runInitWizard(ctx context.Context, cmd *cobra.Command, p Printer, runner shell.Runner, plat platform.Platform, configPath string, autoYes bool) (*config.Config, error) {
	// Config form and write — must happen before the journey stages run so
	// that stage 3 (Converge) and subsequent stages have a config to work with.
	toolStatus := runToolCheck(ctx, p, runner)
	printerInfo(p, "")

	if err := ensureTailscale(ctx, p, runner, plat, toolStatus, autoYes); err != nil {
		return nil, err
	}
	if err := runSecurityFixes(ctx, p, runner, plat, autoYes); err != nil {
		return nil, err
	}

	cfg, err := runInitForm(cmd, autoYes)
	if err != nil {
		return nil, err
	}

	if err := installModuleTools(ctx, p, runner, plat, cfg, toolStatus, autoYes); err != nil {
		return nil, err
	}

	ok, err := previewAndConfirmConfig(ctx, p, cfg, configPath, autoYes)
	if err != nil {
		return nil, fmt.Errorf("init: config preview: %w", err)
	}
	if !ok {
		printerInfo(p, "  Aborted — no config written.")
		return nil, nil
	}

	// Validate-before-write guard (C1/C2): never write a config that
	// config.Load would reject — that bricks every subsequent command until
	// the user hand-edits the YAML the wizard exists to generate.
	if verr := config.Validate(cfg); verr != nil {
		return nil, fmt.Errorf("init: refusing to write a config that `abysslink` cannot load: %w", verr)
	}

	if err := config.Write(configPath, cfg); err != nil {
		return nil, fmt.Errorf("init: write config: %w", err)
	}

	printerInfo(p, "")
	printerInfo(p, fmt.Sprintf("  %s  Config written to %s", iconDoneStr(), styleCode.Render(configPath)))
	printerInfo(p, "")
	return cfg, nil
}

// ensureTailscaleAccount confirms the user has a Tailscale account before proceeding.
// Tailscale uses SSO only (Google, GitHub, Microsoft, Apple — no username/password).
// If the user doesn't have an account yet, we show the signup URL and wait.
// When headless is true (--yes flag or non-TTY stdin), the function prints the
// informational signup-URL note and returns nil immediately — no huh, no /dev/tty.
// runner is used to open the browser URL if the user requests it; ctx propagates
// cancellation into that exec (CLI-10).
func ensureTailscaleAccount(ctx context.Context, p Printer, runner shell.Runner, headless bool) error {
	const signupURL = "https://login.tailscale.com/start"

	printerInfo(p, "  "+styleBold.Render("Tailscale account"))
	printerInfo(p, "")
	printerInfo(p, "  Abysslink routes all remote access through your private Tailscale network.")
	printerInfo(p, "  You need a free Tailscale account to continue.")
	printerInfo(p, "")
	printerInfo(p, "  "+styleMuted.Render("Sign in with Google, GitHub, Microsoft, or Apple — no password needed."))
	printerInfo(p, "  "+styleMuted.Render("Free tier covers 1 user + up to 100 devices."))
	printerInfo(p, "")
	printerInfo(p, "  Sign up or log in → "+styleCode.Render(signupURL))
	printerInfo(p, "")

	// Headless guard: skip TTY-blocking huh prompts when running non-interactively.
	// stdinIsTTY() is also checked here to catch the case where headless=false but
	// stdin is a pipe/redirect (e.g. `abysslink init </dev/null`).
	if headless || !stdinIsTTY() {
		return nil
	}

	var hasAccount bool
	if err := huh.NewConfirm().
		Title("Do you have a Tailscale account?").
		Description("If not, open the URL above in your browser and create one — it takes about 30 seconds.").
		Affirmative("Yes, I have an account").
		Negative("No, open the link for me").
		Value(&hasAccount).Run(); err != nil {
		return err
	}

	if !hasAccount {
		if err := openURL(ctx, runner, signupURL); err != nil {
			printerInfo(p, "  "+iconWarnStr()+"  Could not open browser — visit manually:")
			printerInfo(p, "  "+styleCode.Render(signupURL))
		} else {
			printerInfo(p, "  "+iconDoneStr()+"  Browser opened → "+styleCode.Render(signupURL))
		}
		printerInfo(p, "")
		printerInfo(p, "  "+styleMuted.Render("Create your account, then come back here."))
		printerInfo(p, "")

		var ready bool
		if err := huh.NewConfirm().
			Title("Ready to continue?").
			Description("Press yes once your Tailscale account is created.").
			Value(&ready).Run(); err != nil {
			return err
		}
		if !ready {
			return fmt.Errorf("init: Tailscale account is required — create one at %s", signupURL)
		}
	}

	printerInfo(p, "")
	return nil
}

// openURL opens url in the system browser. Returns an error if no browser opener
// is found on PATH or if the opener exits non-zero.
// runner is used for the actual exec so tests can inject a mock (shell.LookPath is
// a PATH probe that does not go through the runner). ctx is the caller's
// cancellable context (CLI-10 — never context.Background()).
func openURL(ctx context.Context, runner shell.Runner, url string) error {
	switch {
	case shell.LookPath("open"):
		res, err := runner.Run(ctx, "open", url) // macOS
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("open %s: exit %d", url, res.ExitCode)
		}
		return nil
	case shell.LookPath("xdg-open"):
		res, err := runner.Run(ctx, "xdg-open", url) // Linux
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("xdg-open %s: exit %d", url, res.ExitCode)
		}
		return nil
	}
	return fmt.Errorf("no browser opener found (tried: open, xdg-open)")
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
// "Logged out" is a valid daemon state (socket up, not yet authenticated) and
// must return true — only "failed to connect" means the daemon is not running.
func probeTailscaleDaemon(ctx context.Context, runner shell.Runner) bool {
	res, err := runner.Run(ctx, "tailscale", "status")
	if err != nil {
		return false
	}
	if res.ExitCode == 0 {
		return true // connected + authenticated
	}
	// Daemon is up but not authenticated when output does NOT mention socket failure.
	combined := res.Stdout + res.Stderr
	return !strings.Contains(combined, "failed to connect") &&
		!strings.Contains(combined, "is Tailscale running") &&
		!strings.Contains(combined, "connection refused")
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
		// Non-fatal: print the actual error + guidance and continue.
		printerInfo(p, "  "+iconWarnStr()+"  "+styleMuted.Render("Could not start daemon automatically: "+err.Error()))
		printerInfo(p, "  "+styleMuted.Render("  macOS:  brew services restart tailscale"))
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
// On macOS tailscale is installed by Homebrew as a user LaunchAgent
// (~/.Library/LaunchAgents/) and must be managed WITHOUT sudo. Using
// "restart" instead of "start" handles the common case where the plist is
// already loaded in launchd but the service is in an error state.
func doStartTailscaleDaemon(ctx context.Context, runner shell.Runner, plat platform.Platform) error {
	switch plat.OS() {
	case "darwin":
		res, err := runner.Run(ctx, "brew", "services", "restart", "tailscale")
		if err != nil {
			return fmt.Errorf("brew services restart tailscale: %w\n%s", err, strings.TrimSpace(res.Stderr))
		}
		return nil
	default: // linux
		res, err := runner.Run(ctx, "sudo", "systemctl", "enable", "--now", "tailscaled")
		if err != nil {
			return fmt.Errorf("systemctl enable tailscaled: %w\n%s", err, strings.TrimSpace(res.Stderr))
		}
		return nil
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

	// Show install plan before prompting, so the user knows the full scope.
	names := make([]string, 0, len(missing))
	for _, t := range missing {
		names = append(names, t.name)
	}
	printerInfo(p, "  "+styleMuted.Render(fmt.Sprintf(
		"Will install: %s (via %s)", strings.Join(names, ", "), plat.PackageManager())))
	printerInfo(p, "")

	for _, t := range missing {
		if err := installTool(ctx, p, runner, plat, t, autoYes); err != nil {
			return err
		}
	}
	return nil
}

// runSecurityFixes checks macOS firewall and AC sleep settings, prompting to fix
// each. These reduce the attack surface before the first `abysslink up --apply`.
// On Linux these checks are handled by the UFW and power modules; skip here.
func runSecurityFixes(ctx context.Context, p Printer, runner shell.Runner, plat platform.Platform, autoYes bool) error {
	if plat.OS() != "darwin" {
		return nil
	}
	printerInfo(p, "")
	printerInfo(p, "  "+styleBold.Render("Security hardening"))
	printerInfo(p, "")
	if err := maybeFixFirewall(ctx, p, runner, autoYes); err != nil {
		return err
	}
	return maybeFixSleep(ctx, p, runner, autoYes)
}

// maybeFixFirewall checks the macOS Application Firewall and offers to enable it.
func maybeFixFirewall(ctx context.Context, p Printer, runner shell.Runner, autoYes bool) error {
	const fwBin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	nameCol := styleNameCol.Render("firewall")

	res, err := runner.Run(ctx, fwBin, "--getglobalstate")
	if err == nil && strings.Contains(res.Stdout+res.Stderr, "enabled") {
		printerInfo(p, fmt.Sprintf("  %s  %s  enabled", iconDoneStr(), nameCol))
		return nil
	}

	printerInfo(p, fmt.Sprintf("  %s  %s  disabled", iconWarnStr(), nameCol))
	fix := autoYes
	if !autoYes {
		if err := huh.NewConfirm().
			Title("Enable macOS Application Firewall?").
			Description("Blocks unexpected inbound connections. Requires sudo password.").
			Value(&fix).Run(); err != nil {
			return err
		}
	}
	if !fix {
		return nil
	}
	printerInfo(p, fmt.Sprintf("  %s  Enabling firewall...", iconSpinStr()))
	// RunInteractive lets sudo reach the real tty so macOS's tty-keyed credential
	// cache can reuse the timestamp from the earlier sudo call in maybeFixSleep
	// (or vice versa) — avoids a second password prompt within the same init run.
	if err := runner.RunInteractive(ctx, "sudo", fwBin, "--setglobalstate", "on"); err != nil {
		return fmt.Errorf("init: enable firewall: %w", err)
	}
	printerInfo(p, fmt.Sprintf("  %s  %s  enabled", iconDoneStr(), nameCol))
	return nil
}

// maybeFixSleep checks whether the system sleeps on AC power and offers to disable it.
// A rig that sleeps at night is unreachable from the phone.
func maybeFixSleep(ctx context.Context, p Printer, runner shell.Runner, autoYes bool) error {
	nameCol := styleNameCol.Render("sleep (AC)")
	if checkACSleepDisabled(ctx, runner) {
		printerInfo(p, fmt.Sprintf("  %s  %s  disabled", iconDoneStr(), nameCol))
		return nil
	}

	printerInfo(p, fmt.Sprintf("  %s  %s  enabled — rig may sleep and become unreachable", iconWarnStr(), nameCol))
	fix := autoYes
	if !autoYes {
		if err := huh.NewConfirm().
			Title("Prevent sleep while on AC power?").
			Description("Keeps the rig reachable overnight. Requires sudo password.").
			Value(&fix).Run(); err != nil {
			return err
		}
	}
	if !fix {
		return nil
	}
	printerInfo(p, fmt.Sprintf("  %s  Updating power settings...", iconSpinStr()))
	// RunInteractive exposes stdin to the real tty so sudo's tty-keyed credential
	// cache is shared with the maybeFixFirewall sudo call above — single password
	// prompt for both privileged operations in the same init run.
	if err := runner.RunInteractive(ctx, "sudo", "pmset", "-c", "sleep", "0", "disksleep", "0"); err != nil {
		return fmt.Errorf("init: disable AC sleep: %w", err)
	}
	printerInfo(p, fmt.Sprintf("  %s  %s  disabled", iconDoneStr(), nameCol))
	return nil
}

// checkACSleepDisabled returns true when pmset reports sleep=0 for the AC power
// source. It reads `pmset -g custom` (the AC/custom profile) rather than bare
// `pmset -g` (the *active* power source) so the probe agrees with the AC profile
// that maybeFixSleep mutates via `pmset -c …`; on battery the two never agree
// otherwise (CR-01). A non-zero pmset exit is treated as "not disabled" to mirror
// the power module's exit-code check and avoid a false positive (WR-03).
func checkACSleepDisabled(ctx context.Context, runner shell.Runner) bool {
	res, err := runner.Run(ctx, "pmset", "-g", "custom")
	if err != nil || res.ExitCode != 0 {
		return false
	}
	// pmset -g custom emits "AC Power:" and "Battery Power:" blocks; only the AC
	// block is consulted so a non-zero battery sleep is never read as AC. When no
	// power-source header is present (legacy output / test fixture), all lines are
	// considered so the parser degrades gracefully.
	inAC, sawHeader := true, false
	for _, raw := range strings.Split(res.Stdout, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "AC Power"):
			inAC, sawHeader = true, true
			continue
		case strings.HasPrefix(line, "Battery Power"):
			inAC, sawHeader = false, true
			continue
		}
		if sawHeader && !inAC {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "sleep" && fields[1] == "0" {
			return true
		}
	}
	return false
}

// initFormResult holds the collected values from the interactive init form before
// they are applied to a Config. Separating collection from application allows tests
// to exercise applyInitFormResult without needing a TTY.
type initFormResult struct {
	email              string
	hostname           string
	enableSSH          bool
	enableTmux         bool
	enableMosh         bool
	enableNtfy         bool
	ntfyPort           int
	backendType        string // "tailscale", "headscale", or "netbird"
	headscaleServerURL string // non-empty only when backendType == "headscale"
	netbirdServerURL   string // non-empty only when backendType == "netbird"
}

// applyInitFormResult converts a collected initFormResult into a *config.Config.
// All non-interactive defaults are established here so that tests can call this
// directly without running the huh form.
func applyInitFormResult(r initFormResult) (*config.Config, error) {
	cfg := config.Defaults()
	cfg.Identity.Email = r.email
	cfg.Identity.UnixUser = currentUnixUser()
	cfg.Tailnet.Hostname = r.hostname
	cfg.Tailnet.SSH = r.enableSSH
	cfg.Modules.SSH.Enabled = r.enableSSH
	cfg.Modules.SSH.Mode = "tailscale"
	cfg.Modules.Tmux.Enabled = r.enableTmux
	cfg.Modules.Mosh.Enabled = r.enableMosh
	cfg.Modules.Ntfy.Enabled = r.enableNtfy
	cfg.Modules.Ntfy.Port = r.ntfyPort
	cfg.Modules.Notify.Enabled = r.enableNtfy
	// Backend type: "tailscale" is the default; "headscale" and "netbird" populate
	// their respective server sub-struct fields.
	cfg.Backend.Type = r.backendType
	if r.backendType == "headscale" {
		cfg.Server.Headscale.ServerURL = r.headscaleServerURL
		cfg.Server.Headscale.User = "abysslink" // stable default per D-13
	}
	if r.backendType == "netbird" {
		cfg.Server.NetBird.ServerURL = r.netbirdServerURL
	}
	return cfg, nil
}

// promptBackendServerURL runs the conditional server URL prompts for self-hosted
// backends (headscale and netbird) after the main form completes. Extracted to
// keep runInitForm's cyclomatic complexity below the gocyclo limit.
func promptBackendServerURL(cmd *cobra.Command, r *initFormResult) error {
	switch r.backendType {
	case "headscale":
		return huh.NewInput().
			Title("Headscale server URL").
			Description("Public HTTPS URL of your Headscale instance (e.g. https://headscale.example.com)").
			Value(&r.headscaleServerURL).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("server URL is required for headscale backend")
				}
				if !strings.HasPrefix(s, "https://") {
					return fmt.Errorf("server URL must start with https://")
				}
				return nil
			}).Run()
	case "netbird":
		// Emit degradation warning before prompting — wizard-time D-04 disclosure.
		printerInfo(newPrinter(cmd), styleWarn.Render(
			"WARN: NetBird does not support SSH checkPeriod enforcement. "+
				"You will need to run `abysslink up --accept-no-sshcheck` on first use."))
		return huh.NewInput().
			Title("NetBird server URL").
			Description("Management server base URL (e.g. https://nb.example.com)").
			Value(&r.netbirdServerURL).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("server URL is required for netbird backend")
				}
				if !strings.HasPrefix(s, "https://") {
					return fmt.Errorf("server URL must start with https://")
				}
				return nil
			}).Run()
	}
	return nil
}

// sanitizeHostname lowercases h and strips every character outside the
// DNS-safe set enforced by config.Load (safeHostnamePat: [a-z0-9-.], lowercase
// only). Underscores and spaces become hyphens; leading/trailing hyphens and
// dots are trimmed. macOS's os.Hostname() default (e.g.
// "Mohans-MacBook-Pro.local") would otherwise pre-fill a value that bricks
// every later command at config.Load (C1).
func sanitizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		case r == '_' || r == ' ':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-.")
}

// validateInitHostname is the inline form validator for the hostname input.
// It mirrors the config.Load rules so the wizard can never collect a value
// the config loader would later reject (C1).
func validateInitHostname(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("hostname is required")
	}
	if s != strings.ToLower(s) {
		return fmt.Errorf("hostname must be lowercase (try %q)", sanitizeHostname(s))
	}
	if err := config.ValidateHostname(s); err != nil {
		return fmt.Errorf("only a-z, 0-9, hyphens and dots are allowed (try %q)", sanitizeHostname(s))
	}
	return nil
}

// initEmailFromFlags resolves the headless email source: --email flag first,
// ABYSSLINK_EMAIL env second (C2). cmd may be nil (direct test callers).
func initEmailFromFlags(cmd *cobra.Command) string {
	if cmd != nil {
		if email, _ := cmd.Flags().GetString("email"); email != "" {
			return email
		}
	}
	return os.Getenv("ABYSSLINK_EMAIL")
}

// initHostnameFromFlags returns the --hostname flag value, or "" when unset or
// cmd is nil (direct test callers).
func initHostnameFromFlags(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}
	h, _ := cmd.Flags().GetString("hostname")
	return h
}

// initFormPrefill builds the initFormResult defaults: module toggles, email
// from --email/ABYSSLINK_EMAIL, and the hostname pre-fill sanitized to the
// lowercase DNS-safe set config.Load enforces — never a default the loader
// rejects (C1). Under autoYes it applies the headless fail-fast guards (C2):
// no config that config.Load would reject is ever produced.
func initFormPrefill(cmd *cobra.Command, autoYes bool) (initFormResult, error) {
	r := initFormResult{
		enableSSH:   true,
		enableTmux:  true,
		enableMosh:  true,
		enableNtfy:  true,
		ntfyPort:    2586,
		backendType: "tailscale", // default — changed to "headscale" or "netbird" when user selects it
	}
	r.email = initEmailFromFlags(cmd)
	if h := initHostnameFromFlags(cmd); h != "" {
		r.hostname = sanitizeHostname(h)
	} else {
		osHost, _ := os.Hostname()
		r.hostname = sanitizeHostname(osHost)
	}

	if autoYes {
		if r.email == "" {
			return r, fmt.Errorf("init --yes: an account email is required in non-interactive mode — pass --email <addr> or set ABYSSLINK_EMAIL (a config without identity.email cannot be loaded)")
		}
		if err := validateInitHostname(r.hostname); err != nil {
			return r, fmt.Errorf("init --yes: cannot derive a valid rig hostname from the OS (%v) — pass --hostname <name>", err)
		}
	}
	if r.email != "" && !strings.Contains(r.email, "@") {
		return r, fmt.Errorf("init: email %q is not a valid email address", r.email)
	}
	return r, nil
}

// runInitForm runs the interactive questionnaire and returns the resulting Config.
func runInitForm(cmd *cobra.Command, autoYes bool) (*config.Config, error) {
	r, err := initFormPrefill(cmd, autoYes)
	if err != nil {
		return nil, err
	}

	if !autoYes {
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Backend type").
					Description("Which Tailscale-compatible control server to use").
					Options(
						huh.NewOption("Tailscale (cloud, requires account)", "tailscale"),
						huh.NewOption("Headscale (self-hosted)", "headscale"),
						huh.NewOption("NetBird (self-hosted, REST-only — SSHCheck degradation, see docs)", "netbird"),
					).
					Value(&r.backendType),
			),
			huh.NewGroup(
				// Backend-neutral wording (U8): headscale/netbird users have no
				// "Tailscale account"; the email is the config identity.
				huh.NewInput().
					Title("Account email").
					Description("The email you sign in to your control plane with (Tailscale, Headscale, or NetBird)").
					Value(&r.email).
					Validate(func(s string) error {
						if !strings.Contains(s, "@") {
							return fmt.Errorf("must be a valid email address")
						}
						return nil
					}),
				huh.NewInput().
					Title("Rig hostname").
					Description("This machine's tailnet hostname (pre-filled from OS, lowercase a-z0-9-.)").
					Value(&r.hostname).
					Validate(validateInitHostname),
			),
			huh.NewGroup(
				huh.NewConfirm().
					Title("Enable Tailscale SSH?").
					Description("Replaces macOS Remote Login with Tailscale's cryptographically-verified SSH — no open ports, no password auth").
					Value(&r.enableSSH),
				huh.NewConfirm().
					Title("Enable tmux?").
					Description("Keeps your terminal session alive on the rig — reconnect from your phone and pick up exactly where you left off").
					Value(&r.enableTmux),
				huh.NewConfirm().
					Title("Enable mosh?").
					Description("Roaming shell that survives network switches on your phone (WiFi↔LTE), timeouts, and sleep — reconnects automatically").
					Value(&r.enableMosh),
				huh.NewConfirm().
					Title("Enable ntfy push notifications?").
					Description("Sends a buzz to your phone when Claude stops, a build finishes, or any terminal task completes — no polling needed").
					Value(&r.enableNtfy),
			),
		)
		if err := form.Run(); err != nil {
			return nil, fmt.Errorf("init: %w", err)
		}
		// Conditional server URL prompts for self-hosted backends.
		if err := promptBackendServerURL(cmd, &r); err != nil {
			return nil, err
		}
		if r.enableNtfy {
			portStr := fmt.Sprintf("%d", r.ntfyPort)
			if err := huh.NewInput().
				Title("ntfy listen port").
				Description("Port for the notification server on your tailnet.\nDefault 2586 avoids conflicts with local dev servers (8080, 3000, etc.).").
				Value(&portStr).
				Validate(func(s string) error {
					n, err := strconv.Atoi(strings.TrimSpace(s))
					if err != nil || n < 1024 || n > 65535 {
						return fmt.Errorf("must be a number between 1024 and 65535")
					}
					return nil
				}).Run(); err != nil {
				return nil, fmt.Errorf("init: ntfy port: %w", err)
			}
			if n, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil {
				r.ntfyPort = n
			}
		}
	}

	return applyInitFormResult(r)
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

// previewAndConfirmConfig marshals cfg to YAML, prints the preview via p, and
// then asks the user to confirm before writing. It returns (true, nil) when the
// user confirms (or autoYes is set), and (false, nil) when the user declines.
// Under autoYes the preview is still printed so the user can see exactly what
// will be written, but the confirm prompt is skipped.
//
// configPath is shown in the confirmation so the prompt says exactly what the
// action is — writing one YAML file — instead of the "Apply N change(s)? This
// will modify your system." blast warning, which misdescribes it (U12).
//
// Config contains only email, hostname, module toggles, and safe defaults.
// Secrets (API keys, tokens) live exclusively in the OS keychain and are never
// marshalled here — callers must not route the returned yaml through slog or
// audit (it contains no secrets but the output is also not auditable by value).
func previewAndConfirmConfig(ctx context.Context, p Printer, cfg *config.Config, configPath string, autoYes bool) (bool, error) {
	data, err := config.Marshal(cfg)
	if err != nil {
		return false, fmt.Errorf("marshal config for preview: %w", err)
	}

	printerInfo(p, "")
	printerInfo(p, styleBold.Render("Config preview")+" "+styleMuted.Render("(what will be written to abysslink.yaml)"))
	printerInfo(p, "")
	// Print each line of the YAML with indentation so it stands out as a block.
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		printerInfo(p, "  "+styleCode.Render(line))
	}
	printerInfo(p, "")

	if autoYes {
		slog.Warn("init --yes: skipping config-write confirmation; writing immediately")
		return true, nil
	}

	// Non-interactive context (CI, pipe): do not hang — return false so the
	// caller's RunE can surface an actionable error or skip the write.
	if !interactive(autoYes, false) {
		return false, nil
	}

	ok, err := tui.Confirm(ctx, fmt.Sprintf("Write config to %s?", configPath), autoYes)
	if err != nil {
		return false, err
	}
	return ok, nil
}
