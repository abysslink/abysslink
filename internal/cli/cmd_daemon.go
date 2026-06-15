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
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

const daemonLabel = "dev.abysslink.abysslinkd"

func newDaemonCmd() *cobra.Command {
	d := &cobra.Command{
		Use:   "daemon",
		Short: "Manage the abysslinkd background daemon (notify socket + watchers)",
	}
	d.AddCommand(
		daemonLifecycleCmd("start", "Start the daemon", func(ctx context.Context, p platform.Platform) error {
			return p.ServiceStart(ctx, daemonLabel)
		}),
		daemonLifecycleCmd("stop", "Stop the daemon", func(ctx context.Context, p platform.Platform) error {
			return p.ServiceStop(ctx, daemonLabel)
		}),
		daemonLifecycleCmd("enable", "Install and start the daemon at login", func(ctx context.Context, p platform.Platform) error {
			spec, err := daemonServiceSpec()
			if err != nil {
				return err
			}
			if err := p.ServiceInstall(ctx, spec); err != nil {
				return err
			}
			return p.ServiceStart(ctx, daemonLabel)
		}),
		daemonLifecycleCmd("disable", "Stop and remove the daemon login service", func(ctx context.Context, p platform.Platform) error {
			_ = p.ServiceStop(ctx, daemonLabel)
			return p.ServiceUninstall(ctx, daemonLabel)
		}),
		newDaemonStatusCmd(),
	)
	return d
}

// daemonLifecycleCmd builds a subcommand that resolves the platform and runs fn.
// Lifecycle subcommands mutate service state (launchd/systemd), so the standard
// [plan]/--apply gate applies (CLI-07): without --apply they print a preview and
// touch nothing. Read-only subcommands (`daemon status`) are built separately
// and stay ungated.
func daemonLifecycleCmd(use, short string, fn func(context.Context, platform.Platform) error) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short + " (dry-run by default)",
		Example: "  # Preview (dry-run — no changes)\n  abysslink daemon " + use + "\n\n  # " + short + "\n  abysslink daemon " + use + " --apply",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)

			if !cc.apply {
				printerInfo(p, fmt.Sprintf("[plan] would %s%s (service %s)",
					strings.ToLower(short[:1]), short[1:], daemonLabel))
				printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
				return nil
			}

			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("daemon %s: %w", use, err)
			}
			if err := fn(ctx, deps.Platform); err != nil {
				return fmt.Errorf("daemon %s: %w", use, err)
			}
			printerInfo(p, "daemon "+use+": ok")
			return nil
		},
	}
}

func newDaemonStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		Example: `  # Show whether abysslinkd is running
  abysslink daemon status`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("daemon status: %w", err)
			}

			svc, _ := deps.Platform.ServiceStatus(ctx, daemonLabel)
			socketUp := daemon.NewClient().Ping(ctx)
			watches := 0
			if cc.cfg.Modules.Watch.Enabled {
				watches = len(cc.cfg.Modules.Watch.Panes)
			}

			printerInfo(p, fmt.Sprintf("  service:   %s", svc))
			printerInfo(p, fmt.Sprintf("  socket:    %s (%s)", daemon.SocketPath(), reachable(socketUp)))
			printerInfo(p, fmt.Sprintf("  watchers:  %d pane(s)", watches))
			return nil
		},
	}
}

func reachable(ok bool) string {
	if ok {
		return "reachable"
	}
	return "not reachable"
}

// daemonServiceSpec builds the launchd/systemd spec for abysslinkd, resolving
// the daemon binary next to the running abysslink binary. The service spec
// always carries an ABSOLUTE path: a bare "abysslinkd" would defer PATH
// resolution to launchd/systemd start time — a hijack/footgun surface (the
// service manager's PATH is not the user's), so a daemon that cannot be
// resolved NOW is a clear error instead.
func daemonServiceSpec() (platform.ServiceSpec, error) {
	exe, err := os.Executable()
	if err != nil {
		return platform.ServiceSpec{}, fmt.Errorf("resolve executable: %w", err)
	}
	binPath := filepath.Join(filepath.Dir(exe), "abysslinkd")
	if _, statErr := os.Stat(binPath); statErr != nil {
		resolved, lookErr := shell.ResolvePath("abysslinkd")
		if lookErr != nil {
			return platform.ServiceSpec{}, fmt.Errorf(
				"abysslinkd not found next to %s and not on PATH — install abysslinkd before enabling the daemon: %w", exe, lookErr)
		}
		binPath = resolved
	}

	stateDir := abysslinkStateDir()
	_ = os.MkdirAll(stateDir, 0o700)

	return platform.ServiceSpec{
		Label:      daemonLabel,
		Args:       []string{binPath},
		Env:        map[string]string{"PATH": daemonServicePATH},
		StdoutPath: filepath.Join(stateDir, "abysslinkd.out.log"),
		StderrPath: filepath.Join(stateDir, "abysslinkd.err.log"),
		KeepAlive:  true,
		RunAtLoad:  true,
	}, nil
}

// daemonServicePATH is the PATH the daemon runs with under launchd/systemd.
//
// Service managers hand a process a minimal PATH (launchd: /usr/bin:/bin:/usr/sbin:/sbin)
// that excludes Homebrew (/opt/homebrew/bin) and /usr/local/bin — exactly where
// tailscale, tmux, and mosh live. Without these dirs the daemon's CLI shellouts
// fail "executable file not found in $PATH": the content listener cannot confirm
// its tailnet-IP bind and disables itself (BACK-06), and the notify module's
// backend IP lookup fails so it falls back to http://localhost:<ntfy_port>, which
// the secure tailnet-only ntfy bind refuses — surfacing as a 502 to notify clients.
//
// This is a FIXED set of root-owned, conventional bin dirs — deliberately NOT
// os.Getenv("PATH"). Baking the enabling user's full PATH into a persisted
// service plist would import any world-writable or relative entries as a
// shellout-hijack surface for the daemon, contradicting the absolute-binary-path
// guard in daemonServiceSpec. A tailscale installed outside these dirs degrades
// honestly (content listener warns) rather than widening that surface.
const daemonServicePATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
