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

	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/platform"
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
func daemonLifecycleCmd(use, short string, fn func(context.Context, platform.Platform) error) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("daemon %s: %w", use, err)
			}
			if err := fn(ctx, deps.Platform); err != nil {
				return fmt.Errorf("daemon %s: %w", use, err)
			}
			printerInfo(newPrinter(cmd), "daemon "+use+": ok")
			return nil
		},
	}
}

func newDaemonStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
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
// the daemon binary next to the running abysslink binary.
func daemonServiceSpec() (platform.ServiceSpec, error) {
	exe, err := os.Executable()
	if err != nil {
		return platform.ServiceSpec{}, fmt.Errorf("resolve executable: %w", err)
	}
	binPath := filepath.Join(filepath.Dir(exe), "abysslinkd")
	if _, statErr := os.Stat(binPath); statErr != nil {
		binPath = "abysslinkd" // fall back to PATH lookup at service start
	}

	stateDir := abysslinkStateDir()
	_ = os.MkdirAll(stateDir, 0o700)

	return platform.ServiceSpec{
		Label:      daemonLabel,
		Args:       []string{binPath},
		StdoutPath: filepath.Join(stateDir, "abysslinkd.out.log"),
		StderrPath: filepath.Join(stateDir, "abysslinkd.err.log"),
		KeepAlive:  true,
		RunAtLoad:  true,
	}, nil
}
