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
	"fmt"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/spf13/cobra"
)

func newWatchCmd() *cobra.Command {
	watch := &cobra.Command{
		Use:   "watch",
		Short: "Manage tmux pane watchers (notify when a pane sits idle at a prompt)",
	}
	watch.AddCommand(newWatchAddCmd(), newWatchListCmd(), newWatchRemoveCmd())
	return watch
}

func newWatchAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <pane>",
		Short: "Watch a tmux pane and notify when it is idle at a prompt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateWatchPanes(cmd, func(panes []string) ([]string, string) {
				pane := args[0]
				for _, p := range panes {
					if p == pane {
						return panes, fmt.Sprintf("pane %q is already watched", pane)
					}
				}
				return append(panes, pane), fmt.Sprintf("Now watching pane %q.", pane)
			})
		},
	}
}

func newWatchRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <pane>",
		Short: "Stop watching a tmux pane",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return mutateWatchPanes(cmd, func(panes []string) ([]string, string) {
				pane := args[0]
				out := panes[:0:0]
				found := false
				for _, p := range panes {
					if p == pane {
						found = true
						continue
					}
					out = append(out, p)
				}
				if !found {
					return panes, fmt.Sprintf("pane %q was not watched", pane)
				}
				return out, fmt.Sprintf("Stopped watching pane %q.", pane)
			})
		},
	}
}

func newWatchListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List watched tmux panes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := newPrinter(cmd)
			cfg, err := config.Load(resolveConfigPath(cmd))
			if err != nil {
				return fmt.Errorf("watch list: %w", err)
			}
			if !cfg.Modules.Watch.Enabled || len(cfg.Modules.Watch.Panes) == 0 {
				printerInfo(p, "No panes are being watched.")
				return nil
			}
			printerInfo(p, styleBold.Render("Watched panes"))
			for _, pane := range cfg.Modules.Watch.Panes {
				printerInfo(p, "  - "+pane)
			}
			return nil
		},
	}
}

// mutateWatchPanes loads config, transforms the pane list via fn, persists, and
// reports fn's message. The daemon picks up the change on its next restart.
func mutateWatchPanes(cmd *cobra.Command, fn func([]string) ([]string, string)) error {
	p := newPrinter(cmd)
	path := resolveConfigPath(cmd)
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("watch: %w (run `abysslink init` first)", err)
	}
	newPanes, msg := fn(cfg.Modules.Watch.Panes)
	cfg.Modules.Watch.Panes = newPanes
	cfg.Modules.Watch.Enabled = len(newPanes) > 0 || cfg.Modules.Watch.Enabled
	if err := config.Write(path, cfg); err != nil {
		return fmt.Errorf("watch: write config: %w", err)
	}
	printerInfo(p, msg)
	printerInfo(p, styleMuted.Render("Restart the daemon to apply: abysslink daemon stop && abysslink daemon start"))
	return nil
}
