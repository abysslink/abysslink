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
	"errors"
	"fmt"
	"os"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/spf13/cobra"
)

func newWatchCmd() *cobra.Command {
	watch := &cobra.Command{
		Use:   "watch",
		Short: "Manage abysslinkd watchers (tmux pane, file, and HTTP) that notify your phone",
	}
	watch.AddCommand(newWatchAddCmd(), newWatchListCmd(), newWatchRemoveCmd())
	return watch
}

func newWatchAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a watcher: --pane <p>, or --file <path> --grep <re>, or --http <url> (dry-run by default)",
		Example: `  # Preview adding a tmux pane watcher (dry-run — no changes)
  abysslink watch add --pane 0 --label "main session"

  # Watch a tmux pane for idle
  abysslink watch add --pane 0 --label "main session" --apply

  # Watch a log file for a pattern
  abysslink watch add --file /var/log/app.log --grep "ERROR" --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pane, _ := cmd.Flags().GetString("pane")
			file, _ := cmd.Flags().GetString("file")
			httpURL, _ := cmd.Flags().GetString("http")
			grep, _ := cmd.Flags().GetString("grep")
			expect, _ := cmd.Flags().GetInt("expect")
			label, _ := cmd.Flags().GetString("label")
			interval, _ := cmd.Flags().GetInt("interval")
			poll, _ := cmd.Flags().GetInt("poll")

			return mutateWatch(cmd, func(w *config.WatchModule) (string, error) {
				switch {
				case pane != "":
					// Reject duplicates: a pane registered twice would fire
					// duplicate notifications for every event.
					for _, existing := range w.Panes {
						if existing == pane {
							return "", fmt.Errorf("watch add: pane watcher %q is already configured", pane)
						}
					}
					w.Panes = append(w.Panes, pane)
					return "add tmux pane watcher " + pane, nil
				case file != "":
					if grep == "" {
						return "", fmt.Errorf("--file requires --grep <regexp>")
					}
					w.Files = append(w.Files, config.FileWatch{Path: file, Grep: grep, Label: label, PollSecs: poll})
					return "add file watcher " + file, nil
				case httpURL != "":
					w.HTTP = append(w.HTTP, config.HTTPWatch{URL: httpURL, Expect: expect, Label: label, IntervalSecs: interval})
					return "add HTTP watcher " + httpURL, nil
				default:
					return "", fmt.Errorf("specify one of --pane, --file (+--grep), or --http")
				}
			})
		},
	}
	cmd.Flags().String("pane", "", "tmux pane to watch for idle-at-prompt")
	cmd.Flags().String("file", "", "file path to tail")
	cmd.Flags().String("grep", "", "regexp that an appended line must match (with --file)")
	cmd.Flags().String("http", "", "URL to poll")
	cmd.Flags().Int("expect", 0, "expected HTTP status (notify on change; with --http)")
	cmd.Flags().Int("interval", 0, "HTTP poll interval in seconds (default 60)")
	cmd.Flags().Int("poll", 0, "file poll interval in seconds (default 2; with --file)")
	cmd.Flags().String("label", "", "human label for the notification")
	return cmd
}

func newWatchRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a watcher by --pane, --file, or --http identifier",
		Example: `  # Remove a tmux pane watcher
  abysslink watch remove --pane 0 --apply

  # Remove a file watcher
  abysslink watch remove --file /var/log/app.log --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pane, _ := cmd.Flags().GetString("pane")
			file, _ := cmd.Flags().GetString("file")
			httpURL, _ := cmd.Flags().GetString("http")

			return mutateWatch(cmd, func(w *config.WatchModule) (string, error) {
				// CLI-03: removing a watcher that does not exist is an error —
				// never report success for a no-op removal.
				switch {
				case pane != "":
					kept := removeString(w.Panes, pane)
					if len(kept) == len(w.Panes) {
						return "", fmt.Errorf("watch remove: no pane watcher %q configured", pane)
					}
					w.Panes = kept
					return "remove pane watcher " + pane, nil
				case file != "":
					kept := w.Files[:0:0]
					for _, f := range w.Files {
						if f.Path != file {
							kept = append(kept, f)
						}
					}
					if len(kept) == len(w.Files) {
						return "", fmt.Errorf("watch remove: no file watcher %q configured", file)
					}
					w.Files = kept
					return "remove file watcher " + file, nil
				case httpURL != "":
					kept := w.HTTP[:0:0]
					for _, h := range w.HTTP {
						if h.URL != httpURL {
							kept = append(kept, h)
						}
					}
					if len(kept) == len(w.HTTP) {
						return "", fmt.Errorf("watch remove: no HTTP watcher %q configured", httpURL)
					}
					w.HTTP = kept
					return "remove HTTP watcher " + httpURL, nil
				default:
					return "", fmt.Errorf("specify one of --pane, --file, or --http")
				}
			})
		},
	}
	cmd.Flags().String("pane", "", "tmux pane watcher to remove")
	cmd.Flags().String("file", "", "file watcher (path) to remove")
	cmd.Flags().String("http", "", "HTTP watcher (url) to remove")
	return cmd
}

func newWatchListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured watchers",
		Example: `  # Show all configured watchers
  abysslink watch list`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := newPrinter(cmd)
			cfg, err := config.Load(resolveConfigPath(cmd))
			if err != nil {
				// CLI-23: `watch list` is read-only — a missing config simply
				// means no watchers are configured yet. Degrade gracefully
				// instead of hard-failing with a raw error. (config.Defaults()
				// ships a "main" pane watcher, so render the empty state
				// directly rather than listing defaults the user never wrote.)
				if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("watch list: %w", err)
				}
				printerInfo(p, "No watchers configured.")
				return nil
			}
			w := cfg.Modules.Watch
			if len(w.Panes) == 0 && len(w.Files) == 0 && len(w.HTTP) == 0 {
				printerInfo(p, "No watchers configured.")
				return nil
			}
			commandHeader(p, "watch list", styleMuted.Render("configured watchers"))
			for _, pane := range w.Panes {
				printerInfo(p, "  pane  "+pane)
			}
			for _, f := range w.Files {
				printerInfo(p, fmt.Sprintf("  file  %s  (grep %q)", f.Path, f.Grep))
			}
			for _, h := range w.HTTP {
				printerInfo(p, fmt.Sprintf("  http  %s  (expect %d)", h.URL, h.Expect))
			}
			return nil
		},
	}
}

// mutateWatch loads config, applies fn to the watch module, and — only under
// --apply — persists the change (CLI-03: dry-run is the default; without
// --apply it prints a [plan] preview and writes nothing). fn returns an
// imperative change description ("add tmux pane watcher 0"). Enables the watch
// module if any watcher remains.
func mutateWatch(cmd *cobra.Command, fn func(*config.WatchModule) (string, error)) error {
	p := newPrinter(cmd)
	_, apply, err := resolveApplyFlags(cmd)
	if err != nil {
		return err
	}
	path := resolveConfigPath(cmd)
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("watch: %w (run `abysslink init` first)", err)
	}
	desc, err := fn(&cfg.Modules.Watch)
	if err != nil {
		return err
	}
	// Keep the enabled flag consistent with reality in BOTH directions: adding
	// the first watcher enables the module; removing the last one disables it
	// (a lingering enabled:true with zero watchers is a config lie).
	w := cfg.Modules.Watch
	cfg.Modules.Watch.Enabled = len(w.Panes) > 0 || len(w.Files) > 0 || len(w.HTTP) > 0

	if !apply {
		printerInfo(p, "[plan] would "+desc)
		printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
		return nil
	}

	if err := config.Write(path, cfg); err != nil {
		return fmt.Errorf("watch: write config: %w", err)
	}
	printerInfo(p, "Applied: "+desc)
	printerInfo(p, styleMuted.Render("Restart the daemon to apply: abysslink daemon stop && abysslink daemon start"))
	return nil
}

// removeString returns s without any occurrence of v (all matches removed).
func removeString(s []string, v string) []string {
	out := s[:0:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
