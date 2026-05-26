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
	"log/slog"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/modules/acl"
	"github.com/abysslink/abysslink/internal/modules/hardening"
	"github.com/abysslink/abysslink/internal/modules/lock"
	"github.com/abysslink/abysslink/internal/modules/mosh"
	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/modules/ntfy"
	"github.com/abysslink/abysslink/internal/modules/power"
	"github.com/abysslink/abysslink/internal/modules/ssh"
	tsmod "github.com/abysslink/abysslink/internal/modules/tailscale"
	"github.com/abysslink/abysslink/internal/modules/tmux"
	"github.com/abysslink/abysslink/internal/modules/watch"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// cmdContext holds shared state for a command invocation.
type cmdContext struct {
	cfg     *config.Config
	runner  shell.Runner
	dryRun  bool
	apply   bool
	yes     bool
	jsonOut bool
	verbose bool
}

// loadCmdContext loads config and resolves flags from the root command.
func loadCmdContext(cmd *cobra.Command) (*cmdContext, error) {
	configPath, _ := cmd.Flags().GetString("config")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	apply, _ := cmd.Flags().GetBool("apply")
	yes, _ := cmd.Flags().GetBool("yes")
	jsonOut, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		// For commands that don't need config (like status), return defaults.
		cfg = config.Defaults()
	}

	// Default: if neither --apply nor --dry-run is set, dry-run mode.
	if !apply && !dryRun {
		dryRun = true
	}

	return &cmdContext{
		cfg:     cfg,
		runner:  &shell.ExecRunner{},
		dryRun:  dryRun,
		apply:   apply,
		yes:     yes,
		jsonOut: jsonOut,
		verbose: verbose,
	}, nil
}

// newPrinter returns the appropriate Printer based on --json flag.
func newPrinter(cmd *cobra.Command) Printer {
	jsonOut, _ := cmd.Flags().GetBool("json")
	if jsonOut {
		return NewJSONPrinter()
	}
	return NewHumanPrinter()
}

// printerInfo calls p.Print for informational messages.
func printerInfo(p Printer, msg string) { p.Print(msg) }

// printerWarn calls p.Print with a WARN prefix.
func printerWarn(p Printer, msg string) { p.Print(msg) }

// printerError calls p.Error.
func printerError(p Printer, msg string) { p.Error(msg) }

// allModules returns all 11 core modules with the given runner and config.
func allModules(runner shell.Runner, cfg *config.Config) []modules.Module {
	return []modules.Module{
		tsmod.New(runner, cfg),
		ssh.New(runner, cfg),
		tmux.New(runner, cfg),
		mosh.New(runner, cfg),
		acl.New(runner, cfg),
		lock.New(runner, cfg),
		notifymod.New(runner, cfg, nil),
		ntfy.New(runner, cfg),
		watch.New(runner, cfg),
		power.New(runner, cfg),
		hardening.New(runner, cfg),
	}
}
