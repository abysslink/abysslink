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

	"github.com/abysslink/abysslink/internal/audit"
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
	platformauto "github.com/abysslink/abysslink/internal/platform/auto"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tui"
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

	// Default to WARN so internal slog.Info/Debug noise is hidden.
	// --verbose drops to Debug for troubleshooting.
	if verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	} else {
		slog.SetLogLoggerLevel(slog.LevelWarn)
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

// confirmAction prompts the user to confirm a destructive action, honoring the
// --yes flag (which auto-confirms).
func confirmAction(ctx context.Context, cc *cmdContext, prompt string) (bool, error) {
	return tui.Confirm(ctx, prompt, cc.yes)
}

// printerInfo calls p.Print for informational messages.
func printerInfo(p Printer, msg string) { p.Print(msg) }

// printerError calls p.Error.
func printerError(p Printer, msg string) { p.Error(msg) }

// buildDeps constructs the dependency bundle shared by every module: the
// platform facade for the host OS, the keychain store, and the audit writer.
// A missing keychain backend (e.g. Linux without secret-tool or pass) is
// non-fatal — modules that need a secret surface a clear error at point of use
// rather than panicking.
func buildDeps(ctx context.Context, cc *cmdContext) (modules.Deps, error) {
	plat, err := platformauto.New(cc.runner)
	if err != nil {
		return modules.Deps{}, fmt.Errorf("platform init: %w", err)
	}

	kc, err := secrets.NewStore(ctx, cc.runner)
	if err != nil {
		slog.Warn("keychain backend unavailable; secret operations will fail until a backend is installed", "err", err)
		kc = nil
	}

	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return modules.Deps{}, fmt.Errorf("audit init: %w", err)
	}

	return modules.Deps{
		Cfg:      cc.cfg,
		Runner:   cc.runner,
		Platform: plat,
		Keychain: kc,
		Audit:    audit.New(logPath),
	}, nil
}

// allModules returns all 11 core modules wired with the shared dependency bundle.
func allModules(deps modules.Deps) []modules.Module {
	return []modules.Module{
		tsmod.New(deps),
		ssh.New(deps),
		tmux.New(deps),
		mosh.New(deps),
		acl.New(deps),
		lock.New(deps),
		notifymod.New(deps),
		ntfy.New(deps),
		watch.New(deps),
		power.New(deps),
		hardening.New(deps),
	}
}
