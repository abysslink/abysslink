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
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/modules/acl"
	asciinema "github.com/abysslink/abysslink/internal/modules/asciinema"
	atuin "github.com/abysslink/abysslink/internal/modules/atuin"
	"github.com/abysslink/abysslink/internal/modules/claudecode"
	"github.com/abysslink/abysslink/internal/modules/codeserver"
	"github.com/abysslink/abysslink/internal/modules/eternalterminal"
	"github.com/abysslink/abysslink/internal/modules/hardening"
	"github.com/abysslink/abysslink/internal/modules/lock"
	"github.com/abysslink/abysslink/internal/modules/mosh"
	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/modules/ntfy"
	"github.com/abysslink/abysslink/internal/modules/power"
	sandbox "github.com/abysslink/abysslink/internal/modules/sandbox"
	"github.com/abysslink/abysslink/internal/modules/ssh"
	syncthing "github.com/abysslink/abysslink/internal/modules/syncthing"
	tsmod "github.com/abysslink/abysslink/internal/modules/tailscale"
	"github.com/abysslink/abysslink/internal/modules/tmux"
	"github.com/abysslink/abysslink/internal/modules/ttyd"
	upsnap "github.com/abysslink/abysslink/internal/modules/upsnap"
	"github.com/abysslink/abysslink/internal/modules/watch"
	platformauto "github.com/abysslink/abysslink/internal/platform/auto"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/spf13/cobra"
)

// newRunner is the factory used by loadCmdContext to construct the shell runner.
// The default returns &shell.ExecRunner{}, which is byte-identical to the
// previous inline literal. Tests override this var to inject a MockRunner
// without changing production behavior.
var newRunner = func() shell.Runner { return &shell.ExecRunner{} }

// cmdContext holds shared state for a command invocation.
type cmdContext struct {
	cfg     *config.Config
	runner  shell.Runner
	dryRun  bool
	apply   bool
	yes     bool
	jsonOut bool
	verbose bool
	explain bool // gates per-action rationale rendering (--explain flag)
}

// backend constructs a backend.Client for this cmdContext. It is a convenience
// helper for CLI command files that do not receive a modules.Deps bundle.
func (cc *cmdContext) backend() (backend.Client, error) {
	return backend.New(cc.cfg, cc.runner)
}

// loadCmdContext loads config and resolves flags from the root command.
func loadCmdContext(cmd *cobra.Command) (*cmdContext, error) {
	configPath, _ := cmd.Flags().GetString("config")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	apply, _ := cmd.Flags().GetBool("apply")
	yes, _ := cmd.Flags().GetBool("yes")
	jsonOut, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")
	explain, _ := cmd.Flags().GetBool("explain")

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
		runner:  newRunner(),
		dryRun:  dryRun,
		apply:   apply,
		yes:     yes,
		jsonOut: jsonOut,
		verbose: verbose,
		explain: explain,
	}, nil
}

// newPrinter returns the appropriate Printer based on --json flag.
// It routes output through cmd.OutOrStdout() / cmd.ErrOrStderr() so that
// tests can capture command output by calling cmd.SetOut / cmd.SetErr.
func newPrinter(cmd *cobra.Command) Printer {
	jsonOut, _ := cmd.Flags().GetBool("json")
	if jsonOut {
		return NewJSONPrinterTo(cmd.OutOrStdout(), cmd.ErrOrStderr())
	}
	return NewHumanPrinterTo(cmd.OutOrStdout(), cmd.ErrOrStderr())
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
	b, err := backend.New(cc.cfg, cc.runner)
	if err != nil {
		return modules.Deps{}, fmt.Errorf("backend init: %w", err)
	}

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

	// Prefer the signed, hash-chained audit writer when a keychain is available;
	// fall back to the unsigned writer (backward compat) otherwise. Both satisfy
	// audit.AuditWriter so Deps.Audit accepts either without a type assertion.
	var auditWriter audit.AuditWriter
	if kc != nil {
		if sa, saErr := audit.NewSigned(logPath, kc); saErr == nil {
			auditWriter = sa
		} else {
			slog.Warn("signed audit unavailable; falling back to unsigned audit log", "err", saErr)
			auditWriter = audit.New(logPath)
		}
	} else {
		auditWriter = audit.New(logPath)
	}

	// Select the metrics sink: a live in-memory registry when observability
	// metrics are enabled, otherwise the nil-safe NoopRegistry. Modules always
	// call Registry methods unconditionally (never nil-check), so this field is
	// always populated.
	var reg metrics.Registry = metrics.NoopRegistry{}
	if cc.cfg.Observability.Metrics.Enabled {
		reg = metrics.NewMemRegistry()
	}

	return modules.Deps{
		Cfg:      cc.cfg,
		Runner:   cc.runner,
		Backend:  b,
		Platform: plat,
		Keychain: kc,
		Audit:    auditWriter,
		Registry: reg,
		// Prompt routes module prompts through the interactive gate + tui.Pause:
		// never raw stdout (which would corrupt --json) and never a bare stdin
		// read (which would block in non-TTY/CI/--json contexts). CR-01 / T-10-16.
		Prompt: func(ctx context.Context, msg string) error {
			if !interactive(cc.yes, cc.jsonOut) {
				return errMissingInput("yes")
			}
			return tui.Pause(ctx, msg, cc.yes)
		},
	}, nil
}

// allModules returns the core modules plus optional modules wired with the
// shared dependency bundle. Optional modules no-op when disabled in config, so
// they are always constructed; enabling one in abysslink.yaml is what activates
// it on the next `abysslink up`.
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
		// Optional modules (disabled by default; enable via `abysslink enable`).
		claudecode.New(deps),
		codeserver.New(deps),
		ttyd.New(deps),
		eternalterminal.New(deps),
		syncthing.New(deps),
		atuin.New(deps),
		upsnap.New(deps),
		sandbox.New(deps),
		asciinema.New(deps),
	}
}
