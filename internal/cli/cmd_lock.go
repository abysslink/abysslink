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

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/spf13/cobra"
)

func newLockCmd() *cobra.Command {
	lock := &cobra.Command{
		Use:   "lock",
		Short: "Manage Tailnet Lock",
	}
	lock.AddCommand(newLockInitCmd(), newLockStatusCmd(), newLockSignCmd(), newLockRotateCmd())
	return lock
}

func newLockStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report Tailnet Lock status",
		Example: `  # Show whether Tailnet Lock is enabled
  abysslink lock status`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			b, err := cc.backend()
			if err != nil {
				return fmt.Errorf("lock status: %w", err)
			}
			lc, ok := b.(backend.Locker)
			if !ok {
				return fmt.Errorf("lock status: backend %q has no Tailnet Lock support", cc.cfg.Backend.Type)
			}
			st, err := lc.LockStatus(ctx)
			if err != nil {
				return fmt.Errorf("lock status: %w", err)
			}
			if st.Enabled {
				printerInfo(p, styleSuccess.Render("Tailnet Lock is ENABLED."))
			} else {
				printerInfo(p, styleWarn.Render("Tailnet Lock is NOT enabled."))
			}
			return nil
		},
	}
}

func newLockInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialise Tailnet Lock and print disablement secrets (dry-run by default)",
		Example: `  # Preview lock init (dry-run — no changes)
  abysslink lock init

  # Initialise Tailnet Lock and print the once-only disablement secrets
  abysslink lock init --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			b, err := cc.backend()
			if err != nil {
				return fmt.Errorf("lock init: %w", err)
			}
			lc, ok := b.(backend.Locker)
			if !ok {
				return fmt.Errorf("lock init: backend %q has no Tailnet Lock support", cc.cfg.Backend.Type)
			}

			if st, sErr := lc.LockStatus(ctx); sErr == nil && st.Enabled {
				printerInfo(p, styleSuccess.Render("Tailnet Lock is already enabled — nothing to do."))
				printerInfo(p, "")
				printerInfo(p, styleMuted.Render("To generate fresh disablement secrets, rotate instead:"))
				printerInfo(p, "  "+styleCode.Render("abysslink lock rotate"))
				return nil
			}

			n := cc.cfg.Tailnet.Lock.DisablementSecrets
			if n <= 0 {
				n = 2
			}

			if cc.dryRun {
				printerInfo(p, fmt.Sprintf("[plan] would run: tailscale lock init --gen-disablement=%d  (re-run with --apply)", n))
				return nil
			}

			// Animated liveness during key generation (network round-trip to the
			// control plane). spinWork is json-safe; the fail-closed empty-secret
			// check and SecretBox below are unchanged.
			var res *backend.LockInitResult
			if err := spinWork(ctx, p, "Initialising Tailnet Lock…", func(ctx context.Context) error {
				var e error
				res, e = lc.LockInit(ctx, n, cc.cfg.Tailnet.Lock.ShareWithSupport)
				return e
			}); err != nil {
				return fmt.Errorf("lock init: %w", err)
			}
			// Fail closed: never render an empty "shown ONCE" box or demand the
			// "I HAVE PRINTED IT" attestation when no secrets came back — that would
			// lock the user out with nothing recorded (WR-05).
			if len(res.DisablementSecrets) == 0 {
				return fmt.Errorf("lock init: tailscale returned no disablement secrets — Tailnet Lock state is uncertain; run `tailscale lock status` and do NOT assume you are protected")
			}

			// SECURITY: res.DisablementSecrets flows ONLY into tui.SecretBox→Printer.
			// It is NEVER passed to slog, deps.Audit, or any os.WriteFile call.
			// Violating this invariant would constitute a secret leak (T-10-14).
			printerInfo(p, "")
			renderSecretsToBox(p, res.DisablementSecrets)
			printerInfo(p, "")

			return attestSecretsStored(ctx, cc, p)
		},
	}
}

// renderSecretsToBox prints the disablement secrets as a once-only red SecretBox
// through the Printer. The secret slice MUST NOT be passed to slog, audit, or any
// file-write call — only this function is the sanctioned output path (T-10-14).
func renderSecretsToBox(p Printer, secrets []string) {
	box := tui.SecretBox("Tailnet Lock disablement secrets (shown ONCE — Tailnet Lock is now ENABLED)", secrets)
	printerInfo(p, box)
}

// attestSecretsStored requires the operator to type "I HAVE PRINTED IT" to
// confirm they have stored the disablement secrets. This replaces the plain y/N
// confirm with a typed-phrase gate (T-10-15: strengthens, never weakens, the gate).
// --yes bypasses with a loud slog.Warn; it does NOT print the success message.
// Non-interactive (no TTY, no --yes): returns the "not confirmed" error immediately
// to avoid hanging on a form that cannot receive input.
func attestSecretsStored(ctx context.Context, cc *cmdContext, p Printer) error {
	if cc.yes {
		slog.Warn("lock init: --yes set — skipped disablement-secret attestation (I HAVE PRINTED IT gate); ensure the secrets above are stored or you risk permanent lockout")
		return nil
	}
	// Non-interactive guard: do not attempt to open /dev/tty in CI/pipe contexts.
	if !interactive(cc.yes, cc.jsonOut) {
		printerError(p, "Tailnet Lock is enabled but you did NOT confirm storing the secrets — record them NOW to avoid lockout.")
		return fmt.Errorf("lock init: disablement secrets not confirmed stored")
	}
	ok, err := tui.ConfirmTyped(ctx,
		"Type I HAVE PRINTED IT to confirm you have stored these",
		"I HAVE PRINTED IT",
		cc.yes)
	if err != nil {
		return err
	}
	if !ok {
		printerError(p, "Tailnet Lock is enabled but you did NOT confirm storing the secrets — record them NOW to avoid lockout.")
		return fmt.Errorf("lock init: disablement secrets not confirmed stored")
	}
	printerInfo(p, styleSuccess.Render("Tailnet Lock initialised and secrets acknowledged."))
	return nil
}

func newLockSignCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sign <node-key>",
		Short: "Sign a node key into Tailnet Lock",
		Example: `  # Sign a node key into Tailnet Lock
  abysslink lock sign <node-key>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			b, err := cc.backend()
			if err != nil {
				return fmt.Errorf("lock sign: %w", err)
			}
			lc, ok := b.(backend.Locker)
			if !ok {
				return fmt.Errorf("lock sign: backend %q has no Tailnet Lock support", cc.cfg.Backend.Type)
			}
			if cc.dryRun {
				printerInfo(p, fmt.Sprintf("[plan] would run: tailscale lock sign %s  (re-run with --apply)", args[0]))
				return nil
			}
			if err := lc.LockSign(ctx, args[0]); err != nil {
				return fmt.Errorf("lock sign: %w", err)
			}
			printerInfo(p, styleSuccess.Render("Node key signed into Tailnet Lock."))
			return nil
		},
	}
}

func newLockRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Guidance for rotating Tailnet Lock disablement secrets",
		Example: `  # Show guidance for rotating Tailnet Lock disablement secrets
  abysslink lock rotate`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := newPrinter(cmd)
			printerInfo(p, "Rotating disablement secrets requires disabling and re-initialising Tailnet Lock:")
			printerInfo(p, "  1. Disable: tailscale lock disable <one-of-your-disablement-secrets>")
			printerInfo(p, "  2. Re-init: abysslink lock init --apply   (prints fresh secrets)")
			printerInfo(p, "")
			printerInfo(p, styleMuted.Render("This is intentionally manual — automating disablement-secret handling would mean storing them."))
			return nil
		},
	}
}
