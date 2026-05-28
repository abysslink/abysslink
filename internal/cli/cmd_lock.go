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

	"github.com/abysslink/abysslink/internal/tailscale"
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			st, err := tailscale.NewLockClient(cc.runner).Status(ctx)
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			lc := tailscale.NewLockClient(cc.runner)

			if st, sErr := lc.Status(ctx); sErr == nil && st.Enabled {
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

			res, err := lc.Init(ctx, n, cc.cfg.Tailnet.Lock.ShareWithSupport)
			if err != nil {
				return fmt.Errorf("lock init: %w", err)
			}

			// Print the disablement secrets ONCE. Abysslink never stores them.
			printerInfo(p, "")
			printerInfo(p, styleWarn.Render("Tailnet Lock is now ENABLED. Disablement secrets (shown ONCE):"))
			printerInfo(p, "")
			for i, s := range res.DisablementSecrets {
				printerInfo(p, fmt.Sprintf("    %d. %s", i+1, styleBold.Render(s)))
			}
			printerInfo(p, "")
			printerInfo(p, styleMuted.Render("Abysslink does NOT store these. Paste them into your password manager"))
			printerInfo(p, styleMuted.Render("AND print at least one on paper. Losing all of them can permanently lock you out."))
			printerInfo(p, "")

			return attestSecretsStored(ctx, cc, p)
		},
	}
}

// attestSecretsStored requires the operator to confirm they recorded the
// disablement secrets, unless --yes was passed (with a loud warning).
func attestSecretsStored(ctx context.Context, cc *cmdContext, p Printer) error {
	if cc.yes {
		slog.Warn("lock init: --yes set — skipped disablement-secret attestation; ensure the secrets above are stored or you risk permanent lockout")
		return nil
	}
	ok, err := confirmAction(ctx, cc, "Have you stored AND paper-printed the disablement secrets above?")
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			if cc.dryRun {
				printerInfo(p, fmt.Sprintf("[plan] would run: tailscale lock sign %s  (re-run with --apply)", args[0]))
				return nil
			}
			if err := tailscale.NewLockClient(cc.runner).Sign(ctx, args[0]); err != nil {
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
