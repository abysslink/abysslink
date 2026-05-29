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
	"bytes"
	"context"
	"fmt"
	"os"

	aclmod "github.com/abysslink/abysslink/internal/modules/acl"
	"github.com/abysslink/abysslink/internal/tailscale"
	"github.com/spf13/cobra"
)

func newACLCmd() *cobra.Command {
	acl := &cobra.Command{
		Use:   "acl",
		Short: "Manage the Tailscale ACL (pull, push, validate, diff)",
	}
	acl.AddCommand(newACLPullCmd(), newACLPushCmd(), newACLValidateCmd(), newACLDiffCmd())
	return acl
}

// adminClientFor builds an admin client from config + the env secret, reporting
// whether full credentials are present.
func adminClientFor(cc *cmdContext) (*tailscale.AdminClient, bool) {
	a := cc.cfg.Tailnet.Admin
	secret := os.Getenv(oauthSecretEnv)
	has := a.Tailnet != "" && a.OAuthClientID != "" && secret != ""
	return tailscale.NewAdminClient(a.Tailnet, a.OAuthClientID, secret), has
}

// requireAdmin loads context and returns a credentialed admin client, or an
// error directing the user to configure OAuth.
func requireAdmin(cmd *cobra.Command) (context.Context, *cmdContext, *tailscale.AdminClient, error) {
	ctx := cmd.Context()
	cc, err := loadCmdContext(cmd)
	if err != nil {
		return ctx, nil, nil, err
	}
	admin, has := adminClientFor(cc)
	if !has {
		return ctx, cc, nil, fmt.Errorf("no Tailscale admin OAuth client configured " +
			"(set tailnet.admin.* in abysslink.yaml and export " + oauthSecretEnv + "), " +
			"or manage the ACL at https://login.tailscale.com/admin/acls/file")
	}
	return ctx, cc, admin, nil
}

func newACLPullCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pull",
		Short: "Print the current tailnet ACL",
		Example: `  # Print the current tailnet ACL (requires admin credentials)
  abysslink acl pull`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, _, admin, err := requireAdmin(cmd)
			if err != nil {
				return err
			}
			cur, _, err := admin.GetACL(ctx)
			if err != nil {
				return fmt.Errorf("acl pull: %w", err)
			}
			printerInfo(newPrinter(cmd), string(cur))
			return nil
		},
	}
}

func newACLPushCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "push",
		Short: "Converge the tailnet ACL to abysslink's required policy",
		Example: `  # Preview ACL push (dry-run — no changes)
  abysslink acl push

  # Apply ACL changes to the tailnet
  abysslink acl push --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("acl push: %w", err)
			}
			if err := aclmod.New(deps).Apply(ctx); err != nil {
				return fmt.Errorf("acl push: %w", err)
			}
			printerInfo(newPrinter(cmd), "ACL converged.")
			return nil
		},
	}
}

func newACLValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Check the tailnet ACL is valid HuJSON and contains abysslink's rules",
		Example: `  # Validate the tailnet ACL against abysslink's required rules
  abysslink acl validate`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cc, admin, err := requireAdmin(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			cur, _, err := admin.GetACL(ctx)
			if err != nil {
				return fmt.Errorf("acl validate: %w", err)
			}
			editor, err := tailscale.NewACLEditor(cur)
			if err != nil {
				return fmt.Errorf("acl validate: ACL is not valid HuJSON: %w", err)
			}
			before := append([]byte(nil), editor.Bytes()...)
			if err := convergeACL(editor, cc); err != nil {
				return fmt.Errorf("acl validate: %w", err)
			}
			if !bytes.Equal(before, editor.Bytes()) {
				printerError(p, "ACL is valid HuJSON but MISSING abysslink's mobile→laptop grant or SSH rule. Run `abysslink acl push`.")
				return fmt.Errorf("acl validate: policy drift")
			}
			printerInfo(p, styleSuccess.Render("ACL is valid and contains abysslink's required rules."))
			return nil
		},
	}
}

func newACLDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff",
		Short: "Show the changes abysslink would make to the tailnet ACL",
		Example: `  # Show a diff of ACL changes abysslink would apply
  abysslink acl diff`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cc, admin, err := requireAdmin(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			cur, _, err := admin.GetACL(ctx)
			if err != nil {
				return fmt.Errorf("acl diff: %w", err)
			}
			editor, err := tailscale.NewACLEditor(cur)
			if err != nil {
				return fmt.Errorf("acl diff: %w", err)
			}
			before := append([]byte(nil), editor.Bytes()...)
			if err := convergeACL(editor, cc); err != nil {
				return fmt.Errorf("acl diff: %w", err)
			}
			diff := tailscale.Diff(before, editor.Bytes())
			if diff == "" {
				printerInfo(p, "No changes — ACL already converged.")
				return nil
			}
			printerInfo(p, diff)
			return nil
		},
	}
}

// convergeACL applies abysslink's required rules to editor using config identity.
func convergeACL(editor *tailscale.ACLEditor, cc *cmdContext) error {
	owner := cc.cfg.Identity.Email
	if owner == "" {
		return fmt.Errorf("identity.email is required")
	}
	user := cc.cfg.Identity.UnixUser
	if user == "" {
		user = os.Getenv("USER")
	}
	checkPeriod := cc.cfg.Mobile.SSHCheckPeriod
	if checkPeriod == "" {
		checkPeriod = "12h"
	}
	if err := editor.EnsureTagOwners(owner); err != nil {
		return err
	}
	if err := editor.EnsureGrant(); err != nil {
		return err
	}
	return editor.EnsureSSHRule(owner, user, checkPeriod)
}
