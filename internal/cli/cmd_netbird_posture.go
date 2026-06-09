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

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/spf13/cobra"
)

// newNetBirdCmd returns the top-level "netbird" command group exposing posture
// check management and audit event tailing against a configured NetBird control
// server. These read/manage the NetBird Admin API via the existing REST client
// (no new HTTP client; D-05). The API key is read from ABYSSLINK_NB_API_KEY —
// never on argv (T-21-04-01).
func newNetBirdCmd() *cobra.Command {
	nb := &cobra.Command{
		Use:   "netbird",
		Short: "Manage NetBird posture checks and tail audit events",
	}
	nb.AddCommand(
		newNetBirdPostureCmd(),
		newNetBirdEventsCmd(),
	)
	return nb
}

// newNetBirdPostureCmd returns the "netbird posture" sub-group with list, create,
// and delete subcommands operating on /api/posture-checks.
func newNetBirdPostureCmd() *cobra.Command {
	posture := &cobra.Command{
		Use:   "posture",
		Short: "List, create, and delete NetBird posture checks",
	}
	posture.AddCommand(
		newNetBirdPostureListCmd(),
		newNetBirdPostureCreateCmd(),
		newNetBirdPostureDeleteCmd(),
	)
	return posture
}

func newNetBirdPostureListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all NetBird posture checks",
		Example: `  abysslink netbird posture list
  abysslink --json netbird posture list`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			return netbirdPostureListRunE(cmd.Context(), cc, newPrinter(cmd))
		},
	}
}

// netbirdPostureListRunE fetches and prints all posture checks.
func netbirdPostureListRunE(ctx context.Context, cc *cmdContext, p Printer) error {
	checks, err := backend.NetBirdListPostureChecks(ctx, cc.cfg)
	if err != nil {
		return fmt.Errorf("netbird posture list: %w", err)
	}

	if cc.jsonOut {
		p.PrintJSON(checks)
		return nil
	}

	if len(checks) == 0 {
		printerInfo(p, "No posture checks configured.")
		return nil
	}
	printerInfo(p, styleBold.Render("NetBird posture checks"))
	for _, c := range checks {
		printerInfo(p, fmt.Sprintf("  %s  %s  %s", c.ID, c.Name, c.Description))
	}
	return nil
}

func newNetBirdPostureCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a NetBird posture check (dry-run by default)",
		Example: `  # Preview (dry-run — no changes)
  abysslink netbird posture create --name min-os --description "Require minimum OS version"

  # Create on the control plane
  abysslink netbird posture create --name min-os --description "Require minimum OS version" --apply
  abysslink netbird posture create --name nb-ver --checks '{"nb_version_check":{"min_version":"0.57.0"}}' --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			name, _ := cmd.Flags().GetString("name")
			description, _ := cmd.Flags().GetString("description")
			checks, _ := cmd.Flags().GetString("checks")
			return netbirdPostureCreateRunE(cmd.Context(), cc, newPrinter(cmd), name, description, checks)
		},
	}
	cmd.Flags().String("name", "", "posture check name (required)")
	cmd.Flags().String("description", "", "posture check description")
	cmd.Flags().String("checks", "", "raw JSON for the posture-check 'checks' object (validated server-side)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

// netbirdPostureCreateRunE creates a posture check and prints the result.
// The --checks value is passed verbatim as raw JSON (validated server-side;
// no shell interpolation — discrete argv per T-21-04-03).
// CLI-08: creating a posture check mutates the remote NetBird control plane —
// dry-run is the default; without --apply a [plan] preview is printed and no
// request is sent.
func netbirdPostureCreateRunE(ctx context.Context, cc *cmdContext, p Printer, name, description, checksJSON string) error {
	if name == "" {
		return fmt.Errorf("netbird posture create: --name is required")
	}
	if !cc.apply {
		if cc.jsonOut {
			p.PrintJSON(map[string]string{"plan": "create posture check", "name": name, "description": description})
			return nil
		}
		printerInfo(p, fmt.Sprintf("[plan] would create NetBird posture check %q on the control plane", name))
		printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
		return nil
	}
	created, err := backend.NetBirdCreatePostureCheck(ctx, cc.cfg, name, description, []byte(checksJSON))
	if err != nil {
		return fmt.Errorf("netbird posture create: %w", err)
	}

	if cc.jsonOut {
		p.PrintJSON(created)
		return nil
	}
	printerInfo(p, styleSuccess.Render(fmt.Sprintf("  ✓  Created posture check %s (%s)", created.ID, created.Name)))
	return nil
}

func newNetBirdPostureDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a NetBird posture check by ID (dry-run by default)",
		Args:  cobra.ExactArgs(1),
		Example: `  # Preview (dry-run — no changes)
  abysslink netbird posture delete pc-abc123

  # Delete on the control plane
  abysslink netbird posture delete pc-abc123 --apply`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			return netbirdPostureDeleteRunE(cmd.Context(), cc, newPrinter(cmd), args[0])
		},
	}
}

// netbirdPostureDeleteRunE deletes a posture check by ID and prints confirmation.
// CLI-08: deleting a posture check mutates the remote NetBird control plane —
// dry-run is the default; without --apply a [plan] preview is printed and no
// request is sent.
func netbirdPostureDeleteRunE(ctx context.Context, cc *cmdContext, p Printer, id string) error {
	if !cc.apply {
		if cc.jsonOut {
			p.PrintJSON(map[string]string{"plan": "delete posture check", "id": id})
			return nil
		}
		printerInfo(p, "[plan] would delete NetBird posture check "+id+" from the control plane")
		printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
		return nil
	}
	if err := backend.NetBirdDeletePostureCheck(ctx, cc.cfg, id); err != nil {
		return fmt.Errorf("netbird posture delete: %w", err)
	}

	if cc.jsonOut {
		p.PrintJSON(map[string]string{"deleted": id})
		return nil
	}
	printerInfo(p, styleSuccess.Render("  ✓  Deleted posture check "+id))
	return nil
}
