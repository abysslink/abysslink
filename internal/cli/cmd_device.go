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
	"sort"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/device"
	"github.com/spf13/cobra"
)

// deviceStaleWindow is the inactivity window after which an active device is
// flagged stale in `device ls` and `status` (DEVC-04).
const deviceStaleWindow = 7 * 24 * time.Hour

// devicePhoneName is the canonical device name `enroll phone` mints
// credentials for (DEVC-01/DEVC-02).
const devicePhoneName = "phone"

// deviceStorePath resolves the devices.json location. A package var so tests
// can point the store at a temp dir (same seam pattern as newRunner).
var deviceStorePath = device.DefaultPath //nolint:gochecknoglobals // test seam, mirrors newRunner

// deviceStoreReadOnly returns a Store suitable for read-only use (List, Get,
// Stale). It carries no audit writer and no keychain: those are only touched
// by mutations (Enroll/Rotate/Revoke*) and by CA access, which read-only
// callers never perform.
func deviceStoreReadOnly() (*device.Store, error) {
	path, err := deviceStorePath()
	if err != nil {
		return nil, fmt.Errorf("device store: %w", err)
	}
	return device.New(path, nil, nil, nil), nil
}

// deviceStoreForWrite returns a Store wired with the audited file writer and
// the OS keychain via buildDeps. Mutations on this store route through
// internal/audit (backup + audit entry + atomic write — CLAUDE.md hard rule).
// needKeychain guards operations that touch the device SSH CA (Enroll, Rotate,
// CAPublicKey); Revoke/RevokeAll never need it.
func deviceStoreForWrite(ctx context.Context, cc *cmdContext, needKeychain bool) (*device.Store, error) {
	deps, err := buildDeps(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("device store: %w", err)
	}
	if needKeychain && deps.Keychain == nil {
		return nil, fmt.Errorf("device store: no OS keychain backend available — the device SSH CA key lives in the keychain (on Linux install secret-tool or pass)")
	}
	path, err := deviceStorePath()
	if err != nil {
		return nil, fmt.Errorf("device store: %w", err)
	}
	return device.New(path, deps.Audit, deps.Keychain, nil), nil
}

func newDeviceCmd() *cobra.Command {
	d := &cobra.Command{
		Use:   "device",
		Short: "Manage enrolled remote devices (phone credentials)",
	}
	d.AddCommand(newDeviceLsCmd(), newDeviceRevokeCmd(), newDeviceCACmd())
	return d
}

func newDeviceLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List enrolled devices and their credential state",
		Example: `  # Human-readable device table
  abysslink device ls

  # Machine-readable JSON array
  abysslink --json device ls`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			st, err := deviceStoreReadOnly()
			if err != nil {
				return err
			}
			return deviceLS(p, cc.jsonOut, st)
		},
	}
}

func newDeviceRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke one enrolled device's credentials (dry-run by default)",
		Example: `  # Preview what revoking would do (default: dry-run)
  abysslink device revoke phone

  # Revoke for real: bearer, push token, and SSH cert all invalidated
  abysslink device revoke phone --apply`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)

			// Dry-run never mutates, so the read-only store is enough; the
			// audited write store is only built when --apply was passed.
			var st *device.Store
			if cc.apply {
				st, err = deviceStoreForWrite(ctx, cc, false)
			} else {
				st, err = deviceStoreReadOnly()
			}
			if err != nil {
				return err
			}
			return deviceRevoke(ctx, p, st, args[0], cc.apply, cc.jsonOut)
		},
	}
}

func newDeviceCACmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ca",
		Short: "Print the device SSH CA public key (for sshd TrustedUserCAKeys)",
		Long: `Prints the device SSH certificate authority public key as a single
authorized_keys-format line. Wire it into sshd with:

  TrustedUserCAKeys /etc/ssh/abysslink_device_ca.pub

The key line goes to stdout (pipe-friendly); guidance goes to stderr.
On first ever use the CA keypair is created in the OS keychain.`,
		Example: `  # Print the CA public key line
  abysslink device ca

  # Install it for sshd
  abysslink device ca > /etc/ssh/abysslink_device_ca.pub`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			st, err := deviceStoreForWrite(ctx, cc, true)
			if err != nil {
				return err
			}
			return deviceCA(ctx, p, st, cc.jsonOut)
		},
	}
}

// deviceListRow is one `device ls` row; also the --json array element.
type deviceListRow struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	EnrolledAt  string `json:"enrolled_at"`
	RotatedAt   string `json:"rotated_at,omitempty"`
	CertExpires string `json:"cert_expires,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
	Stale       bool   `json:"stale"`
	Revoked     bool   `json:"revoked"`
}

// deviceLS renders the device table (or --json array). Stale is computed by
// the store over the 7-day inactivity window (DEVC-04).
func deviceLS(p Printer, jsonOut bool, st *device.Store) error {
	recs := st.List()
	staleIDs := make(map[string]bool)
	for _, r := range st.Stale(deviceStaleWindow) {
		staleIDs[r.ID] = true
	}

	rows := make([]deviceListRow, 0, len(recs))
	for _, r := range recs {
		row := deviceListRow{
			Name:        r.Name,
			Kind:        r.Kind,
			EnrolledAt:  r.EnrolledAt.UTC().Format("2006-01-02"),
			CertExpires: r.CertNotAfter.UTC().Format("2006-01-02"),
			Stale:       staleIDs[r.ID],
			Revoked:     r.Revoked,
		}
		if !r.RotatedAt.IsZero() {
			row.RotatedAt = r.RotatedAt.UTC().Format("2006-01-02")
		}
		if !r.LastSeen.IsZero() {
			row.LastSeen = r.LastSeen.UTC().Format(time.RFC3339)
		}
		rows = append(rows, row)
	}

	if jsonOut {
		p.PrintJSON(rows) // stable []: empty list encodes as [], never null
		return nil
	}
	if len(rows) == 0 {
		printerInfo(p, "No devices enrolled — run "+styleCode.Render("abysslink enroll phone --apply")+" to enroll one.")
		return nil
	}

	printerInfo(p, styleBold.Render("Devices")+"\n")
	header := fmt.Sprintf("  %-12s %-7s %-11s %-11s %-13s %-21s %-6s %s",
		"NAME", "KIND", "ENROLLED", "ROTATED", "CERT EXPIRES", "LAST SEEN", "STALE", "REVOKED")
	printerInfo(p, styleMuted.Render(header))
	for _, row := range rows {
		printerInfo(p, fmt.Sprintf("  %-12s %-7s %-11s %-11s %-13s %-21s %-6s %s",
			truncCell(row.Name, 12), row.Kind, row.EnrolledAt,
			orDash(row.RotatedAt), row.CertExpires, orNever(row.LastSeen),
			yesOrDash(row.Stale), yesOrDash(row.Revoked)))
	}
	printerInfo(p, "")
	return nil
}

// orDash maps "" to "-" for table cells.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// orNever maps an empty last-seen cell to "never".
func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

// yesOrDash maps a boolean flag to a "yes"/"-" table cell.
func yesOrDash(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}

// deviceRevoke implements `device revoke <name>` (DEVC-01: individually
// revocable). Without apply it previews; an unknown name is a clear error
// listing the known device names.
func deviceRevoke(ctx context.Context, p Printer, st *device.Store, name string, apply, jsonOut bool) error {
	rec, ok := st.Get(name)
	if !ok {
		names := deviceNames(st)
		if len(names) == 0 {
			return fmt.Errorf("device revoke: unknown device %q — no devices are enrolled (run `abysslink enroll phone --apply`)", name)
		}
		return fmt.Errorf("device revoke: unknown device %q — known devices: %s", name, strings.Join(names, ", "))
	}

	if !apply {
		if rec.Revoked {
			printerInfo(p, fmt.Sprintf("[plan] device %q is already revoked — nothing to do", name))
		} else {
			printerInfo(p, fmt.Sprintf("[plan] would revoke device %q (kind=%s): bearer and push token invalidated, SSH certificate serial %d added to the revocation list",
				name, rec.Kind, rec.SSHCertSerial))
		}
		printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
		return nil
	}

	if err := st.Revoke(ctx, name); err != nil {
		return fmt.Errorf("device revoke: %w", err)
	}
	if jsonOut {
		p.PrintJSON(map[string]any{"revoked": name})
		return nil
	}
	if rec.Revoked {
		printerInfo(p, fmt.Sprintf("Device %q was already revoked — nothing changed.", name))
		return nil
	}
	printerInfo(p, fmt.Sprintf("Revoked device %q — its bearer, push token, and SSH certificate are no longer accepted.", name))
	return nil
}

// deviceNames returns the sorted unique names of every record in the store,
// for the unknown-name error message.
func deviceNames(st *device.Store) []string {
	seen := make(map[string]bool)
	var names []string
	for _, r := range st.List() {
		if !seen[r.Name] {
			seen[r.Name] = true
			names = append(names, r.Name)
		}
	}
	sort.Strings(names)
	return names
}

// deviceCA prints the device SSH CA public key as one authorized_keys line.
// Human mode keeps the key line on stdout (pipe-friendly) and the sshd wiring
// hint on stderr.
func deviceCA(ctx context.Context, p Printer, st *device.Store, jsonOut bool) error {
	line, err := st.CAPublicKey(ctx)
	if err != nil {
		return fmt.Errorf("device ca: %w", err)
	}
	if jsonOut {
		p.PrintJSON(map[string]string{"ca_public_key": line})
		return nil
	}
	printerInfo(p, line)
	printerError(p, styleMuted.Render("Wire into sshd: save the line above to /etc/ssh/abysslink_device_ca.pub and set"))
	printerError(p, styleMuted.Render("  TrustedUserCAKeys /etc/ssh/abysslink_device_ca.pub"))
	return nil
}
