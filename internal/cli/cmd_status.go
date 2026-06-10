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
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// statusReport is the JSON-serialisable status summary.
// RigName is populated only on fleet fan-out results (rig_name field, FLEET-02).
type statusReport struct {
	RigName      string `json:"rig_name,omitempty"` // populated by --all-rigs fan-out
	Tailscale    string `json:"tailscale"`
	TailscaleIP  string `json:"tailscale_ip,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	TailscaleSSH string `json:"tailscale_ssh"`
	TailnetLock  string `json:"tailnet_lock"`
	Ntfy         string `json:"ntfy"`
	DiskEncrypt  string `json:"disk_encrypt"`
	Timestamp    string `json:"timestamp"`
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "One-screen health summary of the Tailscale setup",
		Example: `  # Human-readable dashboard
  abysslink status

  # Machine-readable JSON object (ANSI-free)
  abysslink --json status`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			// Read persistent fan-out flags (registered in Plan 03 / root.go).
			strict, _ := cmd.Flags().GetBool("strict")

			// --rig X (single rig) / --all-rigs (every enrolled rig) fan-out
			// branch: aggregate per-rig results (CLI-05).
			rt, rigErr := resolveRigTargets(cmd, cc.cfg.Rigs)
			if rigErr != nil {
				return rigErr
			}
			if rt.fanOut && len(rt.rigs) > 0 {
				return statusRigs(ctx, cc, p, strict, rt.rigs)
			}

			r := cc.runner
			b, bErr := cc.backend()
			if bErr != nil {
				return fmt.Errorf("status: %w", bErr)
			}

			tsRunning := "not running"
			tsIP := ""
			hostname := ""

			st, tsErr := b.Status(ctx)
			if tsErr == nil {
				if st.BackendState == backend.StateRunning {
					tsRunning = "running"
				} else {
					tsRunning = strings.ToLower(string(st.BackendState))
				}
				if st.Self != nil {
					hostname = st.Self.HostName
					if len(st.Self.TailscaleIPs) > 0 {
						tsIP = st.Self.TailscaleIPs[0].String()
					}
				}
			}

			tsSSH := "disabled"
			if cc.cfg.Tailnet.SSH {
				tsSSH = "enabled"
			}

			lockStatus := "disabled"
			if cc.cfg.Tailnet.Lock.Enabled {
				lockStatus = "enabled"
			}

			ntfyStatus := "disabled"
			if cc.cfg.Modules.Ntfy.Enabled {
				ntfyStatus = "enabled"
			}

			diskEncrypt := diskEncryptionStatus(ctx, r)

			rep := statusReport{
				Tailscale:    tsRunning,
				TailscaleIP:  tsIP,
				Hostname:     hostname,
				TailscaleSSH: tsSSH,
				TailnetLock:  lockStatus,
				Ntfy:         ntfyStatus,
				DiskEncrypt:  diskEncrypt,
				Timestamp:    time.Now().Format("2006-01-02 15:04"),
			}

			if cc.jsonOut {
				// Emit a typed, ANSI-free record via PrintJSON (T-10-18).
				p.PrintJSON(rep)
				return nil
			}

			printStatusPanel(p, rep)
			return nil
		},
	}
}

// statusAllRigs fans out `abysslink status --json` to every enrolled rig and
// aggregates the results into a per-rig slice. Offline rigs appear as UNREACHABLE
// rows (SC-2); --strict maps to exit 1 when any rig is offline (T-14-21).
func statusAllRigs(ctx context.Context, cc *cmdContext, p Printer, strict bool) error {
	return statusRigs(ctx, cc, p, strict, cc.cfg.Rigs)
}

// statusRigs fans out `abysslink status --json` to the targeted rigs only
// (every enrolled rig under --all-rigs, a single rig under --rig, CLI-05).
func statusRigs(ctx context.Context, cc *cmdContext, p Printer, strict bool, rigs []config.RigConfig) error {
	const perRigTimeout = 10 * time.Second

	results, fanErr := fleet.FanOut(ctx, cc.runner, rigs, perRigTimeout, strict, []string{"status", "--json"})

	var aggregate []statusReport
	for _, r := range results {
		if !r.Reachable {
			// UNREACHABLE is a result value, not a fatal error (SC-2 / FLEET-02).
			aggregate = append(aggregate, statusReport{
				RigName:   r.Rig.Name,
				Tailscale: "UNREACHABLE",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}
		var rep statusReport
		if err := json.Unmarshal([]byte(r.Stdout), &rep); err != nil {
			// Degraded-but-reachable: surface with a DEGRADED marker so the user
			// knows the rig responded but its output could not be decoded.
			aggregate = append(aggregate, statusReport{
				RigName:   r.Rig.Name,
				Tailscale: "DEGRADED",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}
		rep.RigName = r.Rig.Name
		aggregate = append(aggregate, rep)
	}

	if cc.jsonOut {
		// ANSI-free JSON array (UX-04).
		p.PrintJSON(aggregate)
	} else {
		printStatusAllRigsTable(p, aggregate)
	}

	// Fan-out error is non-nil only under --strict (one or more rigs unreachable).
	if fanErr != nil {
		return &exitError{code: exitCodeFatal}
	}
	return nil
}

// printStatusAllRigsTable renders a human-readable table of per-rig status rows.
func printStatusAllRigsTable(p Printer, rows []statusReport) {
	printerInfo(p, styleBold.Render("Fleet Status")+"\n")
	header := fmt.Sprintf("  %-20s %-14s %-12s %-10s", "RIG", "TAILSCALE", "DISK", "NTFY")
	printerInfo(p, styleMuted.Render(header))
	for _, r := range rows {
		disk := r.DiskEncrypt
		if disk == "" {
			disk = "-"
		}
		ntfy := r.Ntfy
		if ntfy == "" {
			ntfy = "-"
		}
		printerInfo(p, fmt.Sprintf("  %-20s %-14s %-12s %-10s", r.RigName, r.Tailscale, disk, ntfy))
	}
	printerInfo(p, "")
}

// luksDevice is a minimal lsblk JSON device entry used by diskEncryptionStatus.
type luksDevice struct {
	Type     string       `json:"type"`
	Children []luksDevice `json:"children"`
}

// hasLUKSType recursively checks whether any device in the tree has type "crypt".
func hasLUKSType(devs []luksDevice) bool {
	for _, d := range devs {
		if strings.EqualFold(d.Type, "crypt") {
			return true
		}
		if hasLUKSType(d.Children) {
			return true
		}
	}
	return false
}

// diskEncryptionStatus queries the OS for actual disk encryption state.
// Returns "encrypted", "unencrypted", or "unknown".
func diskEncryptionStatus(ctx context.Context, r shell.Runner) string {
	switch runtime.GOOS {
	case "darwin":
		res, err := r.Run(ctx, "fdesetup", "status")
		if err != nil || res.ExitCode != 0 {
			return "unknown"
		}
		if strings.HasPrefix(strings.TrimSpace(res.Stdout), "FileVault is On") {
			return "encrypted"
		}
		return "unencrypted"
	case "linux":
		// Use -J -o NAME,TYPE (no MOUNTPOINT) to match platform/linux and avoid
		// false positives from device names or mount paths containing "crypt".
		res, err := r.Run(ctx, "lsblk", "-J", "-o", "NAME,TYPE")
		if err != nil || res.ExitCode != 0 {
			return "unknown"
		}
		var out struct {
			Blockdevices []luksDevice `json:"blockdevices"`
		}
		if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
			return "unknown"
		}
		if hasLUKSType(out.Blockdevices) {
			return "encrypted"
		}
		return "unencrypted"
	default:
		return "unknown"
	}
}

// statusRow renders one row of the status panel.
func statusRow(label, value string, ok bool) string {
	var icon string
	if ok {
		icon = iconOKStr()
	} else {
		icon = iconFatalStr()
	}
	lbl := styleMuted.Render(fmt.Sprintf("%-18s", label))
	return fmt.Sprintf("  %s  %s  %s", icon, lbl, styleBold.Render(value))
}

// printStatusPanel renders the styled status box.
func printStatusPanel(p Printer, rep statusReport) {
	isOK := func(s string) bool {
		return s == "running" || s == "enabled" || s == "encrypted"
	}

	hostnameLabel := rep.Tailscale
	if rep.Hostname != "" || rep.TailscaleIP != "" {
		parts := []string{}
		if rep.Hostname != "" {
			parts = append(parts, rep.Hostname)
		}
		if rep.TailscaleIP != "" {
			parts = append(parts, styleMuted.Render(rep.TailscaleIP))
		}
		hostnameLabel += "  " + styleMuted.Render("("+strings.Join(parts, " · ")+")")
	}

	var sb strings.Builder
	sb.WriteString(styleBold.Render("Abysslink Status"))
	sb.WriteString("\n\n")
	for _, row := range []string{
		statusRow("Tailscale", hostnameLabel, isOK(rep.Tailscale)),
		statusRow("Tailscale SSH", rep.TailscaleSSH, isOK(rep.TailscaleSSH)),
		statusRow("Tailnet Lock", rep.TailnetLock, isOK(rep.TailnetLock)),
		statusRow("ntfy", rep.Ntfy, isOK(rep.Ntfy)),
		statusRow("Disk Encryption", rep.DiskEncrypt, isOK(rep.DiskEncrypt)),
	} {
		sb.WriteString(row)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(styleMuted.Render(rep.Timestamp))

	printerInfo(p, styleStatusBox.Render(strings.TrimRight(sb.String(), "\n")))
	printerInfo(p, "")
}
