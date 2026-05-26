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
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	tslocal "github.com/abysslink/abysslink/internal/tailscale"
	"github.com/spf13/cobra"
)

// statusReport is the JSON-serialisable status summary.
type statusReport struct {
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			r := cc.runner
			tsClient := tslocal.NewLocalClient(r)

			// Gather Tailscale status — best-effort, never fatal.
			tsRunning := "not running"
			tsIP := ""
			hostname := ""

			st, tsErr := tsClient.Status(ctx)
			if tsErr == nil {
				if st.BackendState == tslocal.StateRunning {
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

			// Tailscale SSH — inferred from config.
			tsSSH := "disabled"
			if cc.cfg.Tailnet.SSH {
				tsSSH = "enabled"
			}

			// Tailnet Lock — inferred from config.
			lockStatus := "disabled"
			if cc.cfg.Tailnet.Lock.Enabled {
				lockStatus = "enabled"
			}

			// ntfy — quick port check via config.
			ntfyStatus := "disabled"
			if cc.cfg.Modules.Ntfy.Enabled {
				ntfyStatus = "enabled (check with: abysslink doctor)"
			}

			// Disk encryption — platform-specific.
			diskEncrypt := diskEncryptionStatus()

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

			p := newPrinter(cmd)

			if cc.jsonOut {
				data, _ := json.MarshalIndent(rep, "", "  ")
				printerInfo(p, string(data))
				return nil
			}

			// Human-readable box.
			printStatusBox(p, rep)
			return nil
		},
	}
}

// diskEncryptionStatus returns a human label for the disk encryption state.
func diskEncryptionStatus() string {
	switch runtime.GOOS {
	case "darwin":
		// On macOS check FileVault status via fdesetup.
		// We cannot call shell here (no runner), so report config intent.
		return "check: run abysslink doctor"
	case "linux":
		return "check: run abysslink doctor"
	default:
		return "unknown"
	}
}

// printStatusBox renders the one-screen status summary.
func printStatusBox(p Printer, rep statusReport) {
	icon := func(s string) string {
		if s == "running" || s == "enabled" || s == "encrypted" {
			return "●"
		}
		return "✕"
	}

	hostnameLabel := ""
	if rep.Hostname != "" || rep.TailscaleIP != "" {
		parts := []string{}
		if rep.Hostname != "" {
			parts = append(parts, rep.Hostname)
		}
		if rep.TailscaleIP != "" {
			parts = append(parts, rep.TailscaleIP)
		}
		hostnameLabel = " (" + strings.Join(parts, " / ") + ")"
	}

	row := func(label, ico, value string) string {
		return fmt.Sprintf("  %-16s  %s  %s", label, ico, value)
	}

	printerInfo(p, "┌─ Abysslink Status ──────────────────────────────┐")
	printerInfo(p, "│"+row("Tailscale", icon(rep.Tailscale), rep.Tailscale+hostnameLabel)+"")
	printerInfo(p, "│"+row("Tailscale SSH", icon(rep.TailscaleSSH), rep.TailscaleSSH)+"")
	printerInfo(p, "│"+row("Tailnet Lock", icon(rep.TailnetLock), rep.TailnetLock)+"")
	printerInfo(p, "│"+row("ntfy", icon(rep.Ntfy), rep.Ntfy)+"")
	printerInfo(p, "│"+row("Disk Encryption", icon(rep.DiskEncrypt), rep.DiskEncrypt)+"")
	printerInfo(p, "│"+fmt.Sprintf("  %-16s     %s", "Timestamp", rep.Timestamp)+"")
	printerInfo(p, "└─────────────────────────────────────────────────┘")
}
