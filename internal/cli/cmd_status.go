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

	"github.com/abysslink/abysslink/internal/shell"
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

			p := newPrinter(cmd)

			if cc.jsonOut {
				data, _ := json.MarshalIndent(rep, "", "  ")
				printerInfo(p, string(data))
				return nil
			}

			printStatusPanel(p, rep)
			return nil
		},
	}
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
	sb.WriteString(styleBold.Render("Abysslink Status") + "\n\n")
	sb.WriteString(statusRow("Tailscale", hostnameLabel, isOK(rep.Tailscale)) + "\n")
	sb.WriteString(statusRow("Tailscale SSH", rep.TailscaleSSH, isOK(rep.TailscaleSSH)) + "\n")
	sb.WriteString(statusRow("Tailnet Lock", rep.TailnetLock, isOK(rep.TailnetLock)) + "\n")
	sb.WriteString(statusRow("ntfy", rep.Ntfy, isOK(rep.Ntfy)) + "\n")
	sb.WriteString(statusRow("Disk Encryption", rep.DiskEncrypt, isOK(rep.DiskEncrypt)) + "\n")
	sb.WriteString("\n" + styleMuted.Render(rep.Timestamp))

	printerInfo(p, styleStatusBox.Render(strings.TrimRight(sb.String(), "\n")))
	printerInfo(p, "")
}
