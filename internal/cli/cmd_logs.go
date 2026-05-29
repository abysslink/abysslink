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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the abysslink audit log, filtered by age and module",
		Example: `  # Show the full audit log
  abysslink logs

  # Show mutations from the last 24 hours
  abysslink logs --since 24h

  # Filter by module
  abysslink logs --module tailscale`,
		RunE: func(c *cobra.Command, _ []string) error {
			p := newPrinter(c)

			sinceStr, _ := c.Flags().GetString("since")
			since, err := time.ParseDuration(sinceStr)
			if err != nil {
				return fmt.Errorf("logs: invalid --since duration %q: %w", sinceStr, err)
			}
			cutoff := time.Now().Add(-since)
			moduleFilter, _ := c.Flags().GetString("module")
			jsonOut, _ := c.Flags().GetBool("json")

			auditPath := filepath.Join(xdgStateHome(), "abysslink", "audit.log")
			entries, err := audit.ReadLog(auditPath)
			if err != nil {
				return fmt.Errorf("logs: %w", err)
			}
			if len(entries) == 0 {
				printerInfo(p, fmt.Sprintf("No audit log entries at %s", auditPath))
				return nil
			}

			shown := 0
			for _, e := range entries {
				if e.Time.Before(cutoff) {
					continue
				}
				if moduleFilter != "" &&
					!strings.Contains(e.Op, moduleFilter) && !strings.Contains(e.Target, moduleFilter) {
					continue
				}
				shown++
				if jsonOut {
					line, _ := json.Marshal(e)
					printerInfo(p, string(line))
					continue
				}
				dry := ""
				if e.DryRun {
					dry = styleMuted.Render(" [dry-run]")
				}
				printerInfo(p, fmt.Sprintf("%s  %-14s %s%s",
					e.Time.Format(time.RFC3339), e.Op, e.Target, dry))
			}
			if shown == 0 {
				printerInfo(p, fmt.Sprintf("No entries in the last %s.", sinceStr))
			}
			return nil
		},
	}
	cmd.Flags().String("since", "24h", "Show entries newer than this duration (e.g. 1h, 24h)")
	cmd.Flags().String("module", "", "Only show entries whose op or target contains this string")
	return cmd
}

// xdgStateHome returns $XDG_STATE_HOME or ~/.local/state.
func xdgStateHome() string {
	if s := os.Getenv("XDG_STATE_HOME"); s != "" {
		return s
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state")
}
