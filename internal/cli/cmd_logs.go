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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Tail or filter the abysslink audit log",
		RunE: func(c *cobra.Command, _ []string) error {
			p := newPrinter(c)

			sinceStr, _ := c.Flags().GetString("since")
			since, err := time.ParseDuration(sinceStr)
			if err != nil {
				return fmt.Errorf("logs: invalid --since duration %q: %w", sinceStr, err)
			}
			cutoff := time.Now().Add(-since)

			auditPath := filepath.Join(xdgStateHome(), "abysslink", "audit.log")
			f, err := os.Open(auditPath) //nolint:gosec // path is computed from XDG env
			if err != nil {
				if os.IsNotExist(err) {
					printerInfo(p, fmt.Sprintf("No audit log found at %s", auditPath))
					return nil
				}
				return fmt.Errorf("logs: open audit log: %w", err)
			}
			defer func() { _ = f.Close() }()

			_ = cutoff // future: filter lines by parsed timestamp

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				printerInfo(p, scanner.Text())
			}
			return scanner.Err()
		},
	}
	cmd.Flags().String("since", "24h", "Show logs since duration (e.g. 1h, 24h, 7d)")
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
