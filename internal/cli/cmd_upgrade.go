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
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade abysslink to the latest release",
		RunE: func(c *cobra.Command, _ []string) error {
			if os.Getuid() == 0 {
				return fmt.Errorf("upgrade: refusing to run as root — run as your normal user")
			}

			checkOnly, _ := c.Flags().GetBool("check")
			p := newPrinter(c)

			printerInfo(p, "Checking for updates...")

			updateURL := os.Getenv("ABYSSLINK_UPDATE_URL")
			if updateURL == "" {
				printerInfo(p, "No update check endpoint configured. Set ABYSSLINK_UPDATE_URL.")
				if !checkOnly {
					return fmt.Errorf("upgrade: not yet implemented — download from https://github.com/abysslink/abysslink/releases")
				}
				return nil
			}

			// TODO: implement actual update check and cosign signature verification.
			if checkOnly {
				printerInfo(p, fmt.Sprintf("Update endpoint: %s (check-only, not downloading)", updateURL))
				return nil
			}

			return fmt.Errorf("upgrade: auto-update not yet implemented — download from https://github.com/abysslink/abysslink/releases")
		},
	}
	cmd.Flags().Bool("check", false, "Only check for a newer version, do not upgrade")
	return cmd
}
