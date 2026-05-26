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
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Interactive bootstrap — generates abysslink.yaml for this machine",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := newPrinter(cmd)

			var (
				email      string
				hostname   string
				enableSSH  bool
				enableTmux bool
				enableMosh bool
				enableNtfy bool
			)

			// Pre-populate hostname from OS.
			hostname, _ = os.Hostname()
			// Default modules to true.
			enableSSH = true
			enableTmux = true
			enableMosh = true
			enableNtfy = true

			yes, _ := cmd.Flags().GetBool("yes")

			if !yes {
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewInput().
							Title("Tailscale account email").
							Description("The email you signed into Tailscale with").
							Value(&email).
							Validate(func(s string) error {
								if !strings.Contains(s, "@") {
									return fmt.Errorf("must be a valid email address")
								}
								return nil
							}),
						huh.NewInput().
							Title("Rig hostname").
							Description("This machine's Tailscale hostname").
							Value(&hostname),
					),
					huh.NewGroup(
						huh.NewConfirm().
							Title("Enable Tailscale SSH?").
							Description("Disables macOS Remote Login and uses Tailscale SSH instead").
							Value(&enableSSH),
						huh.NewConfirm().
							Title("Enable tmux?").
							Description("Install tmux and configure persistent session").
							Value(&enableTmux),
						huh.NewConfirm().
							Title("Enable mosh?").
							Description("Install mosh for roaming connections").
							Value(&enableMosh),
						huh.NewConfirm().
							Title("Enable ntfy notifications?").
							Description("Install ntfy server for phone notifications").
							Value(&enableNtfy),
					),
				)

				if err := form.Run(); err != nil {
					return fmt.Errorf("init: %w", err)
				}
			}

			// Build config from answered questions.
			cfg := config.Defaults()
			cfg.Identity.Email = email
			cfg.Tailnet.Hostname = hostname
			cfg.Tailnet.SSH = enableSSH
			cfg.Modules.SSH.Enabled = enableSSH
			cfg.Modules.SSH.Mode = "tailscale"
			cfg.Modules.Tmux.Enabled = enableTmux
			cfg.Modules.Mosh.Enabled = enableMosh
			cfg.Modules.Ntfy.Enabled = enableNtfy
			cfg.Modules.Notify.Enabled = enableNtfy

			configPath, _ := cmd.Flags().GetString("config")
			if err := config.Write(configPath, cfg); err != nil {
				return fmt.Errorf("init: write config: %w", err)
			}

			printerInfo(p, fmt.Sprintf("Config written to %s", configPath))
			printerInfo(p, "Next step: abysslink up --apply")
			return nil
		},
	}
}
