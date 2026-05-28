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
	"path/filepath"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/spf13/cobra"
)

func newEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <module>",
		Short: "Enable an optional module in abysslink.yaml",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return toggleModule(cmd, args[0], true) },
	}
}

// toggleModule sets a module's enabled flag in abysslink.yaml and persists it.
// The user then runs `abysslink up --apply` to converge.
func toggleModule(cmd *cobra.Command, name string, enabled bool) error {
	p := newPrinter(cmd)
	path := resolveConfigPath(cmd)
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load config %s: %w (run `abysslink init` first)", path, err)
	}
	if err := setModuleEnabled(cfg, name, enabled); err != nil {
		return err
	}
	if err := config.Write(path, cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	verb := "enabled"
	if !enabled {
		verb = "disabled"
	}
	printerInfo(p, fmt.Sprintf("Module %q %s in %s.", name, verb, path))
	printerInfo(p, styleMuted.Render("Run `abysslink up --apply` to converge."))
	return nil
}

// setModuleEnabled flips the enabled flag for the named module, accepting common
// aliases. Returns an error for unknown module names.
func setModuleEnabled(cfg *config.Config, name string, v bool) error {
	switch name {
	case "claudecode", "claude-code":
		cfg.ClaudeCode.Enabled = v
	case "code-server", "codeserver", "code_server":
		cfg.Modules.CodeServer.Enabled = v
	case "ttyd":
		cfg.Modules.Ttyd.Enabled = v
	case "eternal-terminal", "eternalterminal", "et":
		cfg.Modules.EternalTerminal.Enabled = v
	case "syncthing":
		cfg.Modules.Syncthing.Enabled = v
	case "upsnap":
		cfg.Modules.Upsnap.Enabled = v
	case "atuin":
		cfg.Modules.Atuin.Enabled = v
	case "ssh":
		cfg.Modules.SSH.Enabled = v
	case "tmux":
		cfg.Modules.Tmux.Enabled = v
	case "mosh":
		cfg.Modules.Mosh.Enabled = v
	case "ntfy":
		cfg.Modules.Ntfy.Enabled = v
	case "notify":
		cfg.Modules.Notify.Enabled = v
	case "watch":
		cfg.Modules.Watch.Enabled = v
	default:
		return fmt.Errorf("unknown module %q (try: claudecode, code-server, ttyd, eternal-terminal, syncthing, upsnap, atuin)", name)
	}
	return nil
}

// resolveConfigPath returns the --config path or the default XDG location.
func resolveConfigPath(cmd *cobra.Command) string {
	if path, _ := cmd.Flags().GetString("config"); path != "" {
		return path
	}
	return filepath.Join(abysslinkConfigDir(), "abysslink.yaml")
}
