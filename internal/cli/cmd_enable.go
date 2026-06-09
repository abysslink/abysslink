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
		Short: "Enable an optional module in abysslink.yaml (dry-run by default)",
		Example: `  # Enable the Claude Code integration module
  abysslink enable claudecode --apply

  # Enable code-server (VS Code in browser)
  abysslink enable code-server --apply`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return toggleModule(cmd, args[0], true) },
	}
}

// toggleModule sets a module's enabled flag in abysslink.yaml and persists it.
// Dry-run is the default (CLI-02): without --apply it prints a [plan] preview
// and writes nothing. The user then runs `abysslink up --apply` to converge.
func toggleModule(cmd *cobra.Command, name string, enabled bool) error {
	p := newPrinter(cmd)
	_, apply, err := resolveApplyFlags(cmd)
	if err != nil {
		return err
	}
	path := resolveConfigPath(cmd)
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load config %s: %w (run `abysslink init` first)", path, err)
	}
	if err := setModuleEnabled(cfg, name, enabled); err != nil {
		return err
	}

	verb := "enable"
	pastVerb := "enabled"
	if !enabled {
		verb = "disable"
		pastVerb = "disabled"
	}

	if !apply {
		printerInfo(p, fmt.Sprintf("[plan] would %s module %q in %s", verb, name, path))
		printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to execute."))
		return nil
	}

	if err := config.Write(path, cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	printerInfo(p, fmt.Sprintf("Module %q %s in %s.", name, pastVerb, path))
	printerInfo(p, styleMuted.Render("Run `abysslink up --apply` to converge."))
	return nil
}

// setModuleEnabled flips the enabled flag for the named module, accepting common
// aliases. Returns an error for unknown module names.
func setModuleEnabled(cfg *config.Config, name string, v bool) error {
	// aliases maps canonical name → setter. Multi-word aliases share a setter via
	// the canonicalise step below.
	canonical := moduleCanonicalName(name)
	setters := map[string]func(bool){
		"claudecode":       func(b bool) { cfg.ClaudeCode.Enabled = b },
		"code-server":      func(b bool) { cfg.Modules.CodeServer.Enabled = b },
		"ttyd":             func(b bool) { cfg.Modules.Ttyd.Enabled = b },
		"eternal-terminal": func(b bool) { cfg.Modules.EternalTerminal.Enabled = b },
		"syncthing":        func(b bool) { cfg.Modules.Syncthing.Enabled = b },
		"upsnap":           func(b bool) { cfg.Modules.Upsnap.Enabled = b },
		"atuin":            func(b bool) { cfg.Modules.Atuin.Enabled = b },
		"sandbox":          func(b bool) { cfg.Modules.Sandbox.Enabled = b },
		"asciinema":        func(b bool) { cfg.Modules.Asciinema.Enabled = b },
		"ssh":              func(b bool) { cfg.Modules.SSH.Enabled = b },
		"tmux":             func(b bool) { cfg.Modules.Tmux.Enabled = b },
		"mosh":             func(b bool) { cfg.Modules.Mosh.Enabled = b },
		"ntfy":             func(b bool) { cfg.Modules.Ntfy.Enabled = b },
		"notify":           func(b bool) { cfg.Modules.Notify.Enabled = b },
		"watch":            func(b bool) { cfg.Modules.Watch.Enabled = b },
	}
	fn, ok := setters[canonical]
	if !ok {
		return fmt.Errorf("unknown module %q — known: claudecode, code-server, ttyd, eternal-terminal, syncthing, upsnap, atuin, sandbox, asciinema, ssh, tmux, mosh, ntfy, notify, watch", name)
	}
	fn(v)
	return nil
}

// moduleCanonicalName normalises common aliases to the canonical module name.
func moduleCanonicalName(name string) string {
	switch name {
	case "claude-code", "claudecode":
		return "claudecode"
	case "codeserver", "code_server":
		return "code-server"
	case "eternalterminal", "et", "eternal_terminal":
		return "eternal-terminal"
	default:
		return name
	}
}

// resolveConfigPath returns the --config path or the default XDG location.
func resolveConfigPath(cmd *cobra.Command) string {
	if path, _ := cmd.Flags().GetString("config"); path != "" {
		return path
	}
	return filepath.Join(abysslinkConfigDir(), "abysslink.yaml")
}
