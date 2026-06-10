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

package asciinema

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// asciinemaConfig sets api_url to empty to disable cloud uploads by default.
const asciinemaConfig = `[api]
; url =
; Uploads are disabled by default. Set url = https://asciinema.org to enable,
; or point to a self-hosted instance.
`

// Module implements the optional Asciinema terminal-recording module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	plat   platform.Platform
	audit  audit.AuditWriter
	// Prompt is the non-suppressible credential-warning gate, wired from
	// modules.Deps.Prompt (CLI layer → tui.Pause). It may be nil when the module
	// is constructed without a CLI Prompt (tests, non-interactive contexts). Any
	// recording path that depends on the warning MUST fail closed when Prompt is
	// nil — never silently skip the warning (HARD FLOOR, T-21-02-01).
	Prompt func(ctx context.Context, msg string) error
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, plat: d.Platform, audit: d.Audit, Prompt: d.Prompt}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "asciinema" }

// Deps returns this module's dependencies.
func (m *Module) Deps() []string { return nil }

// Detect checks whether asciinema is installed and the config is safe.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.Asciinema.Enabled {
		slog.Debug("asciinema module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	res, err := m.runner.Run(ctx, "asciinema", "--version")
	if err != nil || res.ExitCode != 0 {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "installed",
			Severity: modules.SeverityWarning,
			Message:  "asciinema not found — install via package manager or https://asciinema.org/docs/installation",
		})
		return findings, nil
	}
	slog.Debug("asciinema version", "output", strings.TrimSpace(res.Stdout+res.Stderr))

	// Check config for an ACTIVE cloud upload URL. The line-based helper skips
	// comment lines — a naive substring match would flag the module's own
	// default config (whose comments mention the asciinema.org URL) and any
	// commented-out url, making Detect/Apply non-convergent.
	cfgPath := asciinemaConfigPath()
	data, err := os.ReadFile(cfgPath) //nolint:gosec // G304: cfgPath is the module config path resolved internally, not user input
	if err == nil {
		if hasActiveCloudUploadURL(string(data)) {
			findings = append(findings, modules.Finding{
				Module:   m.Name(),
				Check:    "no_cloud_upload",
				Severity: modules.SeverityWarning,
				Message:  "asciinema is configured to upload recordings to asciinema.org — consider a self-hosted instance or disable uploads",
			})
		}
	}

	return findings, nil
}

// hasActiveCloudUploadURL reports whether content has an uncommented
// `url = …asciinema.org…` line. Comment lines (`;` or `#`) never count.
func hasActiveCloudUploadURL(content string) bool {
	for _, raw := range strings.Split(content, "\n") {
		if isActiveCloudUploadLine(raw) {
			return true
		}
	}
	return false
}

// isActiveCloudUploadLine reports whether a single config line actively points
// uploads at asciinema.org.
func isActiveCloudUploadLine(raw string) bool {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
		return false
	}
	if !strings.HasPrefix(line, "url") {
		return false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "url"))
	if !strings.HasPrefix(rest, "=") {
		return false
	}
	return strings.Contains(rest, "asciinema.org")
}

// disableCloudUploadURL comments out every active asciinema.org url line so
// uploads are disabled while the rest of the user's config is preserved.
func disableCloudUploadURL(content string) string {
	lines := strings.Split(content, "\n")
	for i, raw := range lines {
		if isActiveCloudUploadLine(raw) {
			lines[i] = "; url =  ; cloud upload disabled by abysslink (was: " + strings.TrimSpace(raw) + ")"
		}
	}
	return strings.Join(lines, "\n")
}

// Plan computes the actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Asciinema.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		switch f.Check {
		case "installed":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "install asciinema",
				Reversible:  false,
			})
		case "no_cloud_upload":
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "configure asciinema to disable cloud uploads",
				Reversible:  true,
			})
		}
	}

	if len(actions) == 0 {
		actions = append(actions, modules.Action{
			Module:      m.Name(),
			Description: "write asciinema config (cloud uploads disabled by default)",
			Reversible:  true,
		})
	}

	return actions, nil
}

// Apply installs asciinema and writes a privacy-safe config.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.Modules.Asciinema.Enabled {
		return nil
	}

	if res, err := m.runner.Run(ctx, "asciinema", "--version"); err != nil || res.ExitCode != 0 {
		slog.Info("asciinema apply: installing asciinema")
		if err := m.plat.InstallPackage(ctx, "asciinema"); err != nil {
			return fmt.Errorf("asciinema apply: install: %w", err)
		}
	}

	cfgPath := asciinemaConfigPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("asciinema apply: mkdir config dir: %w", err)
	}

	if m.audit == nil {
		return fmt.Errorf("asciinema apply: audit not available")
	}

	data, err := os.ReadFile(cfgPath) //nolint:gosec // G304: cfgPath is the module config path resolved internally, not user input
	switch {
	case os.IsNotExist(err):
		if err := m.audit.WriteFile(cfgPath, []byte(asciinemaConfig), 0o600, false); err != nil {
			return fmt.Errorf("asciinema apply: write config: %w", err)
		}
		slog.Info("asciinema apply: wrote privacy config (cloud uploads disabled)", "path", cfgPath)
	case err != nil:
		return fmt.Errorf("asciinema apply: read config: %w", err)
	case hasActiveCloudUploadURL(string(data)):
		// Plan promises "configure asciinema to disable cloud uploads" — honor
		// it on an EXISTING config too (W6): comment the active url line(s)
		// out under audit instead of leaving the finding unremediated forever.
		patched := disableCloudUploadURL(string(data))
		if err := m.audit.WriteFile(cfgPath, []byte(patched), 0o600, false); err != nil {
			return fmt.Errorf("asciinema apply: disable cloud upload: %w", err)
		}
		slog.Info("asciinema apply: disabled cloud upload URL in existing config", "path", cfgPath)
	default:
		slog.Debug("asciinema apply: config already privacy-safe, not touching", "path", cfgPath)
	}

	return nil
}

// Verify is a no-op for the asciinema module — all checks run in Detect.
// Pitfall 4 (Doctor double-emission): do NOT call Detect here — runner.Doctor
// calls both Detect and Verify, so re-running Detect would double-emit every
// Detect finding per doctor pass (W4/NET-18). Verify adds no new information
// beyond Detect; returning nil avoids the duplication (mirrors ssh/ntfy).
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair re-runs Apply.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}

// asciinemaConfigPath returns the OS-specific asciinema config path.
func asciinemaConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "asciinema", "config")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "asciinema", "config")
}
