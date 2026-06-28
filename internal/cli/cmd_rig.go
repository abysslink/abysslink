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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// safeImportHostname matches hostnames that are safe SSH target tokens (mirrors
// fleet.safeHostname — defined here to keep cmd_rig.go independent of
// fleet internals; both must stay in sync with T-14-04).
var safeImportHostname = regexp.MustCompile(`^[a-z0-9][a-z0-9\-.]{0,252}[a-z0-9]$`)

// rigLsRecord is the JSON-serializable representation of a single rig in `rig ls`.
// Field names are snake_case to match the config schema (UX-04 ANSI-free JSON).
type rigLsRecord struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Backend  string `json:"backend"`
	LastSeen string `json:"last_seen,omitempty"`
}

// rigExportWrapper is the YAML wrapper used by `rig export` and `rig import`.
// Only the rigs: key is emitted — no secrets, no full config (D-FS-02).
type rigExportWrapper struct {
	Rigs []config.RigConfig `yaml:"rigs"`
}

// newRigCmd returns the `rig` command group with ls / export / import subcommands.
func newRigCmd() *cobra.Command {
	rig := &cobra.Command{
		Use:   "rig",
		Short: "Manage enrolled rigs in the fleet",
	}
	rig.AddCommand(
		newRigLsCmd(),
		newRigExportCmd(),
		newRigImportCmd(),
	)
	return rig
}

// newRigLsCmd returns the `rig ls` subcommand.
func newRigLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List enrolled rigs (human table or --json array)",
		Example: `  abysslink rig ls
  abysslink --json rig ls`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			// CLI-12: honor --config like the sibling export/import subcommands.
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = defaultConfigPath()
			}
			return runRigLs(cfgPath, cc.jsonOut, cmd.OutOrStdout())
		},
	}
}

// newRigExportCmd returns the `rig export` subcommand.
func newRigExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export the rigs: section of config to stdout (no secrets)",
		Example: `  abysslink rig export > rigs.yaml
  abysslink rig export | ssh other-machine abysslink rig import -`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = defaultConfigPath()
			}
			return runRigExport(cfgPath, cmd.OutOrStdout())
		},
	}
}

// newRigImportCmd returns the `rig import <file>` subcommand. "-" reads the
// rigs: YAML doc from stdin (CLI-26 — matches the `rig export | rig import -`
// pipeline in the export help text).
func newRigImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Merge a rigs: YAML doc into local config (--dry-run by default, --apply to write; \"-\" reads stdin)",
		Example: `  # Preview the merge
  abysslink rig import rigs.yaml

  # Apply the merge
  abysslink rig import rigs.yaml --apply

  # Read the rigs doc from stdin
  abysslink rig export | abysslink rig import - --apply`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = defaultConfigPath()
			}
			return runRigImport(cfgPath, args[0], cc.apply, cc.jsonOut, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
}

// runRigLs loads cfg.Rigs and renders them as a human table or --json array.
// jsonOut selects the format; out receives the output.
func runRigLs(cfgPath string, jsonOut bool, out io.Writer) error {
	// WR-07: `rig ls` is read-only (it only renders cfg.Rigs, never feeds a value
	// to argv or a mutation), so it must not hard-fail on a validation error in an
	// unrelated stanza now that config.Load fails closed. A missing config
	// degrades to defaults (empty rig list); a validation error is logged but the
	// parsed rigs are still listed.
	cfg, err := config.LoadForRead(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = config.Defaults()
		} else if cfg != nil {
			slog.Warn("rig ls: config has a validation error; listing rigs anyway (read-only)", "err", err)
		} else {
			return fmt.Errorf("rig ls: load config: %w", err)
		}
	}

	records := make([]rigLsRecord, 0, len(cfg.Rigs))
	for _, r := range cfg.Rigs {
		records = append(records, rigLsRecord{
			Name:     r.Name,
			Hostname: r.Hostname,
			Backend:  r.Backend,
			LastSeen: r.LastSeen,
		})
	}

	if jsonOut {
		// Emit a typed, ANSI-free JSON array (UX-04).
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(records)
	}

	// Human table: name / hostname / backend / last-seen.
	if len(records) == 0 {
		_, _ = fmt.Fprintln(out, styleMuted.Render("No rigs enrolled. Use `abysslink enroll rig <name> --apply` to add one."))
		return nil
	}

	// Header.
	hdr := fmt.Sprintf("  %-20s %-30s %-12s %-25s", "NAME", "HOSTNAME", "BACKEND", "LAST SEEN")
	_, _ = fmt.Fprintln(out, styleBold.Render(hdr))
	_, _ = fmt.Fprintln(out, styleMuted.Render("  "+repeatStr("─", 87)))

	for _, r := range records {
		lastSeen := r.LastSeen
		if lastSeen == "" {
			lastSeen = styleMuted.Render("never")
		}
		row := fmt.Sprintf("  %-20s %-30s %-12s %-25s",
			r.Name, r.Hostname, r.Backend, lastSeen)
		_, _ = fmt.Fprintln(out, row)
	}
	return nil
}

// runRigExport marshals cfg.Rigs as YAML (rigs: section only) to out.
// Secrets stay in the keychain (D-FS-02) — nothing secret is emitted.
func runRigExport(cfgPath string, out io.Writer) error {
	// WR-07: `rig export` is read-only (emits only cfg.Rigs as YAML, no secrets,
	// no argv), so it degrades rather than hard-failing on a validation error in
	// an unrelated stanza. A missing config exports an empty rigs list.
	cfg, err := config.LoadForRead(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = config.Defaults()
		} else if cfg != nil {
			slog.Warn("rig export: config has a validation error; exporting rigs anyway (read-only)", "err", err)
		} else {
			return fmt.Errorf("rig export: load config: %w", err)
		}
	}

	wrapper := rigExportWrapper{Rigs: cfg.Rigs}
	data, err := yaml.Marshal(&wrapper)
	if err != nil {
		return fmt.Errorf("rig export: marshal: %w", err)
	}

	_, err = out.Write(data)
	return err
}

// runRigImport reads a rigs: YAML doc from importPath, merges into cfg.Rigs with
// name-collision, hostname-charset, and ntfy-topic-uniqueness checks, and (under
// apply=true) persists via config.Write (audit).
//
// Security invariants enforced at import time:
//   - rig.Name: validated against rigNameRe (mirrors enrollRig, T-14-11).
//   - rig.Hostname: validated against safeImportHostname (T-14-04 argv injection).
//   - rig.NtfyTopic: checked for collision against existing topics (SC-1, D-NI-02).
//   - Name collision: duplicate names rejected (mirrors enrollRigWriteConfig, CR-02).
//
// validateImportRigs enforces name + hostname + ntfy-topic invariants on an
// import batch before any config mutation (CR-01/CR-02, SC-1, T-14-04, D-NI-02).
func validateImportRigs(existing, incoming []config.RigConfig) error {
	existingNames := make(map[string]bool, len(existing))
	existingTopics := make(map[string]string, len(existing)) // topic → rig name
	for _, r := range existing {
		existingNames[r.Name] = true
		if r.NtfyTopic != "" {
			existingTopics[r.NtfyTopic] = r.Name
		}
	}
	for _, inc := range incoming {
		// CLI-13: imported rig names must satisfy the same charset/length rule as
		// enrollRig (rigNameRe, T-14-11) — the name is used as a keychain service
		// suffix, ntfy topic component, and SSH host token.
		if !rigNameRe.MatchString(inc.Name) {
			return fmt.Errorf("rig import: invalid rig name %q (must match ^[a-z0-9-]{1,63}$, T-14-11)", inc.Name)
		}
		if existingNames[inc.Name] {
			return fmt.Errorf("rig import: name collision for rig %q — use a unique name or remove the existing entry first (D-NI-02)", inc.Name)
		}
		// Record the incoming name so an in-file duplicate (two rigs with the
		// same name inside one import batch) is rejected too (CR-02 — the exact
		// duplicate condition import validation exists to prevent).
		existingNames[inc.Name] = true
		if !safeImportHostname.MatchString(inc.Hostname) {
			return fmt.Errorf("rig import: invalid hostname %q for rig %q: must be a valid DNS name (no spaces or shell metacharacters)", inc.Hostname, inc.Name)
		}
		if inc.NtfyTopic != "" {
			if owner, ok := existingTopics[inc.NtfyTopic]; ok {
				return fmt.Errorf("rig import: ntfy topic %q already used by rig %q — each rig must have a unique topic (SC-1, D-NI-02)", inc.NtfyTopic, owner)
			}
			existingTopics[inc.NtfyTopic] = inc.Name
		}
	}
	return nil
}

func runRigImport(cfgPath, importPath string, apply, jsonOut bool, in io.Reader, out io.Writer) error {
	// Read import file. "-" reads from in (stdin in production — CLI-26).
	var data []byte
	var err error
	if importPath == "-" {
		if in == nil {
			return fmt.Errorf("rig import: no stdin available for \"-\"")
		}
		data, err = io.ReadAll(in)
		if err != nil {
			return fmt.Errorf("rig import: read stdin: %w", err)
		}
	} else {
		data, err = os.ReadFile(importPath) //nolint:gosec // G304: importPath is an operator-supplied rig export file; read is intentional and the path is the documented CLI argument
		if err != nil {
			return fmt.Errorf("rig import: read %s: %w", importPath, err)
		}
	}

	// Unmarshal with strict KnownFields (T-14-12: crafted import file guard).
	var incoming rigExportWrapper
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&incoming); err != nil {
		return fmt.Errorf("rig import: parse %s: %w", importPath, err)
	}

	// Load current config. rig import MUTATES config and validates the merged
	// result before writing, so it keeps the fail-closed config.Load — a config
	// that already fails validation must not be silently rewritten. WR-07: a
	// MISSING config, however, degrades to defaults (matches loadCmdContext) so a
	// fresh install can import its first rig.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = config.Defaults()
		} else {
			return fmt.Errorf("rig import: load config: %w", err)
		}
	}

	// Validate each incoming rig before mutating state.
	if err := validateImportRigs(cfg.Rigs, incoming.Rigs); err != nil {
		return err
	}

	const keysNote = "HMAC signing keys are not imported — run `abysslink enroll rig <name> --apply` on this machine for each rig that should sign."

	if !apply {
		// Dry-run: report what would be imported. Under --json emit one typed,
		// ANSI-free record so the plan is machine-parseable instead of prose lines
		// dribbled into the JSON stream (UX-04, matching runRigLs).
		if jsonOut {
			return json.NewEncoder(out).Encode(rigImportResult{
				Action: "dry-run",
				Rigs:   rigImportSummaries(incoming.Rigs),
				Count:  len(incoming.Rigs),
			})
		}
		for _, r := range incoming.Rigs {
			_, _ = fmt.Fprintf(out, "[dry-run] Would import rig %q (hostname=%s, backend=%s)\n", r.Name, r.Hostname, r.Backend)
		}
		return nil
	}

	// Merge.
	cfg.Rigs = append(cfg.Rigs, incoming.Rigs...)

	// Persist via config.Write (audit) — never os.WriteFile (CLAUDE.md).
	if err := config.Write(cfgPath, cfg); err != nil {
		return fmt.Errorf("rig import: write config: %w", err)
	}

	// Confirmation on success (apply must not be silent — UX parity with the
	// dry-run per-rig preview). Signing keys are NOT imported: FanOut needs a
	// keychain entry per rig, so point at enroll for that half.
	if jsonOut {
		return json.NewEncoder(out).Encode(rigImportResult{
			Action: "imported",
			Rigs:   rigImportSummaries(incoming.Rigs),
			Count:  len(incoming.Rigs),
			Note:   keysNote,
		})
	}
	for _, r := range incoming.Rigs {
		_, _ = fmt.Fprintf(out, "Imported rig %q (hostname=%s, backend=%s)\n", r.Name, r.Hostname, r.Backend)
	}
	_, _ = fmt.Fprintf(out, "Imported %d rig(s). Note: %s\n", len(incoming.Rigs), keysNote)

	return nil
}

// rigImportResult is the typed --json record emitted by `rig import`.
type rigImportResult struct {
	Action string             `json:"action"` // "dry-run" | "imported"
	Rigs   []rigImportSummary `json:"rigs"`
	Count  int                `json:"count"`
	Note   string             `json:"note,omitempty"`
}

// rigImportSummary is the per-rig record in a rigImportResult.
type rigImportSummary struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Backend  string `json:"backend"`
}

// rigImportSummaries maps config rigs to their import summaries.
func rigImportSummaries(rigs []config.RigConfig) []rigImportSummary {
	out := make([]rigImportSummary, 0, len(rigs))
	for _, r := range rigs {
		out = append(out, rigImportSummary{Name: r.Name, Hostname: r.Hostname, Backend: r.Backend})
	}
	return out
}

// repeatStr returns s repeated n times.
func repeatStr(s string, n int) string {
	result := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		result = append(result, s...)
	}
	return string(result)
}
