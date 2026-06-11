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

//go:build darwin

package hardening

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/abysslink/abysslink/internal/modules"
)

// detectPlatform runs macOS-specific hardening checks.
func detectPlatform(ctx context.Context, m *Module) ([]modules.Finding, error) {
	var findings []modules.Finding

	// FileVault check.
	fvFindings, err := checkFileVault(ctx, m)
	if err != nil {
		return findings, fmt.Errorf("hardening detect: filevault: %w", err)
	}
	findings = append(findings, fvFindings...)

	// Application Firewall check.
	fwFindings, err := checkFirewall(ctx, m)
	if err != nil {
		return findings, fmt.Errorf("hardening detect: firewall: %w", err)
	}
	findings = append(findings, fwFindings...)

	return findings, nil
}

// checkFileVault runs `fdesetup status` and fails closed if FileVault is off,
// in-progress, deferred, or decrypting (DOC-02 / D-06).
//
// Stable UNKNOWN marker: "disk-encryption state is UNKNOWN" — used by Plan 04's
// up gate to refuse --force-unsafe for unknown-state FATALs (D-05).
//
// NOTE (Assumption A3): The in-progress/deferred substrings are cross-verified
// against the fdesetup(8) man page and Apple deployment guide at MEDIUM
// confidence. Exact wording should be confirmed on a real Mac.
func checkFileVault(ctx context.Context, m *Module) ([]modules.Finding, error) {
	res, err := m.runner.Run(ctx, "fdesetup", "status")
	if err != nil {
		// DOC-02 / D-06: exec error → disk-encryption state is UNKNOWN → FATAL.
		// Convert error return to FATAL finding so the up gate can block (D-05).
		slog.Warn("hardening detect: fdesetup failed", "error", err)
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "filevault",
			Severity: modules.SeverityFatal,
			Message: "disk-encryption state is UNKNOWN: fdesetup is unavailable or failed to run — " +
				"verify FileVault status manually in System Settings → Privacy & Security → FileVault",
		}}, nil
	}

	if !res.Ok() {
		// DOC-02: non-zero exit → state unknown → fail closed (mirrors the
		// lsblk treatment on Linux). Never parse error output as state.
		slog.Warn("hardening detect: fdesetup exited non-zero", "exit_code", res.ExitCode, "stderr", res.Stderr)
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "filevault",
			Severity: modules.SeverityFatal,
			Message: "disk-encryption state is UNKNOWN: fdesetup exited with a non-zero status — " +
				"verify FileVault status manually in System Settings → Privacy & Security → FileVault",
		}}, nil
	}

	output := strings.TrimSpace(res.Stdout)
	slog.Debug("filevault status", "output", output)

	// Known-off: FileVault explicitly disabled.
	if strings.HasPrefix(output, "FileVault is Off") {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "filevault",
			Severity: modules.SeverityFatal,
			Message:  "FileVault is disabled — enable it in System Settings → Privacy & Security → FileVault",
		}}, nil
	}

	// DOC-02: Not-fully-enabled states — FATAL (fail-closed).
	// These strings are per fdesetup(8) man page (MEDIUM confidence, see NOTE above).
	notFullyEnabled := []struct {
		substr  string
		msgSufx string
	}{
		{"Encryption in progress", "encryption is in progress (not yet fully enabled) — wait for encryption to complete before enabling remote access"},
		{"Deferred enablement appears to be active", "deferred enablement is pending (not yet fully enabled) — complete FileVault setup at next login before enabling remote access"},
		{"Decryption in progress", "decryption is in progress (FileVault is being disabled) — re-enable FileVault before enabling remote access"},
	}
	for _, s := range notFullyEnabled {
		if strings.Contains(output, s.substr) {
			return []modules.Finding{{
				Module:   m.Name(),
				Check:    "filevault",
				Severity: modules.SeverityFatal,
				Message:  "FileVault is not fully enabled: " + s.msgSufx,
			}}, nil
		}
	}

	// DOC-01 backfill: only "FileVault is On" is fully enabled → SeverityOK.
	// Emitted here (not in detectPlatform) to avoid Detect+Verify double-emission.
	if strings.HasPrefix(output, "FileVault is On") {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "filevault",
			Severity: modules.SeverityOK,
			Message:  "FileVault full-disk encryption is enabled",
		}}, nil
	}

	// Unknown fdesetup output (not any recognised string) → fail closed.
	return []modules.Finding{{
		Module:   m.Name(),
		Check:    "filevault",
		Severity: modules.SeverityFatal,
		Message: "disk-encryption state is UNKNOWN: fdesetup returned an unrecognised status (" + output + ") — " +
			"verify FileVault status manually in System Settings → Privacy & Security → FileVault",
	}}, nil
}

// firewallJSON is the relevant subset of system_profiler SPFirewallDataType -json output.
type firewallJSON struct {
	SPFirewallDataType []struct {
		SpfwGlobalState string `json:"spfw_global_state"`
	} `json:"SPFirewallDataType"`
}

// checkFirewall checks the macOS Application Firewall state.
//
// Probe failures (exec error, non-zero exit, unparseable JSON) are NOT silent:
// they emit an explicit UNKNOWN finding so "check could not run" is
// distinguishable from "check ran and passed" — consistent with the filevault
// tri-state treatment in this file (review INFO). The firewall is advisory
// (abysslink never auto-enables it), so UNKNOWN is a WARNING, not FATAL.
func checkFirewall(ctx context.Context, m *Module) ([]modules.Finding, error) {
	unknown := func(reason string) []modules.Finding {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "firewall",
			Severity: modules.SeverityWarning,
			Message: "Application Firewall state is UNKNOWN: " + reason + " — " +
				"verify it manually in System Settings → Network → Firewall",
		}}
	}

	res, err := m.runner.Run(ctx, "system_profiler", "SPFirewallDataType", "-json")
	if err != nil {
		// system_profiler may not be available in CI; don't hard-fail, but say so.
		slog.Warn("hardening detect: system_profiler failed", "error", err)
		return unknown("system_profiler is unavailable or failed to run"), nil
	}

	if !res.Ok() {
		slog.Warn("hardening detect: system_profiler exited non-zero", "stderr", res.Stderr)
		return unknown("system_profiler exited with a non-zero status"), nil
	}

	var fw firewallJSON
	if err := json.Unmarshal([]byte(res.Stdout), &fw); err != nil {
		slog.Warn("hardening detect: could not parse firewall JSON", "error", err)
		return unknown("system_profiler returned unparseable JSON"), nil
	}

	slog.Debug("firewall state", "data", fw.SPFirewallDataType)

	if len(fw.SPFirewallDataType) == 0 {
		return unknown("system_profiler reported no firewall data"), nil
	}

	for _, entry := range fw.SPFirewallDataType {
		state := strings.ToLower(entry.SpfwGlobalState)
		// Enabled values seen in the wild: "enabled", "on", "1".
		if state == "" || state == "disabled" || state == "off" || state == "0" {
			return []modules.Finding{{
				Module:   m.Name(),
				Check:    "firewall",
				Severity: modules.SeverityWarning,
				Message:  "Application Firewall is disabled — abysslink does NOT auto-enable it; turn it on in System Settings → Network → Firewall, or run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
			}}, nil
		}
	}

	// DOC-01: explicit OK so "ran and passed" is visible in the tri-state.
	return []modules.Finding{{
		Module:   m.Name(),
		Check:    "firewall",
		Severity: modules.SeverityOK,
		Message:  "Application Firewall is enabled",
	}}, nil
}
