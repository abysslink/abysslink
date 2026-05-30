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

// checkFileVault runs `fdesetup status` and fails closed if FileVault is off.
func checkFileVault(ctx context.Context, m *Module) ([]modules.Finding, error) {
	res, err := m.runner.Run(ctx, "fdesetup", "status")
	if err != nil {
		return nil, fmt.Errorf("run fdesetup: %w", err)
	}

	output := strings.TrimSpace(res.Stdout)
	slog.Debug("filevault status", "output", output)

	if strings.HasPrefix(output, "FileVault is Off") {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "filevault",
			Severity: modules.SeverityFatal,
			Message:  "FileVault is disabled — enable it in System Settings → Privacy & Security → FileVault",
		}}, nil
	}

	return nil, nil
}

// firewallJSON is the relevant subset of system_profiler SPFirewallDataType -json output.
type firewallJSON struct {
	SPFirewallDataType []struct {
		SpfwGlobalState string `json:"spfw_global_state"`
	} `json:"SPFirewallDataType"`
}

// checkFirewall checks the macOS Application Firewall state.
func checkFirewall(ctx context.Context, m *Module) ([]modules.Finding, error) {
	res, err := m.runner.Run(ctx, "system_profiler", "SPFirewallDataType", "-json")
	if err != nil {
		// system_profiler may not be available in CI; don't hard-fail.
		slog.Warn("hardening detect: system_profiler failed", "error", err)
		return nil, nil
	}

	if res.ExitCode != 0 {
		slog.Warn("hardening detect: system_profiler exited non-zero", "stderr", res.Stderr)
		return nil, nil
	}

	var fw firewallJSON
	if err := json.Unmarshal([]byte(res.Stdout), &fw); err != nil {
		slog.Warn("hardening detect: could not parse firewall JSON", "error", err)
		return nil, nil
	}

	slog.Debug("firewall state", "data", fw.SPFirewallDataType)

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

	return nil, nil
}
