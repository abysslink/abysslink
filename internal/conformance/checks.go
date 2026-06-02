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

// Package conformance implements compile-time and runtime security audit checks
// for the abysslink binary and its artifacts. These checks are exercised by the
// abysslink-conformance command and by the `make security-audit` target.
package conformance

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// secretPatterns are regexes that, if matched in the audit log, indicate a
// secret has leaked. Each pattern matches a key-name followed by a value that
// looks like a secret (long hex/alphanumeric string or any non-empty value).
var secretPatterns = []*regexp.Regexp{
	// "secret": <hex or base64, >20 chars>
	regexp.MustCompile(`(?i)"?secret"?\s*[=:]\s*["']?[a-fA-F0-9+/]{20,}`),
	// "token": <alphanumeric, >20 chars>
	regexp.MustCompile(`(?i)"?token"?\s*[=:]\s*["']?[a-zA-Z0-9+/_-]{20,}`),
	// "password": <anything non-empty>
	regexp.MustCompile(`(?i)"?password"?\s*[=:]\s*["']?.{3,}`),
	// "api_key" or "apikey": <anything non-empty>
	regexp.MustCompile(`(?i)"?api[_-]?key"?\s*[=:]\s*["']?.{8,}`),
}

// telemetryPackages are import paths whose presence in .go source files
// indicates unauthorized telemetry / analytics usage.
var telemetryPackages = []string{
	"github.com/DataDog",
	"github.com/getsentry",
	"go.opentelemetry.io",
	"github.com/newrelic",
	"github.com/honeycombio",
	"gopkg.in/segmentio",
	"github.com/segmentio",
	"github.com/amplitude",
	"github.com/mixpanel",
	"github.com/posthog",
}

// CheckNoSecretsInAuditLog scans the audit log at auditLogPath for patterns
// that look like leaked secrets. Returns an error describing the first match.
// Returns nil if the file does not exist (no audit log yet = no secrets).
func CheckNoSecretsInAuditLog(_ context.Context, auditLogPath string) error {
	f, err := os.Open(auditLogPath) //nolint:gosec // G304: auditLogPath is the internal audit-log path under test, not user input
	if os.IsNotExist(err) {
		// No audit log yet; nothing to check.
		return nil
	}
	if err != nil {
		return fmt.Errorf("conformance: open audit log %s: %w", auditLogPath, err)
	}
	defer f.Close() //nolint:errcheck // errcheck: close error on read-only/append file handle is non-actionable; data durability handled by explicit Sync where required

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, pat := range secretPatterns {
			if pat.MatchString(line) {
				return fmt.Errorf("conformance: possible secret in audit log at line %d (matched %s): %q",
					lineNum, pat.String(), truncate(line, 120))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("conformance: scan audit log: %w", err)
	}
	return nil
}

// CheckBinarySize verifies that the abysslink binary at binPath is under
// maxBytes. Returns an error if the binary exceeds the limit or cannot be stat'd.
func CheckBinarySize(_ context.Context, binPath string, maxBytes int64) error {
	info, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("conformance: stat binary %s: %w", binPath, err)
	}
	size := info.Size()
	if size > maxBytes {
		const mb = 1 << 20
		return fmt.Errorf("conformance: binary %s is %.1f MB, exceeds %.0f MB limit",
			binPath, float64(size)/mb, float64(maxBytes)/mb)
	}
	return nil
}

// CheckNoTelemetry scans all .go files under repoRoot for imports of known
// telemetry / analytics packages. Returns an error listing every offending file.
func CheckNoTelemetry(_ context.Context, repoRoot string) error {
	var offenders []string

	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			// Skip vendor, hidden directories, and testdata.
			name := d.Name()
			if name == "vendor" || strings.HasPrefix(name, ".") || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // G304: path is a conformance-scenario file path derived internally, not user input
		if readErr != nil {
			return nil // best-effort; skip unreadable files
		}
		content := string(data)
		for _, pkg := range telemetryPackages {
			if strings.Contains(content, `"`+pkg) {
				offenders = append(offenders, fmt.Sprintf("%s (imports %s)", path, pkg))
				break
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("conformance: walk repo: %w", err)
	}

	if len(offenders) > 0 {
		return fmt.Errorf("conformance: telemetry imports found in %d file(s):\n  %s",
			len(offenders), strings.Join(offenders, "\n  "))
	}
	return nil
}

// CheckDefaultsMatchThreatModel verifies that a freshly-generated default
// Config has the secure defaults mandated by the threat model. These defaults
// are load-bearing: they must never be weakened without explicit user opt-in.
//
// The checks here mirror §4.2 of DESIGN.md.
func CheckDefaultsMatchThreatModel(_ context.Context, cfgDefaults interface {
	GetTailnetLockEnabled() bool
	GetSSHCheckPeriod() string
	GetDisableMacOSSSHD() bool
	GetFirewallStealth() bool
	GetFileVaultPolicy() string
}) error {
	var failures []string

	if !cfgDefaults.GetTailnetLockEnabled() {
		failures = append(failures, "tailnet.lock.enabled must default to true")
	}
	if period := cfgDefaults.GetSSHCheckPeriod(); period != "12h" {
		failures = append(failures, fmt.Sprintf("mobile.ssh_check_period must default to 12h, got %q", period))
	}
	if !cfgDefaults.GetDisableMacOSSSHD() {
		failures = append(failures, "hardening.disable_macos_sshd must default to true")
	}
	if !cfgDefaults.GetFirewallStealth() {
		failures = append(failures, "hardening.firewall_stealth must default to true")
	}
	if p := cfgDefaults.GetFileVaultPolicy(); p != "required" {
		failures = append(failures, fmt.Sprintf("hardening.filevault must default to 'required', got %q", p))
	}

	if len(failures) > 0 {
		return fmt.Errorf("conformance: threat-model defaults violated:\n  %s",
			strings.Join(failures, "\n  "))
	}
	return nil
}

// CheckNtfyConfigBindAddr verifies that a generated ntfy server config does not
// bind to all interfaces. Rejects 0.0.0.0 or a bare :port (no IP prefix).
func CheckNtfyConfigBindAddr(_ context.Context, configContent string) error {
	for _, line := range strings.Split(configContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "listen-http:") {
			continue
		}
		if strings.Contains(trimmed, "0.0.0.0") {
			return fmt.Errorf("conformance: ntfy config binds to 0.0.0.0: %q", trimmed)
		}
		// Bare :port pattern — strip the key and quotes, check if value starts with ":".
		val := strings.TrimSpace(strings.TrimPrefix(trimmed, "listen-http:"))
		val = strings.Trim(val, `"' `)
		if strings.HasPrefix(val, ":") {
			return fmt.Errorf("conformance: ntfy config uses bare :port (binds all interfaces): %q", trimmed)
		}
	}
	return nil
}

// CheckSSHHardeningDirectives verifies that a sshd_config drop-in snippet
// contains all security-critical directives mandated by the threat model.
func CheckSSHHardeningDirectives(_ context.Context, configContent string) error {
	required := []string{
		"PasswordAuthentication no",
		"AllowAgentForwarding no",
		"AllowTcpForwarding no",
		"X11Forwarding no",
		"PermitRootLogin no",
	}
	var missing []string
	for _, directive := range required {
		if !strings.Contains(configContent, directive) {
			missing = append(missing, directive)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("conformance: sshd config missing required directives: %s",
			strings.Join(missing, ", "))
	}
	return nil
}

// truncate shortens s to at most n bytes, appending "…" if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
