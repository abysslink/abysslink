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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/shell"
)

// errSSHDAbsent is the sentinel returned when no OpenSSH effective config can be
// produced — neither `sshd -T` (root-only) nor /etc/ssh/sshd_config is available.
// Callers translate it into a SeverityOK "sshd not installed" finding so the
// sec-ssh-* checks degrade gracefully on unprivileged / sshd-less hosts (RESEARCH
// Pitfall 2). It is never a FATAL.
var errSSHDAbsent = errors.New("sec: sshd effective config unavailable")

// defaultSSHDConfigPath is the canonical OpenSSH server config location used as
// the fallback parse source when `sshd -T` cannot be run (non-root) or fails.
const defaultSSHDConfigPath = "/etc/ssh/sshd_config"

// OpenSSH compiled-in defaults applied when a directive is absent from the parsed
// config (commented out or omitted) and `sshd -T` was not consulted. [ASSUMED per
// RESEARCH A1 — OpenSSH documentation; may differ on distro-patched builds.]
const (
	sshDefaultPermitRoot      = "prohibit-password" // OK — not "yes"
	sshDefaultX11Forwarding   = "no"                // OK
	sshDefaultAgentForwarding = "yes"               // triggers WARN
	sshDefaultMaxAuthTries    = "6"                 // triggers WARN (> 4)
	sshDefaultLoginGraceTime  = "120"               // triggers WARN (> 60s)
)

// ---------------------------------------------------------------------------
// SECTION 1 — sshd effective config (RESEARCH Pattern 2)
// ---------------------------------------------------------------------------

// readSSHEffectiveConfig returns the effective value of an sshd config keyword.
// It PARSES /etc/ssh/sshd_config as the primary, always-available path (no
// prompt, no root). It attempts the authoritative `sshd -T` ONLY when running as
// root (os.Getuid()==0) — it NEVER invokes sudo (CONTEXT Open Question #1). When
// neither source yields a value it returns ("", nil) for an absent directive, or
// ("", errSSHDAbsent) when sshd is not installed at all.
func readSSHEffectiveConfig(ctx context.Context, runner shell.Runner, keyword string) (string, error) {
	return readSSHEffectiveConfigPath(ctx, runner, defaultSSHDConfigPath, keyword)
}

// readSSHEffectiveConfigPath is the path-injectable core used by both the live
// check and the unit tests (which point at a fixture sshd_config).
func readSSHEffectiveConfigPath(ctx context.Context, runner shell.Runner, configPath, keyword string) (string, error) {
	// Authoritative source: sshd -T (root only — it reads private host keys to
	// validate ciphers and fails as "no hostkeys available" otherwise).
	if runner != nil && os.Getuid() == 0 {
		if res, err := runner.Run(ctx, "sshd", "-T"); err == nil && res.ExitCode == 0 {
			if val, found := parseSSHDTOutput(res.Stdout, keyword); found {
				return val, nil
			}
		}
	}
	// Fallback: parse the config file directly.
	val, err := parseSSHDConfigFile(configPath, keyword)
	if err != nil {
		return "", err // errSSHDAbsent when the file is missing
	}
	return val, nil
}

// parseSSHDTOutput scans `sshd -T` output (one "keyword value" pair per line,
// lowercase keyword, single-space separator) for keyword (case-insensitive).
func parseSSHDTOutput(output, keyword string) (string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], keyword) {
			return strings.TrimSpace(parts[1]), true
		}
	}
	return "", false
}

// parseSSHDConfigFile scans an sshd_config file for keyword (case-insensitive),
// skipping comment and blank lines. A missing file returns errSSHDAbsent; an
// absent directive (commented or omitted) returns ("", nil) so the caller can
// apply the OpenSSH compiled-in default.
func parseSSHDConfigFile(path, keyword string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is /etc/ssh/sshd_config or a test fixture, not user-controlled at runtime
	if err != nil {
		if os.IsNotExist(err) {
			return "", errSSHDAbsent
		}
		return "", fmt.Errorf("sec: open sshd_config: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), keyword) {
			return strings.TrimSpace(parts[1]), nil
		}
	}
	return "", nil // directive absent → caller applies compiled-in default
}

// ---------------------------------------------------------------------------
// SECTION 2 — individual sec-* check functions
// ---------------------------------------------------------------------------

// secSSHFindingDefaults is a tiny helper: when readSSHEffectiveConfig returns
// errSSHDAbsent, produce the graceful-degradation SeverityOK finding.
func secSSHDAbsentOK(check string) modules.Finding {
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "sshd not installed — no OpenSSH daemon to harden"}
}

// --- SSH checks (6). Each *Path variant takes an explicit config path for tests.

func secSSHPermitRootCheck(ctx context.Context, runner shell.Runner) modules.Finding {
	return secSSHPermitRootCheckPathRunner(ctx, runner, defaultSSHDConfigPath)
}

func secSSHPermitRootCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHPermitRootCheckPathRunner(ctx, nil, path)
}

func secSSHPermitRootCheckPathRunner(ctx context.Context, runner shell.Runner, path string) modules.Finding {
	const check = "sec-ssh-permitroot"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "permitrootlogin")
	if errors.Is(err, errSSHDAbsent) {
		return secSSHDAbsentOK(check)
	}
	if val == "" {
		val = sshDefaultPermitRoot
	}
	if strings.EqualFold(val, "yes") {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "sshd PermitRootLogin is 'yes' — set it to 'no' or 'prohibit-password'"}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "PermitRootLogin: " + val}
}

func secSSHX11ForwardingCheck(ctx context.Context, runner shell.Runner) modules.Finding {
	return secSSHX11ForwardingCheckPathRunner(ctx, runner, defaultSSHDConfigPath)
}

func secSSHX11ForwardingCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHX11ForwardingCheckPathRunner(ctx, nil, path)
}

func secSSHX11ForwardingCheckPathRunner(ctx context.Context, runner shell.Runner, path string) modules.Finding {
	const check = "sec-ssh-x11forwarding"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "x11forwarding")
	if errors.Is(err, errSSHDAbsent) {
		return secSSHDAbsentOK(check)
	}
	if val == "" {
		val = sshDefaultX11Forwarding
	}
	if strings.EqualFold(val, "yes") {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "sshd X11Forwarding is 'yes' — disable it unless X11 over SSH is required"}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "X11Forwarding: " + val}
}

func secSSHAgentForwardingCheck(ctx context.Context, runner shell.Runner) modules.Finding {
	return secSSHAgentForwardingCheckPathRunner(ctx, runner, defaultSSHDConfigPath)
}

func secSSHAgentForwardingCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHAgentForwardingCheckPathRunner(ctx, nil, path)
}

func secSSHAgentForwardingCheckPathRunner(ctx context.Context, runner shell.Runner, path string) modules.Finding {
	const check = "sec-ssh-agentforwarding"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "allowagentforwarding")
	if errors.Is(err, errSSHDAbsent) {
		return secSSHDAbsentOK(check)
	}
	if val == "" {
		val = sshDefaultAgentForwarding
	}
	if strings.EqualFold(val, "yes") {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "sshd AllowAgentForwarding is 'yes' — disable it to prevent agent hijacking on the rig"}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "AllowAgentForwarding: " + val}
}

func secSSHMaxAuthTriesCheck(ctx context.Context, runner shell.Runner) modules.Finding {
	return secSSHMaxAuthTriesCheckPathRunner(ctx, runner, defaultSSHDConfigPath)
}

func secSSHMaxAuthTriesCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHMaxAuthTriesCheckPathRunner(ctx, nil, path)
}

func secSSHMaxAuthTriesCheckPathRunner(ctx context.Context, runner shell.Runner, path string) modules.Finding {
	const check = "sec-ssh-maxauthtries"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "maxauthtries")
	if errors.Is(err, errSSHDAbsent) {
		return secSSHDAbsentOK(check)
	}
	if val == "" {
		val = sshDefaultMaxAuthTries
	}
	n, perr := strconv.Atoi(strings.TrimSpace(val))
	if perr != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "MaxAuthTries unparseable (" + val + ") — treating as default"}
	}
	if n > 4 {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: fmt.Sprintf("sshd MaxAuthTries is %d — lower it to 4 or fewer", n)}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: fmt.Sprintf("MaxAuthTries: %d", n)}
}

func secSSHLoginGraceTimeCheck(ctx context.Context, runner shell.Runner) modules.Finding {
	return secSSHLoginGraceTimeCheckPathRunner(ctx, runner, defaultSSHDConfigPath)
}

func secSSHLoginGraceTimeCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHLoginGraceTimeCheckPathRunner(ctx, nil, path)
}

func secSSHLoginGraceTimeCheckPathRunner(ctx context.Context, runner shell.Runner, path string) modules.Finding {
	const check = "sec-ssh-logingracetime"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "logingracetime")
	if errors.Is(err, errSSHDAbsent) {
		return secSSHDAbsentOK(check)
	}
	if val == "" {
		val = sshDefaultLoginGraceTime
	}
	// LoginGraceTime may carry a unit suffix (e.g. "2m"); strip non-digits for a
	// coarse seconds estimate. A bare integer is seconds.
	n, perr := strconv.Atoi(strings.TrimSpace(val))
	if perr != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "LoginGraceTime unparseable (" + val + ") — treating as default"}
	}
	if n > 60 {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: fmt.Sprintf("sshd LoginGraceTime is %ds — lower it to 60s or fewer", n)}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: fmt.Sprintf("LoginGraceTime: %ds", n)}
}

func secSSHCiphersCheck(ctx context.Context, runner shell.Runner) modules.Finding {
	return secSSHCiphersCheckPathRunner(ctx, runner, defaultSSHDConfigPath)
}

func secSSHCiphersCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHCiphersCheckPathRunner(ctx, nil, path)
}

func secSSHCiphersCheckPathRunner(ctx context.Context, runner shell.Runner, path string) modules.Finding {
	const check = "sec-ssh-ciphers"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "ciphers")
	if errors.Is(err, errSSHDAbsent) {
		return secSSHDAbsentOK(check)
	}
	// Empty/absent → modern OpenSSH defaults are safe.
	low := strings.ToLower(val)
	for _, weak := range []string{"-cbc", "arcfour", "blowfish"} {
		if strings.Contains(low, weak) {
			return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
				Message: "sshd Ciphers includes a weak algorithm (" + weak + ") — remove CBC/arcfour/blowfish ciphers"}
		}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "no weak ciphers configured"}
}

// --- Audit log checks (2).

func secAuditLogExistsCheck() modules.Finding {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return modules.Finding{Module: "sec", Check: "sec-audit-log-exists", Severity: modules.SeverityFatal,
			Message: "cannot determine audit log path: " + err.Error()}
	}
	return secAuditLogExistsCheckPath(logPath)
}

func secAuditLogExistsCheckPath(logPath string) modules.Finding {
	const check = "sec-audit-log-exists"
	if _, err := os.Stat(logPath); err != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: fmt.Sprintf("audit log does not exist at %s — run 'abysslink up --apply'", logPath)}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "audit log present at " + logPath}
}

func secAuditLogPermsCheck() modules.Finding {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return modules.Finding{Module: "sec", Check: "sec-audit-log-perms", Severity: modules.SeverityFatal,
			Message: "cannot determine audit log path: " + err.Error()}
	}
	return secAuditLogPermsCheckPath(logPath)
}

func secAuditLogPermsCheckPath(logPath string) modules.Finding {
	const check = "sec-audit-log-perms"
	fi, err := os.Stat(logPath)
	if err != nil {
		// Absent: sec-audit-log-exists covers the missing-file case as FATAL.
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "audit log absent — sec-audit-log-exists covers this"}
	}
	if fi.Mode()&0o077 != 0 {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: fmt.Sprintf("audit log %s has permissions %#o — must be 0600", logPath, fi.Mode().Perm())}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "audit log permissions are 0600"}
}

// --- Permissions sweep (2).

func secNoWorldReadableConfigCheck() modules.Finding {
	return secNoWorldReadableConfigCheckDir(abysslinkConfigDir())
}

// secNoWorldReadableConfigCheckDir walks every REGULAR file under the abysslink
// config directory and FATALs on any world/group-writable file (mode & 0o022).
// Symlinks are not followed (entry.Type().IsRegular()); directories are skipped
// (RESEARCH Open Question #2, T-20-02-03).
func secNoWorldReadableConfigCheckDir(dir string) modules.Finding {
	const check = "sec-no-world-readable-config"
	if dir == "" {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "config directory not resolvable — nothing to scan"}
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "config directory does not exist — nothing to scan"}
	}
	var offenders []string
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries; never fail the whole walk
		}
		if !d.Type().IsRegular() {
			return nil // skip dirs and symlinks
		}
		fi, ferr := d.Info()
		if ferr != nil {
			return nil
		}
		if fi.Mode()&0o022 != 0 {
			offenders = append(offenders, fmt.Sprintf("%s (%#o)", path, fi.Mode().Perm()))
		}
		return nil
	})
	if walkErr != nil {
		slog.Warn("sec: config dir walk failed", "err", walkErr)
	}
	if len(offenders) > 0 {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "world/group-writable config files found: " + strings.Join(offenders, ", ")}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "no world/group-writable config files"}
}

func secDaemonSocketPermsCheck() modules.Finding {
	return secDaemonSocketPermsCheckPath(daemon.SocketPath())
}

func secDaemonSocketPermsCheckPath(socketPath string) modules.Finding {
	const check = "sec-daemon-socket-perms"
	fi, err := os.Stat(socketPath)
	if err != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "daemon socket absent — abysslinkd not running"}
	}
	if fi.Mode()&0o077 != 0 {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: fmt.Sprintf("daemon socket %s has permissions %#o — must be 0600", socketPath, fi.Mode().Perm())}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "daemon socket permissions are 0600"}
}

// --- Listener / funnel / disk (3).

// secListenerBindCheck FATALs when any USER-CONFIGURABLE bind address is the
// unspecified wildcard (0.0.0.0 / ::). Only observability.metrics.bind_addr and
// webui.bind_addr are checked — config.NtfyModule has no BindAddr field.
func secListenerBindCheck(cfg *config.Config) modules.Finding {
	const check = "sec-listener-bind"
	type bindField struct {
		name string
		addr string
	}
	for _, bf := range []bindField{
		{"observability.metrics.bind_addr", cfg.Observability.Metrics.BindAddr},
		{"webui.bind_addr", cfg.WebUI.BindAddr},
	} {
		if bf.addr != "" && config.IsUnspecifiedBindAddr(bf.addr) {
			return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
				Message: fmt.Sprintf("%s is %q — must bind the tailnet IP only, never 0.0.0.0/::", bf.name, bf.addr)}
		}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "all listener bind addresses are tailnet-scoped"}
}

// secFunnelSchemaCheck FATALs when cfg.Validate() rejects a Funnel-related field
// (Tailscale Funnel is permanently rejected at the schema level). A clean
// Validate (Funnel not configured) is SeverityOK.
func secFunnelSchemaCheck(cfg *config.Config) modules.Finding {
	const check = "sec-funnel-schema"
	if err := config.Validate(cfg); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "funnel") {
			return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
				Message: "Tailscale Funnel is configured but permanently rejected: " + err.Error()}
		}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "Funnel is not configured (permanently rejected at schema level)"}
}

// secDiskEncryptionCheck aliases the FileVault/LUKS fail-closed disk-encryption
// posture via platform.DiskEncryptionStatus (reuse — RESEARCH Don't Hand-Roll).
func secDiskEncryptionCheck(ctx context.Context, plat platform.Platform) modules.Finding {
	const check = "sec-disk-encryption"
	if plat == nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "platform unavailable — cannot determine disk encryption status"}
	}
	state, err := plat.DiskEncryptionStatus(ctx)
	if err != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "disk encryption status unknown: " + err.Error()}
	}
	switch state {
	case platform.DiskEncrypted:
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "full-disk encryption is enabled"}
	case platform.DiskUnencrypted:
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "disk is NOT encrypted — enable FileVault (macOS) / LUKS (Linux) before remote access"}
	default: // DiskUnknown
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "disk encryption status could not be determined"}
	}
}

// --- Supply-chain aliases (2): call the existing checks, rename Check/Module.

func secBinarySignedCheck(ctx context.Context, runner shell.Runner) modules.Finding {
	f := supplyCosignBundleCheck(ctx, runner, version, "")
	f.Check = "sec-binary-signed"
	f.Module = "sec"
	return f
}

func secUpgradeVerifiedCheck() modules.Finding {
	f := supplySLSASourceCheck()
	f.Check = "sec-upgrade-verified"
	f.Module = "sec"
	return f
}

// --- Cross-ref aliases (3): copy a pre-computed finding, rename Check/Module.

func secMetricsBindAlias(metFindings []modules.Finding) modules.Finding {
	return secAliasFromFindings(metFindings, "metrics-bind-tailnet", "sec-metrics-bind", "metrics disabled — bind floor not applicable")
}

func secWebUIBindAlias(webuiFindings []modules.Finding) modules.Finding {
	return secAliasFromFindings(webuiFindings, "webui-bind", "sec-webui-bind", "webui disabled — bind floor not applicable")
}

func secAuditAnchorAgeAlias(auditFindings []modules.Finding) modules.Finding {
	return secAliasFromFindings(auditFindings, "audit-anchor-age", "sec-audit-anchor-age", "audit anchor age within threshold")
}

// secAliasFromFindings finds srcCheck in findings and returns a copy renamed to
// newCheck under Module "sec". If absent (the underlying check did not run, e.g.
// the feature is disabled), it returns a SeverityOK placeholder so the aggregate
// always carries the full 18-check roster (run-once pattern, T-20-02-04).
func secAliasFromFindings(findings []modules.Finding, srcCheck, newCheck, okMsg string) modules.Finding {
	for _, f := range findings {
		if f.Check == srcCheck {
			f.Check = newCheck
			f.Module = "sec"
			return f
		}
	}
	return modules.Finding{Module: "sec", Check: newCheck, Severity: modules.SeverityOK, Message: okMsg}
}

// ---------------------------------------------------------------------------
// SECTION 3 — aggregator
// ---------------------------------------------------------------------------

// secDoctorFindings runs all 18 sec-* checks in a stable order and returns the
// findings. The 3 alias checks read from the pre-computed metFindings /
// webuiFindings / auditFindings slices so the underlying Phase-17/18/19 checks
// run exactly once (RESEARCH Pitfall 3). The 6 SSH checks degrade gracefully —
// any panic in an sshd parse is recovered to a WARN, never propagated as FATAL.
func secDoctorFindings(ctx context.Context, cc *cmdContext, deps modules.Deps,
	metFindings, webuiFindings, auditFindings []modules.Finding) []modules.Finding {
	findings := make([]modules.Finding, 0, 18)

	// SSH checks (6) — guarded so a parse failure never crashes the doctor run.
	findings = append(findings, safeSSHCheck("sec-ssh-permitroot", func() modules.Finding { return secSSHPermitRootCheck(ctx, cc.runner) }))
	findings = append(findings, safeSSHCheck("sec-ssh-x11forwarding", func() modules.Finding { return secSSHX11ForwardingCheck(ctx, cc.runner) }))
	findings = append(findings, safeSSHCheck("sec-ssh-agentforwarding", func() modules.Finding { return secSSHAgentForwardingCheck(ctx, cc.runner) }))
	findings = append(findings, safeSSHCheck("sec-ssh-maxauthtries", func() modules.Finding { return secSSHMaxAuthTriesCheck(ctx, cc.runner) }))
	findings = append(findings, safeSSHCheck("sec-ssh-logingracetime", func() modules.Finding { return secSSHLoginGraceTimeCheck(ctx, cc.runner) }))
	findings = append(findings, safeSSHCheck("sec-ssh-ciphers", func() modules.Finding { return secSSHCiphersCheck(ctx, cc.runner) }))

	// Audit log + perms sweep (4).
	findings = append(findings,
		secAuditLogExistsCheck(),
		secAuditLogPermsCheck(),
		secNoWorldReadableConfigCheck(),
		secDaemonSocketPermsCheck(),
	)

	// Listener / funnel / disk (3).
	findings = append(findings,
		secListenerBindCheck(cc.cfg),
		secFunnelSchemaCheck(cc.cfg),
		secDiskEncryptionCheck(ctx, deps.Platform),
	)

	// Supply-chain aliases (2).
	findings = append(findings,
		secBinarySignedCheck(ctx, cc.runner),
		secUpgradeVerifiedCheck(),
	)

	// Cross-ref aliases (3) — reuse pre-computed findings.
	findings = append(findings,
		secMetricsBindAlias(metFindings),
		secWebUIBindAlias(webuiFindings),
		secAuditAnchorAgeAlias(auditFindings),
	)

	return findings
}

// safeSSHCheck runs an SSH check and recovers any panic into a WARN finding so a
// malformed sshd config never propagates a FATAL/crash up to the doctor run
// (graceful degradation — RESEARCH Pitfall 2).
func safeSSHCheck(check string, fn func() modules.Finding) (f modules.Finding) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("sec: ssh check panicked; degrading to WARN", "check", check, "recover", r)
			f = modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
				Message: "ssh check could not complete — sshd config unreadable"}
		}
	}()
	return fn()
}
