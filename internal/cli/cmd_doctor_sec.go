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
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/secrets"
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

// readSSHEffectiveConfigPath returns the effective value of an sshd config
// keyword. It PARSES sshd_config (default /etc/ssh/sshd_config) as the primary,
// always-available path (no prompt, no root). It attempts the authoritative
// `sshd -T` ONLY when running as root (os.Getuid()==0) — it NEVER invokes sudo
// (CONTEXT Open Question #1). When neither source yields a value it returns
// ("", nil) for an absent directive, or ("", errSSHDAbsent) when sshd is not
// installed at all. configPath is injectable so unit tests can point at a fixture.
//
// allowNonRootSshd is the --pentest escape hatch: when true, `sshd -T` is
// attempted even when not root (os.Getuid()!=0). Explicit pentest runs accept
// the "no hostkeys available" failure mode in exchange for trying the
// authoritative source; the file-parse fallback still applies on failure. When
// false (the normal doctor path) the os.Getuid()==0 guard remains in effect.
func readSSHEffectiveConfigPath(ctx context.Context, runner shell.Runner, configPath, keyword string, allowNonRootSshd bool) (string, error) {
	// Authoritative source: sshd -T (normally root only — it reads private host
	// keys to validate ciphers and fails as "no hostkeys available" otherwise).
	// --pentest (allowNonRootSshd) bypasses the root guard to try it regardless.
	if runner != nil && (allowNonRootSshd || os.Getuid() == 0) {
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
	if err := scanner.Err(); err != nil {
		// A read error mid-scan would otherwise read as "directive absent"
		// and silently apply the compiled-in default — fail honest instead.
		return "", fmt.Errorf("sec: read sshd_config: %w", err)
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

func secSSHPermitRootCheck(ctx context.Context, runner shell.Runner, pentest bool) modules.Finding {
	return secSSHPermitRootCheckPathRunner(ctx, runner, defaultSSHDConfigPath, pentest)
}

func secSSHPermitRootCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHPermitRootCheckPathRunner(ctx, nil, path, false)
}

func secSSHPermitRootCheckPathRunner(ctx context.Context, runner shell.Runner, path string, pentest bool) modules.Finding {
	const check = "sec-ssh-permitroot"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "permitrootlogin", pentest)
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

func secSSHX11ForwardingCheck(ctx context.Context, runner shell.Runner, pentest bool) modules.Finding {
	return secSSHX11ForwardingCheckPathRunner(ctx, runner, defaultSSHDConfigPath, pentest)
}

func secSSHX11ForwardingCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHX11ForwardingCheckPathRunner(ctx, nil, path, false)
}

func secSSHX11ForwardingCheckPathRunner(ctx context.Context, runner shell.Runner, path string, pentest bool) modules.Finding {
	const check = "sec-ssh-x11forwarding"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "x11forwarding", pentest)
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

func secSSHAgentForwardingCheck(ctx context.Context, runner shell.Runner, pentest bool) modules.Finding {
	return secSSHAgentForwardingCheckPathRunner(ctx, runner, defaultSSHDConfigPath, pentest)
}

func secSSHAgentForwardingCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHAgentForwardingCheckPathRunner(ctx, nil, path, false)
}

func secSSHAgentForwardingCheckPathRunner(ctx context.Context, runner shell.Runner, path string, pentest bool) modules.Finding {
	const check = "sec-ssh-agentforwarding"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "allowagentforwarding", pentest)
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

func secSSHMaxAuthTriesCheck(ctx context.Context, runner shell.Runner, pentest bool) modules.Finding {
	return secSSHMaxAuthTriesCheckPathRunner(ctx, runner, defaultSSHDConfigPath, pentest)
}

func secSSHMaxAuthTriesCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHMaxAuthTriesCheckPathRunner(ctx, nil, path, false)
}

func secSSHMaxAuthTriesCheckPathRunner(ctx context.Context, runner shell.Runner, path string, pentest bool) modules.Finding {
	const check = "sec-ssh-maxauthtries"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "maxauthtries", pentest)
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

func secSSHLoginGraceTimeCheck(ctx context.Context, runner shell.Runner, pentest bool) modules.Finding {
	return secSSHLoginGraceTimeCheckPathRunner(ctx, runner, defaultSSHDConfigPath, pentest)
}

func secSSHLoginGraceTimeCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHLoginGraceTimeCheckPathRunner(ctx, nil, path, false)
}

func secSSHLoginGraceTimeCheckPathRunner(ctx context.Context, runner shell.Runner, path string, pentest bool) modules.Finding {
	const check = "sec-ssh-logingracetime"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "logingracetime", pentest)
	if errors.Is(err, errSSHDAbsent) {
		return secSSHDAbsentOK(check)
	}
	if val == "" {
		val = sshDefaultLoginGraceTime
	}
	// LoginGraceTime may carry an sshd time-format unit suffix (e.g. "2m" = 120s,
	// "1h" = 3600s); convert it to seconds. A bare integer is seconds (IN-03).
	n, perr := parseSSHDSeconds(strings.TrimSpace(val))
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

// parseSSHDSeconds converts an sshd_config time value to seconds. sshd accepts a
// bare integer (seconds) or a value with a single unit suffix — s(econds),
// m(inutes), h(ours), d(ays), w(eeks) — e.g. "2m" = 120, "1h" = 3600. Only the
// common single-unit form is handled (sufficient for a coarse threshold check);
// anything else returns an error so the caller treats it as the default.
func parseSSHDSeconds(val string) (int, error) {
	if val == "" {
		return 0, fmt.Errorf("empty time value")
	}
	mult := 1
	last := val[len(val)-1]
	switch last {
	case 's', 'S':
		mult, val = 1, val[:len(val)-1]
	case 'm', 'M':
		mult, val = 60, val[:len(val)-1]
	case 'h', 'H':
		mult, val = 3600, val[:len(val)-1]
	case 'd', 'D':
		mult, val = 86400, val[:len(val)-1]
	case 'w', 'W':
		mult, val = 604800, val[:len(val)-1]
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

func secSSHCiphersCheck(ctx context.Context, runner shell.Runner, pentest bool) modules.Finding {
	return secSSHCiphersCheckPathRunner(ctx, runner, defaultSSHDConfigPath, pentest)
}

func secSSHCiphersCheckPath(ctx context.Context, path string) modules.Finding {
	return secSSHCiphersCheckPathRunner(ctx, nil, path, false)
}

func secSSHCiphersCheckPathRunner(ctx context.Context, runner shell.Runner, path string, pentest bool) modules.Finding {
	const check = "sec-ssh-ciphers"
	val, err := readSSHEffectiveConfigPath(ctx, runner, path, "ciphers", pentest)
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

// secAuditLogPath is a test seam so parity goldens can pin the audit log path
// to a fixed value, preventing process-specific t.TempDir() paths from baking
// into the golden output (same pattern as auditDefaultLogPath in cmd_doctor.go).
var secAuditLogPath = audit.DefaultLogPath //nolint:gochecknoglobals // test seam, mirrors auditDefaultLogPath

func secAuditLogExistsCheck() modules.Finding {
	logPath, err := secAuditLogPath()
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

// secAuditEpochCheck reports the audit HMAC key-epoch health (ROT-03): the
// current epoch, and — critically — whether a rotation is stuck half-finished
// (the in-chain marker was recorded but the keychain pointer was never
// advanced, the documented rotation crash window). A half-finished rotation
// makes every subsequent append fail closed, so it is surfaced as WARN and
// escalated to FATAL by --profile at-risk (atRiskTightenedChecks) with the
// exact recovery command. A keychain that is simply unavailable is not this
// check's job (audit-keychain covers that) — it degrades to OK here.
func secAuditEpochCheck(ctx context.Context, cc *cmdContext) modules.Finding {
	const check = "sec-audit-epoch"
	logPath, err := secAuditLogPath()
	if err != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "cannot determine audit log path — sec-audit-log-exists covers this"}
	}
	kc := auditKeychain(ctx, cc)
	if kc == nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "keychain unavailable — audit-keychain covers this; epoch health not evaluated"}
	}
	st, serr := audit.ReadEpochStatus(ctx, logPath, kc)
	if serr != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "could not read audit key-epoch status: " + serr.Error()}
	}
	if st.Incomplete {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: fmt.Sprintf("audit key rotation is incomplete: chain is at epoch %d but the keychain pointer is %d — appends fail closed until you run `abysslink rotate audit-hmac --apply`",
				st.TailEpoch, st.PointerEpoch)}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: fmt.Sprintf("audit HMAC key epoch %d; no rotation in progress", st.PointerEpoch)}
}

// secMlockCheck reports whether this process can lock secret memory (MEM-02).
// It is defense-in-depth posture, not a hard requirement: an unlocked fallback
// still zeroizes on free, so a memlock-constrained host (common in containers,
// where RLIMIT_MEMLOCK is tiny) is a WARN with the remediation, never FATAL.
// Kept out of atRiskTightenedChecks: the at-risk profile must not fail closed
// on a kernel limit the operator may be unable to raise.
func secMlockCheck() modules.Finding {
	const check = "sec-mlock"
	if secrets.MlockAvailable() {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "secret memory can be locked (mlock available) — in-memory keys are held in mlock'd, zeroized-on-free buffers"}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
		Message: "cannot lock secret memory (RLIMIT_MEMLOCK too low or unsupported) — in-memory keys fall back to unlocked, zeroized-on-free buffers; raise `ulimit -l` (or the container's --ulimit memlock) to restore the mlock defense-in-depth"}
}

func secAuditLogPermsCheck() modules.Finding {
	logPath, err := secAuditLogPath()
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

// looseConfigBits is the set of group/other permission bits that are forbidden
// on an abysslink config file. abysslink config can carry tailnet bind
// addresses, rig topology, ntfy topics, and backend endpoints, so ANY
// group/other access (read OR write) is an exposure the check must catch. This
// includes the world-read bit (0o004) the check name promises (SEC-04), the
// group-read bit (0o040), and the group/other-write tamper bits (0o022).
const looseConfigBits = 0o077

// secNoWorldReadableConfigCheckDir walks every REGULAR file under the abysslink
// config directory and FATALs on any file granting group/other access
// (mode & 0o077) — world-readable config is the primary exposure the check name
// promises (SEC-04), and group/other-write is the tamper surface. Symlinks are
// not followed (entry.Type().IsRegular()); directories are skipped (RESEARCH
// Open Question #2, T-20-02-03).
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
		if fi.Mode()&looseConfigBits != 0 {
			offenders = append(offenders, fmt.Sprintf("%s (%#o)", path, fi.Mode().Perm()))
		}
		return nil
	})
	if walkErr != nil {
		slog.Warn("sec: config dir walk failed", "err", walkErr)
	}
	if len(offenders) > 0 {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "config files readable/writable by group or other found: " + strings.Join(offenders, ", ")}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
		Message: "no group/other-accessible config files"}
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
//
// Severity contract (W10): UNKNOWN is FATAL, not WARN. `abysslink up` treats an
// unknown disk-encryption state as a non-overridable blocker (D-05: even
// --force-unsafe cannot bypass it), so doctor must not under-report the exact
// state up considers the most severe — a user triaging with doctor would see
// "review recommended" and then hit a hard block in up.
func secDiskEncryptionCheck(ctx context.Context, plat platform.Platform) modules.Finding {
	const check = "sec-disk-encryption"
	if plat == nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "disk-encryption state is UNKNOWN: platform unavailable — verify FileVault/LUKS manually; `up --apply` will refuse until the state is determinable"}
	}
	state, err := plat.DiskEncryptionStatus(ctx)
	if err != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "disk-encryption state is UNKNOWN: " + err.Error() + " — verify FileVault/LUKS manually; `up --apply` will refuse until the state is determinable"}
	}
	switch state {
	case platform.DiskEncrypted:
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "full-disk encryption is enabled"}
	case platform.DiskUnencrypted:
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "disk is NOT encrypted — enable FileVault (macOS) / LUKS (Linux) before remote access"}
	case platform.DiskEncrypting:
		// Mid-encryption (or decryption/deferred): plaintext blocks may still
		// exist on disk, so this is NOT-safe and is gated like unencrypted (BKLG-02).
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "disk encryption is IN PROGRESS — not yet fully protected; wait for FileVault to " +
				"finish (fdesetup status) before enabling remote access (fail-closed)"}
	default: // DiskUnknown
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityFatal,
			Message: "disk-encryption state is UNKNOWN — could not be determined; verify FileVault (macOS) / LUKS (Linux) manually; `up --apply` refuses this state even with --force-unsafe (D-05)"}
	}
}

// secTailnetLockCheck surfaces the Tailnet Lock posture in doctor (BKLG-01 /
// BKLG-04). It queries LIVE state via the backend Locker (which goes through
// shell.Runner) rather than config, so a `tailnet.lock.enabled=false` intent
// cannot mask an off tailnet. Default severity is WARN (mirrors the lock module's
// WARN so a normal doctor does not hard-fail on a machine that simply hasn't
// enabled lock yet); `--profile at-risk` tightens it to FATAL via
// atRiskTightenedChecks. An undeterminable status is WARN "could not determine" —
// it never silently passes as OK. A backend without Tailnet Lock support
// (Headscale / NetBird) reports OK not-applicable — the feature cannot exist there.
func secTailnetLockCheck(ctx context.Context, b backend.Client) modules.Finding {
	const check = "sec-tailnet-lock"
	if b == nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "could not determine Tailnet Lock status — backend unavailable"}
	}
	lc, ok := b.(backend.Locker)
	if !ok {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "Tailnet Lock not applicable on this backend"}
	}
	st, err := lc.LockStatus(ctx)
	if err != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "could not determine Tailnet Lock status (" + err.Error() +
				") — ensure tailscale is running and logged in"}
	}
	if st.Enabled {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "Tailnet Lock is enabled"}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
		Message: "Tailnet Lock is NOT enabled — the only defense against a compromised coordination " +
			"server injecting a rogue device that still passes your ACLs; enable with `tailscale lock init`"}
}

// secAutoLoginCheck surfaces macOS automatic-login posture (guide §3.4, BKLG-04).
// Auto-login directly undermines the FileVault/keychain-at-rest model this phase
// hardens, so it must be OFF. Detection (ASSUMED, MEDIUM): `defaults read
// /Library/Preferences/com.apple.loginwindow autoLoginUser` prints a username when
// auto-login is ON and exits non-zero (key absent) when OFF. Default WARN when ON
// or undeterminable; FATAL under `--profile at-risk`. Non-darwin returns OK
// "not applicable" (Linux doctor output unchanged).
func secAutoLoginCheck(ctx context.Context, runner shell.Runner, osName string) modules.Finding {
	const check = "sec-autologin"
	if osName != "darwin" {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "auto-login check not applicable on " + osName}
	}
	res, err := runner.Run(ctx, "defaults", "read",
		"/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
	if err != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "could not determine auto-login status: " + err.Error()}
	}
	// Non-zero exit (key absent) or empty output ⇒ auto-login is OFF (good). We do
	// not echo the username value into the finding (kept out of doctor output).
	if !res.Ok() || strings.TrimSpace(res.Stdout) == "" {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "automatic login is disabled"}
	}
	return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
		Message: "automatic login is ENABLED — it undermines FileVault/keychain-at-rest protection; " +
			"turn OFF Automatic login in System Settings → Users & Groups"}
}

// secRemoteLoginCheck surfaces the public macOS sshd (Remote Login) posture (guide
// §2.3, BKLG-04). Abysslink exposes SSH via Tailscale SSH only; the public sshd
// Remote Login toggle must be OFF. Detection (ASSUMED, MEDIUM): `systemsetup
// -getremotelogin` prints "Remote Login: On" / "Remote Login: Off". Default WARN
// when ON or undeterminable; FATAL under `--profile at-risk`. Non-darwin returns
// OK "not applicable".
func secRemoteLoginCheck(ctx context.Context, runner shell.Runner, osName string) modules.Finding {
	const check = "sec-remote-login"
	if osName != "darwin" {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "Remote Login check not applicable on " + osName}
	}
	res, err := runner.Run(ctx, "systemsetup", "-getremotelogin")
	if err != nil {
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "could not determine Remote Login status: " + err.Error()}
	}
	out := strings.TrimSpace(res.Stdout)
	switch {
	case strings.Contains(out, "Remote Login: Off"):
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityOK,
			Message: "public sshd (Remote Login) is disabled — SSH is exposed via Tailscale SSH only"}
	case strings.Contains(out, "Remote Login: On"):
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "public sshd (Remote Login) is ENABLED — expose SSH via Tailscale only; " +
				"turn OFF Remote Login in System Settings → General → Sharing"}
	default:
		return modules.Finding{Module: "sec", Check: check, Severity: modules.SeverityWarning,
			Message: "could not determine Remote Login status (unrecognized systemsetup output)"}
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

// secDoctorFindings runs all 23 sec-*  checks in a stable order and returns the
// findings. The 3 alias checks read from the pre-computed metFindings /
// webuiFindings / auditFindings slices so the underlying Phase-17/18/19 checks
// run exactly once (RESEARCH Pitfall 3). The 6 SSH checks degrade gracefully —
// any panic in an sshd parse is recovered to a WARN, never propagated as FATAL.
//
// pentest is the --pentest escape hatch: when true the SSH checks attempt the
// authoritative `sshd -T` even when not root (bypassing the os.Getuid()==0
// guard). The normal doctor path passes pentest=false so sshd -T is attempted
// only as root and the always-available sshd_config parse is the primary source.
//
// supplyFindings (optional, variadic for call-site compatibility): when the
// caller already ran supplyChainFindings, pass its result so sec-binary-signed
// aliases the pre-computed supply-cosign-bundle finding instead of triggering
// a second release-artifact download (W8 / RESEARCH Pitfall 3). When absent,
// the check runs itself (legacy single-run callers: audit aggregate, report).
func secDoctorFindings(ctx context.Context, cc *cmdContext, deps modules.Deps, pentest bool,
	metFindings, webuiFindings, auditFindings []modules.Finding,
	supplyFindings ...[]modules.Finding) []modules.Finding {
	findings := make([]modules.Finding, 0, 23)

	// SSH checks (6) — guarded so a parse failure never crashes the doctor run.
	findings = append(findings, safeSSHCheck("sec-ssh-permitroot", func() modules.Finding { return secSSHPermitRootCheck(ctx, cc.runner, pentest) }))
	findings = append(findings, safeSSHCheck("sec-ssh-x11forwarding", func() modules.Finding { return secSSHX11ForwardingCheck(ctx, cc.runner, pentest) }))
	findings = append(findings, safeSSHCheck("sec-ssh-agentforwarding", func() modules.Finding { return secSSHAgentForwardingCheck(ctx, cc.runner, pentest) }))
	findings = append(findings, safeSSHCheck("sec-ssh-maxauthtries", func() modules.Finding { return secSSHMaxAuthTriesCheck(ctx, cc.runner, pentest) }))
	findings = append(findings, safeSSHCheck("sec-ssh-logingracetime", func() modules.Finding { return secSSHLoginGraceTimeCheck(ctx, cc.runner, pentest) }))
	findings = append(findings, safeSSHCheck("sec-ssh-ciphers", func() modules.Finding { return secSSHCiphersCheck(ctx, cc.runner, pentest) }))

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

	// Host-posture footguns (3) — BKLG-01/04. WARN by default, FATAL under
	// --profile at-risk. Inserted right after sec-disk-encryption in a stable slot.
	// osName is read nil-safely: deps.Platform may be a bare modules.Deps{} on the
	// audit-fix path where buildDeps failed. The backend Locker query goes through
	// shell.Runner; a nil backend (construction failed) degrades to WARN.
	osName := ""
	if deps.Platform != nil {
		osName = deps.Platform.OS()
	}
	var lockBackend backend.Client
	if b, bErr := cc.backend(); bErr == nil {
		lockBackend = b
	}
	findings = append(findings,
		secTailnetLockCheck(ctx, lockBackend),
		secAutoLoginCheck(ctx, cc.runner, osName),
		secRemoteLoginCheck(ctx, cc.runner, osName),
	)

	// Audit HMAC key-epoch health (1) — ROT-03.
	findings = append(findings, secAuditEpochCheck(ctx, cc))

	// Secure-memory (mlock) posture (1) — MEM-02.
	findings = append(findings, secMlockCheck())

	// Supply-chain aliases (2). Reuse the caller's pre-computed supply findings
	// when provided so the cosign bundle check (a network download) runs exactly
	// once per doctor invocation (W8).
	if len(supplyFindings) > 0 && supplyFindings[0] != nil {
		findings = append(findings,
			secAliasFromFindings(supplyFindings[0], "supply-cosign-bundle", "sec-binary-signed",
				"supply-chain check did not run"),
			secUpgradeVerifiedCheck(),
		)
	} else {
		findings = append(findings,
			secBinarySignedCheck(ctx, cc.runner),
			secUpgradeVerifiedCheck(),
		)
	}

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
