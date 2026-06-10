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
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/spf13/cobra"
)

// newAuditCmd builds the `abysslink audit` command tree: verify, tail, ls,
// export. All output flows through the Printer abstraction so tests can capture
// it and --json produces ANSI-free structured output.
func newAuditCmd() *cobra.Command {
	a := &cobra.Command{
		Use:   "audit",
		Short: "Inspect and verify the tamper-evident audit log",
	}
	a.AddCommand(newAuditVerifyCmd(), newAuditTailCmd(), newAuditLsCmd(), newAuditExportCmd())
	return a
}

// auditKeychain resolves a keychain store for the audit commands. A missing
// backend is non-fatal: Verify can still walk the hash chain with a nil key
// (skipping the HMAC sig check), and the read-only tail/ls/export paths never
// touch the keychain. Returns nil when no backend is available.
func auditKeychain(ctx context.Context, cc *cmdContext) audit.KeychainStore {
	kc, err := secrets.NewStore(ctx, cc.runner)
	if err != nil {
		slog.Warn("audit: keychain unavailable — HMAC signature checks will be skipped", "err", err)
		return nil
	}
	return kc
}

// cmdSignedAudit resolves a *audit.SignedAudit from the command context.
// It calls DefaultLogPath, auditKeychain, and audit.NewSigned. Returns an error
// when the keychain is unavailable or NewSigned fails — callers must treat this
// as a fail-closed condition (e.g. refuse a chain-gated restore rather than
// falling back to the unchained path). Used by the restore command and all server
// backup commands (AUD-01).
func cmdSignedAudit(ctx context.Context, cc *cmdContext) (*audit.SignedAudit, error) {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return nil, fmt.Errorf("audit log path: %w", err)
	}
	kc := auditKeychain(ctx, cc)
	if kc == nil {
		return nil, fmt.Errorf("keychain unavailable — cannot build signed audit writer")
	}
	sa, saErr := audit.NewSigned(logPath, kc)
	if saErr != nil {
		return nil, fmt.Errorf("signed audit init: %w", saErr)
	}
	return sa, nil
}

// runAuditVerify walks the chain and anchor at logPath. It returns nil (exit 0)
// on a clean chain and an *exitError{code:2} on any gap, fork, HMAC mismatch, or
// detected truncation — emitting the exact "CHAIN BROKEN at entry N" string on
// stderr (T-17-09: exit 2 is reserved for genuine chain breaks).
func runAuditVerify(ctx context.Context, p Printer, logPath string, kc audit.KeychainStore) error {
	// WR-02: never let an operator mistake an unverified walk for a real
	// integrity check. When the keychain is unavailable, HMAC signatures (and
	// the anchor) cannot be authenticated, so emit a prominent visible banner —
	// slog.Warn alone is hidden at the default non-TTY level.
	if kc == nil {
		printerError(p, "HMAC checks SKIPPED — keychain unavailable; chain structure walked but signatures NOT authenticated")
	}

	result, err := audit.Verify(ctx, logPath, kc)
	if err != nil {
		// Parse/IO errors are generic failures (exit 1), never exit 2 (T-17-09).
		return fmt.Errorf("audit verify: %w", err)
	}

	if !result.OK {
		printerError(p, fmt.Sprintf("CHAIN BROKEN at entry %d: %s", result.At, result.Reason))
		if result.TruncationDetected {
			printerError(p, "TRUNCATION DETECTED: current entry count is less than the anchor's recorded count")
		}
		return &exitError{code: exitCodeFatal}
	}
	if result.TruncationDetected {
		printerError(p, "TRUNCATION DETECTED: current entry count is less than the anchor's recorded count")
		return &exitError{code: exitCodeFatal}
	}

	// WR-03: distinguish authenticated signatures from skipped/legacy ones so
	// "Chain OK" never overstates what was verified.
	entries, _ := audit.ReadLog(logPath)
	printerInfo(p, fmt.Sprintf("Chain OK — %d entries (%d signatures verified, %d legacy/unsigned/unverifiable skipped)",
		len(entries), result.SigsVerified, result.SigsSkipped))

	// AUD-02 D-04: surface CounterStatus honestly — "unknown" must NEVER be
	// rendered as a pass. Only "verified" is a clean counter result.
	switch result.CounterStatus {
	case "verified":
		printerInfo(p, "Counter OK — keychain counter matches log entry count (tail-truncation check passed)")
	case "mismatch":
		printerError(p, fmt.Sprintf("COUNTER MISMATCH: %s", result.Reason))
	case "unknown":
		printerError(p, "? Counter UNKNOWN — keychain counter absent or unreadable; tail-truncation check could not run")
	case "":
		// Pre-AUD-02 log with no counter; no output (not a failure for legacy logs).
	}

	if kc == nil {
		// Degraded result: chain walked but unauthenticated. Exit non-zero so
		// scripts do not treat an unverified log as fully trusted (WR-02).
		return &exitError{code: exitCodeError}
	}
	// AUD-02: CounterStatus="unknown" is not a clean result — exit non-zero so
	// scripts cannot treat an unverified tail-truncation check as fully trusted.
	if result.CounterStatus == "unknown" {
		return &exitError{code: exitCodeError}
	}
	return nil
}

func newAuditVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit chain and aggregate the full security posture",
		Long: `Verify the tamper-evident audit log hash chain AND aggregate every
security-posture finding (doctor sec-* checks, audit/metrics/webui checks) into
a single read-only readout (SEC-01).

Exit codes:
  0  — clean: chain OK and no findings.
  1  — warnings only: chain OK, WARN findings present.
  2  — fatal: any FATAL finding OR the chain is broken.

Flags:
  --pentest        run the full sec-* suite (attempts sshd -T even when not root)
  --fix            apply mechanically-safe permission fixes (chmod 0600); the
                   change is a dry-run preview unless --apply is also set. Never
                   edits sshd_config.
  --format=json    emit a machine-parseable JSON array of findings (read-only)`,
		Example: `  # Aggregate read-only security posture (exit 0/1/2)
  abysslink audit verify

  # Full sec-* suite including sshd -T attempts
  abysslink audit verify --pentest

  # Preview the mechanically-safe permission fixes (dry-run)
  abysslink audit verify --fix

  # Apply the permission fixes
  abysslink audit verify --fix --apply

  # Machine-parseable JSON array of findings
  abysslink audit verify --format=json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			pentest, _ := cmd.Flags().GetBool("pentest")
			fix, _ := cmd.Flags().GetBool("fix")
			format, _ := cmd.Flags().GetString("format")
			// IN-01: reject unknown --format values rather than silently falling
			// back to human output (a script piping "JSON" would get ANSI text).
			if format != "" && format != "json" {
				return fmt.Errorf("unsupported --format %q (only \"json\")", format)
			}
			// --format=json forces a JSON printer even when the root --json flag
			// is absent, so the findings array reaches stdout (PrintJSON is a
			// no-op on the human printer).
			var p Printer
			if format == "json" {
				p = NewJSONPrinterTo(cmd.OutOrStdout(), cmd.ErrOrStderr())
			} else {
				p = newPrinter(cmd)
			}
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit verify: %w", err)
			}
			opts := aggregateOpts{pentest: pentest, fix: fix, format: format, dryRun: cc.dryRun}
			return runAuditAggregate(ctx, cc, p, logPath, auditKeychain(ctx, cc), opts)
		},
	}
	cmd.Flags().Bool("pentest", false, "run the full sec-* suite (attempts sshd -T even when not root)")
	cmd.Flags().Bool("fix", false, "apply mechanically-safe permission fixes (chmod 0600); requires --apply to mutate")
	cmd.Flags().String("format", "", "output format: \"json\" emits a machine-parseable findings array")
	return cmd
}

// stderrOnlyPrinter wraps a Printer and redirects Print (stdout) to Error
// (stderr). It is used in --format=json mode so the chain-verify info banner
// never pollutes the JSON-array stdout payload. PrintJSON is suppressed (the
// aggregate emits the single canonical JSON array itself).
type stderrOnlyPrinter struct{ inner Printer }

func (s stderrOnlyPrinter) Print(msg string)         { s.inner.Error(msg) }
func (s stderrOnlyPrinter) Printv(key, value string) { s.inner.Error(key + ": " + value) }
func (s stderrOnlyPrinter) Error(msg string)         { s.inner.Error(msg) }
func (s stderrOnlyPrinter) PrintJSON(_ any)          {}

// aggregateOpts carries the audit-verify aggregate flags. dryRun mirrors the
// root --apply gate (true when --apply is absent): the --fix path only mutates
// permissions when dryRun is false.
type aggregateOpts struct {
	pentest bool
	fix     bool
	format  string
	dryRun  bool
}

// runAuditAggregate is the SEC-01 read-only security-posture aggregate. It runs
// the chain-integrity check FIRST (propagating immediately on a break — exit 2,
// RESEARCH Pitfall 7), then collects every doctor finding source exactly once,
// dedups by check ID, and rolls the severities up into an exit code. With
// --format=json it emits the findings as a JSON array; with --fix it applies the
// mechanically-safe permission fixes (gated by --apply via opts.dryRun).
func runAuditAggregate(ctx context.Context, cc *cmdContext, p Printer, logPath string, kc audit.KeychainStore, opts aggregateOpts) error {
	// 1. Chain integrity first. A break is exit 2; do NOT collect findings after.
	// In --format=json mode the chain-OK info banner must not pollute stdout (the
	// JSON array is the only stdout payload), so route the verify step's Printer
	// output to stderr. Chain-break errors are still surfaced (stderr) and the
	// exit code is unchanged.
	verifyP := p
	if opts.format == "json" {
		verifyP = stderrOnlyPrinter{inner: p}
	}
	// degradedCode records a non-fatal verify result (exit 1: kc==nil walk or
	// CounterStatus "unknown") so the final exit code can never roll back to 0
	// purely on the strength of the findings (WR-02/AUD-02: a skipped HMAC or
	// tail-truncation check is not a clean result).
	degradedCode, fatalErr := auditVerifyStepCode(ctx, verifyP, logPath, kc)
	if fatalErr != nil {
		return fatalErr // CHAIN BROKEN — propagate exit 2 immediately.
	}

	// 2. Obtain deps with graceful degradation (mirrors cmd_doctor.go).
	deps, depsErr := buildDeps(ctx, cc)
	if depsErr != nil {
		slog.Warn("audit-aggregate: deps unavailable; sec checks will degrade", "err", depsErr)
		deps = modules.Deps{}
	}

	// 3. Collect every finding source exactly once (run-once pattern).
	allFindings := collectAggregateFindings(ctx, cc, deps, opts.pentest, logPath)

	// 4. Dedup by check ID (first occurrence wins).
	allFindings = dedupFindings(allFindings)

	// 5. --fix: apply mechanically-safe permission fixes (gated by --apply).
	if opts.fix {
		runAuditFix(ctx, p, logPath, kc, opts.dryRun)
	}

	// 6. --format=json: emit a machine-parseable JSON array and roll up.
	if opts.format == "json" {
		p.PrintJSON(buildDoctorFindings(allFindings))
		return exitCodeToError(maxExitCode(degradedCode, aggregateExitCode(allFindings)))
	}

	// 7. Human output + severity roll-up (never below the degraded verify code).
	if len(allFindings) == 0 {
		printerInfo(p, "All checks passed — security posture is clean.")
		return exitCodeToError(degradedCode)
	}
	doctorHumanOutput(p, allFindings)
	printerInfo(p, doctorSeverityCounts(allFindings))
	return exitCodeToError(maxExitCode(degradedCode, aggregateExitCode(allFindings)))
}

// maxExitCode returns the more severe of two roll-up exit codes.
func maxExitCode(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// auditVerifyStepCode runs the chain-verify step for the aggregate and maps
// its outcome: a FATAL chain break is returned as fatalErr (the aggregate
// aborts with exit 2 immediately); any non-fatal degradation (kc==nil walk,
// CounterStatus "unknown", parse/IO failure) is returned as a degraded exit
// code that the aggregate roll-up must never undercut (WR-02/AUD-02).
func auditVerifyStepCode(ctx context.Context, p Printer, logPath string, kc audit.KeychainStore) (degraded int, fatalErr error) {
	err := runAuditVerify(ctx, p, logPath, kc)
	if err == nil {
		return exitCodeOK, nil
	}
	var ee *exitError
	switch {
	case errors.As(err, &ee) && ee.ExitCode() == exitCodeFatal:
		return exitCodeFatal, err
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	default:
		// Parse/IO failure in the verify step: still a degraded posture.
		return exitCodeError, nil
	}
}

// collectAggregateFindings runs every doctor finding source exactly once and
// returns the concatenated slice. The 3 sec-* cross-ref aliases reuse the
// pre-computed met/webui/audit slices so the underlying checks run once
// (RESEARCH Pitfall 3).
func collectAggregateFindings(ctx context.Context, cc *cmdContext, deps modules.Deps, pentest bool, logPath string) []modules.Finding {
	var all []modules.Finding

	// Module-runner doctor pass (best-effort; nil deps degrade gracefully).
	if r, rerr := modules.NewRunner(allModules(deps), cc.cfg); rerr == nil {
		if mf, derr := r.Doctor(ctx); derr == nil {
			all = append(all, mf...)
		} else {
			slog.Warn("audit-aggregate: module doctor pass failed", "err", derr)
		}
	}

	// Backend + fleet findings.
	all = appendBackendAndFleetFindings(ctx, cc, deps.Keychain, all)

	// Supply-chain advisories.
	all = append(all, supplyChainFindings(ctx, cc.runner, version, "")...)

	// Audit posture (Phase 17) — captured for the sec-audit-anchor-age alias.
	auditFinds := auditDoctorFindings(logPath, deps.Keychain)
	all = append(all, auditFinds...)

	// Metrics posture (Phase 18) — captured for the sec-metrics-bind alias.
	metFinds := metricsDoctorFindings(cc.cfg, deps.MetricsRegistry(), resolveTailnetIP(ctx, cc))
	all = append(all, metFinds...)

	// Web UI posture (Phase 19) — captured for the sec-webui-bind alias.
	webuiFinds := webuiDoctorFindings(ctx, cc.cfg)
	all = append(all, webuiFinds...)

	// 18 sec-* checks; the 3 aliases reuse the slices above (run-once).
	all = append(all, secDoctorFindings(ctx, cc, deps, pentest, metFinds, webuiFinds, auditFinds)...)

	// Phase 21 optional-module posture (MOD3-01..05): wol-apply-gate,
	// upsnap-bind/no-public, atuin-bind/key-backed-up, asciinema-rec-warning,
	// sandbox-landlock-supported, nb-posture-active. Mirrors cmd_doctor.go RunE
	// (B1): without this the aggregate silently dropped all 9 Phase-21 checks.
	all = append(all, mod3DoctorFindings(ctx, cc.cfg, cc.runner)...)

	return all
}

// dedupFindings collapses findings sharing a check ID, keeping the first
// occurrence. The doctor pattern already avoids duplicates by design; this
// guards the aggregate's run-once contract explicitly (RESEARCH Pitfall 3).
func dedupFindings(in []modules.Finding) []modules.Finding {
	seen := make(map[string]bool, len(in))
	out := make([]modules.Finding, 0, len(in))
	for _, f := range in {
		if seen[f.Check] {
			continue
		}
		seen[f.Check] = true
		out = append(out, f)
	}
	return out
}

// aggregateExitCode rolls findings up into an exit code: any FATAL → 2, any
// WARN → 1, else 0 (RESEARCH Pattern 3 exit-code design).
func aggregateExitCode(findings []modules.Finding) int {
	code := exitCodeOK
	for _, f := range findings {
		switch f.Severity {
		case modules.SeverityFatal:
			return exitCodeFatal
		case modules.SeverityWarning:
			code = exitCodeError
		case modules.SeverityOK:
			// no-op
		}
	}
	return code
}

// exitCodeToError maps a roll-up exit code to a RunE return value (nil for 0,
// an *exitError otherwise) so cobra exits with the right process code.
func exitCodeToError(code int) error {
	if code == exitCodeOK {
		return nil
	}
	return &exitError{code: code}
}

// runAuditFix applies (or, when dryRun, previews) the mechanically-safe
// permission fixes: tighten the audit log, any world/group-writable config
// file, and the daemon socket to 0600. A real chmod (--apply) is recorded in
// the audit log AFTER it succeeds, via the chain-correct writer (CLAUDE.md hard
// rule). A dry-run is a pure read-only preview: it prints what WOULD change and
// records nothing (CR-01/WR-01 — recording a dry-run with the unsigned writer
// broke the signed hash chain, and even a chain-correct dry-run record would
// make a read-only preview non-idempotent and grow the log unbounded).
//
// kc selects the writer: when a keychain is present the production log is a
// signed hash chain, so the record MUST extend it via the signed writer; only a
// genuinely unsigned legacy log (kc == nil) uses the unsigned writer. This
// mirrors buildDeps so a sec-fix entry is never an unsigned entry injected into
// a signed chain (which audit.Verify reports as CHAIN BROKEN).
//
// T-20-03-01: every fix target is derived from a trusted source function
// (logPath argument / abysslinkConfigDir() / daemon.SocketPath()) — never parsed
// from a Finding.Message — so a crafted finding cannot redirect a chmod.
func runAuditFix(ctx context.Context, p Printer, logPath string, kc audit.KeychainStore, dryRun bool) {
	// 1. Audit log perms.
	if logPath != "" {
		if fi, err := os.Stat(logPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
			secFixChmod(ctx, p, logPath, logPath, kc, dryRun)
		}
	}

	// 2. Group/other-accessible config files (re-walk the trusted config dir).
	// Mirror secNoWorldReadableConfigCheckDir's looseConfigBits (0o077) so --fix
	// tightens exactly what the sec-no-world-readable-config check flags (WR-03).
	if dir := abysslinkConfigDir(); dir != "" {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			fi, ferr := d.Info()
			if ferr != nil {
				return nil
			}
			if fi.Mode().Perm()&looseConfigBits != 0 {
				secFixChmod(ctx, p, logPath, path, kc, dryRun)
			}
			return nil
		})
	}

	// 3. Daemon socket perms (durable fix is a daemon restart).
	if sock := daemon.SocketPath(); sock != "" {
		if fi, err := os.Stat(sock); err == nil && fi.Mode().Perm()&0o077 != 0 {
			if secFixChmod(ctx, p, logPath, sock, kc, dryRun) {
				printerInfo(p, "note: restart abysslinkd — the socket is recreated on restart, so the durable fix is a restart")
			}
		}
	}
}

// secFixChmod tightens path to 0600 when dryRun is false, then records the
// mutation in the audit log. It REFUSES any path containing "sshd" (CONTEXT:
// --fix never edits sshd config; T-20-03-01). Returns true when a chmod was
// applied (or, in dry-run, would be applied).
//
// CR-01: the audit record is written ONLY on --apply, ONLY after the chmod
// actually succeeds, and through the chain-correct writer (the signed writer
// when a keychain is present, the unsigned writer only for a genuinely unsigned
// legacy log). A dry-run is a pure read-only preview that writes NOTHING to the
// log — both because a chain-correct dry-run record would make the preview
// non-idempotent (WR-01) and because the prior unsigned dry-run append poisoned
// the signed chain (CHAIN BROKEN on the next verify). The audit-after-chmod
// ordering is acceptable here: chmod is reversible (re-runnable) and a crash
// between the chmod and the append leaves the file correctly tightened, not in a
// dangerous lax state — the opposite risk profile from a content WriteFile.
func secFixChmod(ctx context.Context, p Printer, logPath, path string, kc audit.KeychainStore, dryRun bool) bool {
	if strings.Contains(path, "sshd") {
		slog.Warn("sec-fix: refusing to touch sshd config", "path", path)
		printerError(p, "sec-fix: refusing to chmod sshd config "+path+" — edit it manually")
		return false
	}
	if dryRun {
		// Pure read-only preview: print what WOULD change, record nothing.
		printerInfo(p, "sec-fix: would chmod 0600 "+path+" (run with --apply to apply)")
		return true
	}
	if cerr := secChmodNoFollow(path, 0o600); cerr != nil {
		printerError(p, "sec-fix: chmod failed for "+path+": "+cerr.Error())
		return false
	}
	// Record the applied mutation AFTER the chmod succeeds, through the
	// chain-correct writer so a signed chain is only ever extended by the signed
	// writer (never an unsigned entry injected into a signed chain — CR-01).
	if aerr := appendSecFixRecord(ctx, kc, logPath, path); aerr != nil {
		// The chmod already succeeded and is durable; surface the audit failure
		// but do not report the chmod as un-applied.
		printerError(p, "sec-fix: chmod 0600 "+path+" applied but audit append failed: "+aerr.Error())
		return true
	}
	printerInfo(p, "sec-fix: chmod 0600 "+path)
	return true
}

// appendSecFixRecord records an applied sec-fix chmod in the RESOLVED audit log
// (logPath — the same chain audit verify walks, not necessarily
// DefaultLogPath()) via the chain-correct writer. With a keychain it extends the
// signed hash chain (audit.NewSigned — the key already exists for a signed
// install, so no key is rotated); without one it appends to a genuinely
// unsigned legacy log (audit.New). The target carries the path; no file content
// is recorded.
func appendSecFixRecord(ctx context.Context, kc audit.KeychainStore, logPath, path string) error {
	if logPath == "" {
		return fmt.Errorf("audit log path is empty")
	}
	if kc != nil {
		sa, saErr := audit.NewSigned(logPath, kc)
		if saErr != nil {
			return fmt.Errorf("signed audit writer: %w", saErr)
		}
		return sa.Append(ctx, audit.SignInput{
			Title:    "sec-fix",
			DiffHash: sha256.Sum256([]byte("chmod:" + path)),
		}, "chmod:"+path, false)
	}
	return audit.New(logPath).Append("sec-fix", "chmod:"+path, nil, false)
}

// secChmodNoFollow tightens path's permissions without following symlinks
// (WR-02). --fix exists to remediate a config dir that is already
// group/other-accessible, so an attacker with write access to that dir could,
// between the enumerating walk and the chmod, swap a flagged regular file for a
// symlink to a sensitive target (e.g. ~/.ssh/authorized_keys) and redirect the
// chmod. The plain os.Chmod follows symlinks, so we:
//
//  1. Lstat the path immediately before acting and REFUSE if it is now a symlink.
//  2. For regular files, open with O_NOFOLLOW and fchmod the resulting fd — the
//     kernel guarantees the fd refers to the inode that passed the lstat, closing
//     the residual lstat→chmod race entirely.
//
// Non-regular targets (the daemon socket) cannot be opened O_RDONLY, so they
// fall back to a plain chmod after the symlink guard; the lstat→chmod window is
// acceptable there because the socket lives in a daemon-owned runtime dir, not
// the user-writable config dir, and the symlink guard still blocks redirection.
func secChmodNoFollow(path string, mode os.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to chmod %s: path is a symlink (possible TOCTOU swap)", path)
	}
	if !fi.Mode().IsRegular() {
		// Socket / device / etc.: cannot O_NOFOLLOW-open for fchmod; the symlink
		// guard above already blocked the redirection case.
		return os.Chmod(path, mode)
	}
	// #nosec G304 -- path is derived from trusted source functions (audit log
	// path / abysslinkConfigDir() / daemon.SocketPath()), never from a
	// Finding.Message (T-20-03-01); O_NOFOLLOW additionally refuses any symlink
	// swapped in after the enumerating walk (WR-02).
	fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("refusing to chmod %s: open O_NOFOLLOW failed (replaced or symlink): %w", path, err)
	}
	defer func() { _ = fd.Close() }()
	return fd.Chmod(mode)
}

// tailEntries returns the last n entries of the log. A missing log yields an
// empty slice; n <= 0 or n > len returns all entries.
func tailEntries(logPath string, n int) ([]audit.Entry, error) {
	entries, err := audit.ReadLog(logPath)
	if err != nil {
		return nil, err
	}
	if n <= 0 || n > len(entries) {
		return entries, nil
	}
	return entries[len(entries)-n:], nil
}

// renderEntryTable prints a human-readable table of entries via the Printer.
func renderEntryTable(p Printer, entries []audit.Entry) {
	printerInfo(p, fmt.Sprintf("%-20s  %-8s  %-40s  %s", "TIME", "OP", "TARGET", "DRY_RUN"))
	for _, e := range entries {
		printerInfo(p, fmt.Sprintf("%-20s  %-8s  %-40s  %v",
			e.Time.Format("2006-01-02 15:04:05"), e.Op, e.Target, e.DryRun))
	}
}

// runAuditTail renders the last n entries (table or --json array).
func runAuditTail(p Printer, logPath string, n int, jsonOut bool) error {
	entries, err := tailEntries(logPath, n)
	if err != nil {
		return fmt.Errorf("audit tail: %w", err)
	}
	if len(entries) == 0 {
		printerInfo(p, "No audit entries found")
		return nil
	}
	if jsonOut {
		p.PrintJSON(entries)
		return nil
	}
	renderEntryTable(p, entries)
	return nil
}

func newAuditTailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent audit log entries (default 20)",
		Example: `  # Show the last 20 audit entries
  abysslink audit tail

  # Show the last 5 entries as JSON
  abysslink audit tail --n 5 --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			n, _ := cmd.Flags().GetInt("n")
			jsonOut, _ := cmd.Flags().GetBool("json")
			p := newPrinter(cmd)
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit tail: %w", err)
			}
			return runAuditTail(p, logPath, n, jsonOut)
		},
	}
	cmd.Flags().Int("n", 20, "number of trailing entries to show")
	return cmd
}

// runAuditLs renders all entries (table or --json array).
func runAuditLs(p Printer, logPath string, jsonOut bool) error {
	entries, err := audit.ReadLog(logPath)
	if err != nil {
		return fmt.Errorf("audit ls: %w", err)
	}
	if len(entries) == 0 {
		printerInfo(p, "No audit entries found")
		return nil
	}
	if jsonOut {
		p.PrintJSON(entries)
		return nil
	}
	renderEntryTable(p, entries)
	return nil
}

func newAuditLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List every audit log entry",
		Example: `  # List all audit entries as a table
  abysslink audit ls`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			jsonOut, _ := cmd.Flags().GetBool("json")
			p := newPrinter(cmd)
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit ls: %w", err)
			}
			return runAuditLs(p, logPath, jsonOut)
		},
	}
}

// runAuditExport writes raw JSONL entries (one json object per line) to w.
// Export is for machine consumption, so JSONL is the canonical output regardless
// of the --json flag. A missing log produces no output (empty export).
func runAuditExport(w io.Writer, logPath string) error {
	entries, err := audit.ReadLog(logPath)
	if err != nil {
		return fmt.Errorf("audit export: %w", err)
	}
	for _, e := range entries {
		line, merr := json.Marshal(e)
		if merr != nil {
			return fmt.Errorf("audit export: marshal entry: %w", merr)
		}
		if _, werr := fmt.Fprintf(w, "%s\n", line); werr != nil {
			return fmt.Errorf("audit export: write: %w", werr)
		}
	}
	return nil
}

func newAuditExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export every audit log entry as raw JSONL (one object per line)",
		Example: `  # Export the full audit log as JSONL for archival or analysis
  abysslink audit export > audit.jsonl`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit export: %w", err)
			}
			return runAuditExport(cmd.OutOrStdout(), logPath)
		},
	}
}
