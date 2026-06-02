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
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/metrics"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// auditDefaultLogPath is a package var so the doctor RunE can resolve the audit
// log path; indirection keeps it swappable in focused tests.
var auditDefaultLogPath = audit.DefaultLogPath

// auditDoctorFindings runs the three Phase 17 tamper-evident audit posture
// checks against logPath. kc may be nil (no keychain backend); the keychain
// check fails closed in that case.
//
//   - audit-keychain (FATAL): the signed audit path cannot reach the keychain
//     (kc nil or audit.NewSigned fails) — signed entries cannot be written.
//   - audit-anchor-age (WARN): newest anchor.json is missing or older than 24h —
//     the daemon may not be running / anchor writes are failing.
//   - audit-count-vs-anchor (FATAL): the log holds fewer entries than the anchor
//     records — truncation detected.
//
// T-17-10: error messages describe the failure class only; key material is never
// logged. T-17-13: a brand-new install with no anchor emits WARN, never FATAL.
func auditDoctorFindings(ctx context.Context, logPath string, kc secrets.KeychainStore) []modules.Finding {
	var findings []modules.Finding

	// Check 1 — audit-keychain (FATAL when the signed path cannot reach the keychain).
	if kc == nil {
		findings = append(findings, modules.Finding{
			Module:   "audit",
			Check:    "audit-keychain",
			Severity: modules.SeverityFatal,
			Message:  "HMAC signing key unavailable — keychain not accessible; signed entries cannot be written (AUD-02)",
		})
	} else if _, err := audit.NewSigned(logPath, kc); err != nil {
		findings = append(findings, modules.Finding{
			Module:   "audit",
			Check:    "audit-keychain",
			Severity: modules.SeverityFatal,
			Message:  "HMAC signing key unavailable — keychain not accessible; signed entries cannot be written (AUD-02)",
		})
	}

	anchor, err := audit.ReadAnchor(logPath)
	if err != nil {
		slog.Warn("doctor: read audit anchor failed", "err", err)
		return findings
	}

	// Check 2 — audit-anchor-age (WARN when missing or > 24h old).
	switch {
	case anchor == nil:
		findings = append(findings, modules.Finding{
			Module:   "audit",
			Check:    "audit-anchor-age",
			Severity: modules.SeverityWarning,
			Message:  "No audit anchor found — run `abysslink up --apply` or start the daemon to create one",
		})
	default:
		if anchorTime, perr := time.Parse(time.RFC3339, anchor.Time); perr == nil {
			if age := time.Since(anchorTime); age > 24*time.Hour {
				findings = append(findings, modules.Finding{
					Module:   "audit",
					Check:    "audit-anchor-age",
					Severity: modules.SeverityWarning,
					Message: fmt.Sprintf(
						"Audit anchor is %s old (threshold 24h) — daemon may not be running or anchor writes are failing",
						age.Round(time.Minute)),
				})
			}
		} else {
			slog.Warn("doctor: parse anchor time failed", "err", perr)
		}
	}

	// Check 3 — audit-count-vs-anchor (FATAL when the log is shorter than the anchor).
	if anchor != nil {
		// CR-01: the anchor's EntryCount is only trustworthy if its HMAC is
		// valid. A local attacker can rewrite audit.anchor.json with a smaller
		// EntryCount to hide truncation; without authenticating the HMAC the
		// count comparison is meaningless. A forged/unsigned anchor is itself a
		// tamper signal and must be reported FATAL, not silently trusted. We can
		// only authenticate when a keychain is available.
		if kc == nil {
			findings = append(findings, modules.Finding{
				Module:   "audit",
				Check:    "audit-count-vs-anchor",
				Severity: modules.SeverityFatal,
				Message:  "Audit anchor cannot be authenticated — keychain unavailable; anchor HMAC unverifiable (AUD-02)",
			})
			return findings
		}
		anchorOK, verr := audit.VerifyAnchor(logPath, kc)
		if verr != nil {
			slog.Warn("doctor: verify audit anchor failed", "err", verr)
			return findings
		}
		if !anchorOK {
			findings = append(findings, modules.Finding{
				Module:   "audit",
				Check:    "audit-count-vs-anchor",
				Severity: modules.SeverityFatal,
				Message:  "Audit anchor HMAC is invalid — anchor forged or tampered (truncation detection compromised)",
			})
			return findings
		}
		entries, rerr := audit.ReadLog(logPath)
		if rerr != nil {
			slog.Warn("doctor: read audit log failed", "err", rerr)
			return findings
		}
		if int64(len(entries)) < anchor.EntryCount {
			findings = append(findings, modules.Finding{
				Module:   "audit",
				Check:    "audit-count-vs-anchor",
				Severity: modules.SeverityFatal,
				Message: fmt.Sprintf(
					"Audit log has %d entries but anchor records %d — truncation detected",
					len(entries), anchor.EntryCount),
			})
		}
	}

	return findings
}

// metricsDoctorFindings runs the four Phase 18 observability posture checks
// against the metrics config and the live registry. All checks are read-only.
//
//   - metrics-bind-tailnet (FATAL): metrics enabled with a bind_addr containing
//     0.0.0.0 or :: — the endpoint must bind the tailnet IP only (OBS-03).
//   - met-label-audit (FATAL): a metric series carries a label name outside the
//     compile-time allowlist {severity,check_id,backend,result,rig} (OBS-04).
//   - met-cardinality (WARN): more than 500 unique (name, label-set) series —
//     cardinality-explosion risk (OBS-04).
//   - met-disabled-listener (FATAL): metrics disabled but the configured port is
//     still accepting connections (stale listener) — probed via net.DialTimeout
//     with a 200ms timeout, no shellout (OBS-05).
func metricsDoctorFindings(cfg *config.Config, reg metrics.Registry) []modules.Finding {
	return []modules.Finding{
		metBindTailnetCheck(cfg),
		metLabelAuditCheck(reg),
		metCardinalityCheck(reg),
		metDisabledListenerCheck(cfg),
	}
}

// metBindTailnetCheck enforces the OBS-03 tailnet-only bind floor.
func metBindTailnetCheck(cfg *config.Config) modules.Finding {
	const check = "metrics-bind-tailnet"
	addr := cfg.Observability.Metrics.BindAddr
	if cfg.Observability.Metrics.Enabled && addr != "" &&
		(strings.Contains(addr, "0.0.0.0") || strings.Contains(addr, "::")) {
		return modules.Finding{
			Module:   "metrics",
			Check:    check,
			Severity: modules.SeverityFatal,
			Message:  "observability.metrics.bind_addr must be tailnet IP only — 0.0.0.0/:: is forbidden (OBS-03)",
		}
	}
	return modules.Finding{Module: "metrics", Check: check, Severity: modules.SeverityOK, Message: "metrics bind address is tailnet-scoped"}
}

// metLabelAuditCheck flags any series whose label names fall outside the
// compile-time allowlist (collapsed to "other" by SanitizeLabel).
func metLabelAuditCheck(reg metrics.Registry) modules.Finding {
	const check = "met-label-audit"
	for _, fam := range reg.Snapshot() {
		for _, sample := range fam.Samples {
			for key := range sample.Labels {
				if metrics.SanitizeLabel(key) == "other" {
					return modules.Finding{
						Module:   "metrics",
						Check:    check,
						Severity: modules.SeverityFatal,
						Message: fmt.Sprintf(
							"unlisted label name %q found in metric %q — only {severity,check_id,backend,result,rig} are permitted (OBS-04)",
							key, fam.Name),
					}
				}
			}
		}
	}
	return modules.Finding{Module: "metrics", Check: check, Severity: modules.SeverityOK, Message: "all metric labels are within the allowlist"}
}

// metCardinalityCheck WARNs when the registry holds more than 500 unique series.
func metCardinalityCheck(reg metrics.Registry) modules.Finding {
	const check = "met-cardinality"
	if n := countMetricSeries(reg); n > 500 {
		return modules.Finding{
			Module:   "metrics",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("met-cardinality: %d series exceeds 500 — risk of cardinality explosion (OBS-04)", n),
		}
	}
	return modules.Finding{Module: "metrics", Check: check, Severity: modules.SeverityOK, Message: "metric series count is within budget"}
}

// metDisabledListenerCheck FATALs when metrics are disabled but the configured
// port is still listening. The probe uses net.DialTimeout (200ms) — never a
// ss/lsof shellout (OBS-05). Disable is restart-scoped: this verifies the port
// stays closed after a restart with enabled=false.
func metDisabledListenerCheck(cfg *config.Config) modules.Finding {
	const check = "met-disabled-listener"
	if cfg.Observability.Metrics.Enabled {
		return modules.Finding{Module: "metrics", Check: check, Severity: modules.SeverityOK, Message: "metrics enabled — listener probe not applicable"}
	}
	addr := cfg.Observability.Metrics.BindAddr
	if addr == "" {
		port := cfg.Observability.Metrics.Port
		if port <= 0 {
			port = 9090
		}
		addr = fmt.Sprintf(":%d", port)
	}
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return modules.Finding{
			Module:   "metrics",
			Check:    check,
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("port %s is listening but metrics.enabled=false — stale listener (OBS-05)", addr),
		}
	}
	return modules.Finding{Module: "metrics", Check: check, Severity: modules.SeverityOK, Message: "no stale metrics listener detected"}
}

// countMetricSeries returns the number of unique (metric name, sorted label-set)
// tuples across all registered families — the Prometheus time-series definition.
func countMetricSeries(reg metrics.Registry) int {
	seen := make(map[string]struct{})
	formatCanonicalKey := func(name string, labels map[string]string) string {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString(name)
		for _, k := range keys {
			b.WriteString("|")
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(labels[k])
		}
		return b.String()
	}
	for _, fam := range reg.Snapshot() {
		for _, sample := range fam.Samples {
			seen[formatCanonicalKey(fam.Name, sample.Labels)] = struct{}{}
		}
	}
	return len(seen)
}

// fleetKeychain is the subset of secrets.KeychainStore consumed by the fleet
// doctor helpers (avoids exposing secrets package import in the helper signature).
type fleetKeychain = secrets.KeychainStore

// doctorFinding is the JSON record emitted per finding under --json.
// Fields match the documented schema: module, check, severity, message, fix.
// Severity is a lowercase string: "ok" | "warn" | "fatal".
type doctorFinding struct {
	Module   string `json:"module"`
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

// buildDoctorFindings converts a slice of modules.Finding to the JSON-safe
// []doctorFinding slice. Severity is mapped to a lowercase string so JSON
// consumers get a stable, documented enum value, not an integer.
func buildDoctorFindings(findings []modules.Finding) []doctorFinding {
	records := make([]doctorFinding, 0, len(findings))
	for _, f := range findings {
		records = append(records, doctorFinding{
			Module:   f.Module,
			Check:    f.Check,
			Severity: severityString(f.Severity),
			Message:  f.Message,
			Fix:      findingFix(f.Check),
		})
	}
	return records
}

// severityString maps a modules.Severity int to its documented lowercase string.
func severityString(s modules.Severity) string {
	switch s {
	case modules.SeverityOK:
		return "ok"
	case modules.SeverityWarning:
		return "warn"
	case modules.SeverityFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// doctorSeverityCounts returns a summary count line "N ok · M warn · K fatal"
// for the human-readable footer. Icon+word conveys severity without colour alone (§10).
func doctorSeverityCounts(findings []modules.Finding) string {
	var nOK, nWarn, nFatal int
	for _, f := range findings {
		switch f.Severity {
		case modules.SeverityOK:
			nOK++
		case modules.SeverityWarning:
			nWarn++
		case modules.SeverityFatal:
			nFatal++
		}
	}
	return fmt.Sprintf("  %s %d ok · %s %d warn · %s %d fatal",
		iconDoneStr(), nOK,
		iconWarnStr(), nWarn,
		iconFatalStr(), nFatal,
	)
}

// doctorHumanOutput renders findings grouped by module and prints them via p.
// Returns (hasFatal, hasWarn).
func doctorHumanOutput(p Printer, findings []modules.Finding) (hasFatal, hasWarn bool) {
	// Group findings by module.
	seenMod := map[string]bool{}
	for _, f := range findings {
		if !seenMod[f.Module] {
			seenMod[f.Module] = true
			printerInfo(p, styleMuted.Render("  "+strings.Repeat("─", 50)))
			printerInfo(p, "  "+styleBold.Render(f.Module))
		}

		switch f.Severity {
		case modules.SeverityOK:
			printerInfo(p, fmt.Sprintf("    %s  %s",
				iconDoneStr(),
				styleMuted.Render(f.Check)))
		case modules.SeverityWarning:
			hasWarn = true
			fix := findingFix(f.Check)
			msg := fmt.Sprintf("    %s  %s  %s  %s",
				iconWarnStr(), styleWarn.Render("WARN"), styleBold.Render(f.Check),
				styleMuted.Render(f.Message))
			if fix != "" {
				msg += "\n       " + styleCode.Render("fix: "+fix)
			}
			printerInfo(p, msg)
		case modules.SeverityFatal:
			hasFatal = true
			fix := findingFix(f.Check)
			msg := fmt.Sprintf("    %s  %s  %s  %s",
				iconFatalStr(), styleFatal.Render("FATAL"), styleBold.Render(f.Check), f.Message)
			if fix != "" {
				msg += "\n       " + styleCode.Render("fix: "+fix)
			}
			printerInfo(p, msg)
		}
	}
	return hasFatal, hasWarn
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Exhaustive verification of all modules and security posture",
		Long: `Run exhaustive checks across all Abysslink modules and report
the system health. Findings are grouped by module with icon+word
severity labels (no colour dependency).

Exit codes:
  0  — OK: all checks passed.
  1  — Warning: issues found; system is operable but review recommended.
  2  — Fatal: fail-closed or fatal issue; system is not safe to use.`,
		Example: `  # Human-readable deep health check
  abysslink doctor

  # Machine-readable JSON array of findings (ANSI-free)
  abysslink --json doctor

  # Get fix guidance for a single module
  abysslink doctor | grep tailscale`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			if !cc.jsonOut {
				header := styleBold.Render("abysslink doctor") + "  " + styleMuted.Render("health check")
				printerInfo(p, styleHeaderBox.Render(header))
				printerInfo(p, "")
				emitSecurityNote(p, cc.jsonOut, "doctor-not-full-audit") // §7 note 11
				emitSecurityNote(p, cc.jsonOut, "no-funnel")             // §7 note 8
				printerInfo(p, "")
			}

			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("doctor: %w", err)
			}
			mods := allModules(deps)
			r, err := modules.NewRunner(mods, cc.cfg)
			if err != nil {
				return err
			}

			findings, err := r.Doctor(ctx)
			if err != nil {
				return fmt.Errorf("doctor: %w", err)
			}

			// Backend-specific + fleet: append all backend and fleet findings.
			findings = appendBackendAndFleetFindings(ctx, cc, deps.Keychain, findings)

			// Supply-chain integrity advisories (cosign v3 bundle + SLSA provenance).
			findings = append(findings, supplyChainFindings(ctx, cc.runner, version, "")...)

			// Tamper-evident audit-log posture (anchor age, count-vs-anchor, keychain).
			if logPath, lpErr := auditDefaultLogPath(); lpErr == nil {
				findings = append(findings, auditDoctorFindings(ctx, logPath, deps.Keychain)...)
			} else {
				slog.Warn("doctor: audit log path unavailable; skipping audit checks", "err", lpErr)
			}

			// Observability metrics posture (OBS-03/04/05): bind floor, label
			// allowlist, cardinality budget, and stale-listener probe.
			findings = append(findings, metricsDoctorFindings(cc.cfg, deps.MetricsRegistry())...)

			// --all-rigs: fan-out doctor --json to all enrolled rigs and merge findings.
			allRigsFlag, _ := cmd.Flags().GetBool("all-rigs")
			strictFlag, _ := cmd.Flags().GetBool("strict")
			if allRigsFlag && len(cc.cfg.Rigs) > 0 {
				var fanErr error
				findings, fanErr = appendAllRigsFindings(ctx, cc, findings, strictFlag)
				if fanErr != nil && strictFlag {
					return &exitError{code: exitCodeFatal}
				}
			}

			// --json: emit structured ANSI-free records.
			if cc.jsonOut {
				p.PrintJSON(buildDoctorFindings(findings))
				return nil
			}

			if len(findings) == 0 {
				printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("All checks passed. System is healthy."))
				printerInfo(p, "")
				return nil
			}

			hasFatal, hasWarn := doctorHumanOutput(p, findings)

			printerInfo(p, styleMuted.Render("  "+strings.Repeat("─", 50)))
			printerInfo(p, doctorSeverityCounts(findings))
			printerInfo(p, "")

			if hasFatal {
				printerInfo(p, "  "+iconFatalStr()+"  "+styleFatal.Render("FATAL  Fatal issues found — system is not safe."))
				printerInfo(p, "  "+styleMuted.Render("Run: abysslink repair --apply  to auto-fix what can be fixed."))
				printerInfo(p, "")
				return &exitError{code: exitCodeFatal}
			}
			if hasWarn {
				printerInfo(p, "  "+iconWarnStr()+"  "+styleWarn.Render("WARN  Warnings found — review the issues above."))
				printerInfo(p, "  "+styleMuted.Render("Run: abysslink repair --apply  to auto-fix what can be fixed."))
				printerInfo(p, "")
				return &exitError{code: exitCodeError}
			}
			return nil
		},
	}
}

// appendBackendAndFleetFindings combines the headscale, netbird, and fleet
// doctor finding appends. This consolidation keeps newDoctorCmd's RunE below
// the gocyclo < 15 threshold.
func appendBackendAndFleetFindings(ctx context.Context, cc *cmdContext, kc fleetKeychain, findings []modules.Finding) []modules.Finding {
	// Headscale backend: append hs-* doctor findings.
	if cc.cfg.Backend.Type == "headscale" {
		doReq := backend.NewHeadscaleDoRequest(cc.cfg, cc.runner)
		hsFindingsRaw, hsErr := backend.HeadscaleDoctorChecks(ctx, cc.cfg, cc.runner, doReq)
		if hsErr == nil {
			for _, hf := range hsFindingsRaw {
				findings = append(findings, modules.Finding{
					Module:   hf.Module,
					Check:    hf.Check,
					Severity: modules.Severity(hf.Severity),
					Message:  hf.Message,
				})
			}
		}
	}

	// NetBird backend: append nb-* doctor findings.
	if cc.cfg.Backend.Type == "netbird" {
		doReq := backend.NewNetBirdDoRequest(cc.cfg)
		nbFindingsRaw := backend.NetBirdDoctorChecks(ctx, cc.cfg, cc.runner, doReq)
		for _, nf := range nbFindingsRaw {
			findings = append(findings, modules.Finding{
				Module:   nf.Module,
				Check:    nf.Check,
				Severity: modules.Severity(nf.Severity),
				Message:  nf.Message,
			})
		}
	}

	// Fleet: append mr-* doctor findings when rigs are enrolled.
	return appendFleetFindings(ctx, cc, kc, findings)
}

// appendFleetFindings appends mr-* fleet isolation findings to findings when
// rigs are enrolled. Returns the extended slice (may be same slice if no rigs).
func appendFleetFindings(ctx context.Context, cc *cmdContext, kc fleetKeychain, findings []modules.Finding) []modules.Finding {
	if len(cc.cfg.Rigs) == 0 {
		return findings
	}
	b, _ := cc.backend()
	var aclMgr backend.ACLManager
	if b != nil {
		aclMgr, _ = b.(backend.ACLManager)
	}
	for _, mf := range fleet.DoctorChecks(ctx, cc.cfg, kc, aclMgr) {
		findings = append(findings, modules.Finding{
			Module:   mf.Module,
			Check:    mf.Check,
			Severity: modules.Severity(mf.Severity),
			Message:  mf.Message,
		})
	}
	return findings
}

// appendAllRigsFindings fans out `abysslink doctor --json` to all enrolled rigs,
// decodes the results, and merges them into findings with rig-prefixed Module names.
// UNREACHABLE rigs surface as findings; error is non-nil only under --strict.
func appendAllRigsFindings(ctx context.Context, cc *cmdContext, findings []modules.Finding, strict bool) ([]modules.Finding, error) {
	const perRigTimeout = 30 * time.Second
	results, fanErr := fleet.FanOut(ctx, cc.runner, cc.cfg.Rigs, perRigTimeout, strict, []string{"doctor", "--json"})
	for _, res := range results {
		if !res.Reachable {
			sev := modules.SeverityWarning
			if strict {
				sev = modules.SeverityFatal
			}
			findings = append(findings, modules.Finding{
				Module:   res.Rig.Name,
				Check:    "rig-reachable",
				Severity: sev,
				Message:  fmt.Sprintf("rig %q is UNREACHABLE — could not collect remote doctor findings", res.Rig.Name),
			})
			continue
		}
		remoteFindings, _, decErr := fleet.DecodeFindings(res)
		if decErr != nil {
			findings = append(findings, modules.Finding{
				Module:   res.Rig.Name,
				Check:    "rig-decode",
				Severity: modules.SeverityWarning,
				Message:  fmt.Sprintf("rig %q doctor output could not be decoded: %v", res.Rig.Name, decErr),
			})
			continue
		}
		for _, rf := range remoteFindings {
			findings = append(findings, modules.Finding{
				Module:   res.Rig.Name + "/" + rf.Module,
				Check:    rf.Check,
				Severity: remoteSeverity(rf.Severity),
				Message:  rf.Message,
			})
		}
	}
	return findings, fanErr
}

// findingFix maps a finding check name to a short remediation command or
// instruction. Returns "" when no specific guidance exists (generic repair
// message is shown instead).
func findingFix(check string) string {
	fixes := map[string]string{
		// Disk encryption.
		"filevault": "System Settings → Privacy & Security → FileVault → Turn On",
		"luks":      "Enable full-disk encryption (LUKS) before exposing remote access",
		// Firewall.
		"firewall":             "System Settings → Network → Firewall → Turn On  (macOS)",
		"application_firewall": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
		// SSH.
		"sshd_running": "sudo systemctl disable --now sshd  (Linux)  |  System Settings → General → Sharing → Remote Login → turn off  (macOS)",
		"checkperiod":  "Lower ssh_check_period in abysslink.yaml (max 12h)",
		// Tailscale.
		"needs_login":   "tailscale login",
		"ssh_sandboxed": "brew install tailscale  (replaces App Store version)",
		"installed":     "abysslink up --apply",
		// Tailnet Lock.
		"lock_enabled": "tailscale lock init   (then abysslink up --apply)",
		"lock_status":  "ensure tailscale is running: brew services restart tailscale",
		// Claude Code hooks.
		"stop_hook_configured":         "abysslink up --apply",
		"notification_hook_configured": "abysslink up --apply",
		"api_key_present":              "export ANTHROPIC_API_KEY=<key>  then  abysslink up --apply",
		"api_key_keychain":             "unlock your login keychain in Keychain Access.app",
		// ntfy.
		"ntfy_bind":  "abysslink up --apply  (ntfy must bind to tailnet IP, not 0.0.0.0)",
		"ntfy_admin": "abysslink up --apply",
		// Generic install / config.
		"not_installed":        "abysslink up --apply",
		"panes_configured":     "add panes to modules.watch.panes in abysslink.yaml",
		"claude_dir_exists":    "install Claude Code: npm i -g @anthropic-ai/claude-code",
		"settings_json_exists": "abysslink up --apply",
		// Headscale backend (hs-* checks).
		"hs-tls":             "Renew or replace the TLS certificate; ensure key file is 0600 owned by the service user",
		"hs-bind":            "Set metrics_listen_addr: 127.0.0.1:9090 and grpc_allow_insecure: false in Headscale config.yaml",
		"hs-api-auth":        "Rotate the Headscale API key: abysslink server headscale init --apply (re-init mints a new key)",
		"hs-key-expiry":      "Expire affected pre-auth keys via the Headscale admin panel or REST API; re-mint with explicit expiry",
		"hs-db-perms":        "chmod 0600 /var/lib/headscale/db.sqlite && chown headscale:headscale /var/lib/headscale/db.sqlite",
		"hs-lock":            "", // permanent WARN — Tailnet Lock (TKA) is not available on Headscale; no fix possible
		"hs-oidc-filter":     "Set oidc.allowed_domains or oidc.allowed_users in Headscale config.yaml to restrict OIDC registration",
		"hs-proc-user":       "Ensure Headscale runs as the dedicated service user: check systemd User= or launchd UserName= in the service unit",
		"hs-derp-failclosed": "Set derp.server.verify_clients: true in Headscale config.yaml (R-02 correct key)",
		// NetBird backend (nb-* checks).
		"nb-tls":       "Renew or replace the TLS certificate; ensure server.tls.certFile and server.tls.keyFile are set in NetBird config.yaml",
		"nb-version":   "Upgrade netbird-server to >= v0.57.0 (CVE-2025-10678 fix): abysslink server netbird upgrade --binary-path /path/to/new-binary --apply",
		"nb-zitadel":   "Remove the default ZITADEL admin account: run the ZITADEL cleanup script to delete zitadel-admin@ user",
		"nb-mgmt-bind": "Set metricsListenAddress: 127.0.0.1:9090 in NetBird config.yaml to prevent public metrics exposure",
		"nb-key-type":  "Revoke reusable or expired setup keys via the NetBird dashboard; re-mint one-off keys with explicit expiry",
		"nb-api-auth":  "Set or rotate the NetBird API key: abysslink server netbird init --apply (re-init prints the new key)",
		"nb-proc-user": "Ensure netbird-server runs as a non-root service user: check systemd User= in the unit file",
		"nb-runtime":   "Install a container runtime: brew install --cask docker  (or colima: brew install colima && colima start)",
		"nb-sshcheck":  "", // permanent WARN — SSHCheck not available on NetBird; no fix possible
		// Fleet isolation checks (mr-* checks).
		"mr-rig-isolation":   "abysslink enroll rig <name> --apply  (re-pushes the rig-to-rig ACL deny)",
		"mr-topic-isolation": "Give each rig a unique ntfy_topic in abysslink.yaml",
		"mr-key-uniqueness":  "Rename the conflicting rig; rig names must be unique (they form the keychain service)",
		// Supply-chain integrity advisories (supply-* checks).
		"supply-cosign-bundle": "Install cosign and re-verify: abysslink verify   (or reinstall from a signed release)",
		"supply-slsa-source":   "Upgrade to a v3+ release built with SLSA provenance: abysslink upgrade --apply",
	}
	return fixes[check]
}

// supplyChainFindings runs the supply-chain integrity advisory checks:
// supply-cosign-bundle (verifies the release cosign v3 bundle offline) and
// supply-slsa-source (confirms a SLSA provenance URL is embedded). Both are
// SeverityWarning on failure — the binary runs fine without a verifiable bundle;
// these are integrity advisories, not fail-closed gates. The runner is injected
// so tests can substitute a shell.MockRunner. When bundleOverride is non-empty,
// the cosign verification runs against it directly and no download is attempted.
func supplyChainFindings(ctx context.Context, runner shell.Runner, ver, bundleOverride string) []modules.Finding {
	return []modules.Finding{
		supplyCosignBundleCheck(ctx, runner, ver, bundleOverride),
		supplySLSASourceCheck(),
	}
}

// supplyCosignBundleCheck verifies the installed release's cosign v3 bundle.
func supplyCosignBundleCheck(ctx context.Context, runner shell.Runner, ver, bundleOverride string) modules.Finding {
	const check = "supply-cosign-bundle"
	bare := strings.TrimPrefix(ver, "v")
	if bare == "" || bare == "dev" || bare == "unknown" {
		return modules.Finding{
			Module:   "supply",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "dev build — no release bundle available to verify",
		}
	}

	checksumName := fmt.Sprintf("abysslink_%s_checksums.txt", bare)
	checksumPath := bundleOverride // reused below only when override present
	bundlePath := bundleOverride

	if bundleOverride == "" {
		tmpDir, err := os.MkdirTemp("", "abysslink-doctor-supply-*")
		if err != nil {
			return supplyBundleWarn(check, err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()
		baseURL := fmt.Sprintf("https://github.com/%s/releases/download/v%s", upgradeRepo, bare)
		checksumPath = filepath.Join(tmpDir, checksumName)
		bundlePath = filepath.Join(tmpDir, checksumName+".bundle")
		if err := downloadFile(ctx, baseURL+"/"+checksumName, checksumPath); err != nil {
			return supplyBundleWarn(check, fmt.Errorf("download checksums: %w", err))
		}
		if err := downloadFile(ctx, baseURL+"/"+checksumName+".bundle", bundlePath); err != nil {
			return supplyBundleWarn(check, fmt.Errorf("download bundle: %w", err))
		}
	} else {
		// Override mode (tests): use a sibling checksums file if present.
		sibling := filepath.Join(filepath.Dir(bundleOverride), checksumName)
		if _, statErr := os.Stat(sibling); statErr == nil {
			checksumPath = sibling
		}
	}

	if err := verifyCosignBundle(ctx, runner, checksumPath, bundlePath); err != nil {
		return supplyBundleWarn(check, err)
	}
	return modules.Finding{
		Module:   "supply",
		Check:    check,
		Severity: modules.SeverityOK,
		Message:  "cosign v3 bundle verified (offline)",
	}
}

// supplyBundleWarn builds the SeverityWarning finding for a failed bundle check.
func supplyBundleWarn(check string, err error) modules.Finding {
	return modules.Finding{
		Module:   "supply",
		Check:    check,
		Severity: modules.SeverityWarning,
		Message:  fmt.Sprintf("cosign bundle verification failed: %v", err),
	}
}

// supplySLSASourceCheck confirms a SLSA provenance URL is embedded in the build.
func supplySLSASourceCheck() modules.Finding {
	const check = "supply-slsa-source"
	if slsaURL == "" {
		return modules.Finding{
			Module:   "supply",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "no SLSA provenance URL embedded (dev build or pre-v3 release)",
		}
	}
	return modules.Finding{
		Module:   "supply",
		Check:    check,
		Severity: modules.SeverityOK,
		Message:  "SLSA L2 provenance available at " + slsaURL,
	}
}

// remoteSeverity converts a JSON severity string ("ok" | "warn" | "fatal") to
// the modules.Severity integer. Unknown values map to SeverityWarning so
// unrecognised remote findings degrade gracefully without crashing.
func remoteSeverity(s string) modules.Severity {
	switch strings.ToLower(s) {
	case "ok":
		return modules.SeverityOK
	case "fatal":
		return modules.SeverityFatal
	default:
		return modules.SeverityWarning
	}
}
