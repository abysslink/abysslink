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

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// CollectDoctorFindings runs every doctor finding family in the SAME canonical
// order as the `abysslink doctor` command (cmd_doctor.go RunE) and returns the
// merged slice. It is the single source of truth for the doctor posture so the
// CLI command, the abysslinkd web-UI dashboard (Phase 19 / B3), and any future
// consumer cannot drift apart on ordering or which families run.
//
// Ordering (must match cmd_doctor.go RunE):
//
//	core modules (Runner.Doctor) → backend+fleet → supply-chain → audit →
//	metrics → webui → security (reuses metrics/webui/audit slices) → mod3.
//
// It is read-only: no family mutates the system. cfg and runner are the only
// inputs the daemon entrypoint needs; deps (backend, keychain, audit writer,
// metrics registry) are built internally via buildDeps. A build failure for
// deps is surfaced as a single FATAL finding rather than an error return so the
// caller (a dashboard renderer) always has something honest to show — never a
// fabricated all-clear (WR-05).
//
// ctx cancellation propagates into every family that accepts it. The function
// never panics: per-family panics inside the underlying checks are already
// recovered at their own seams (e.g. safeSSHCheck).
func CollectDoctorFindings(ctx context.Context, cfg *config.Config, runner shell.Runner) []modules.Finding {
	if cfg == nil {
		cfg = config.Defaults()
	}
	if runner == nil {
		runner = &shell.ExecRunner{}
	}

	cc := &cmdContext{
		cfg:    cfg,
		runner: runner,
		dryRun: true, // doctor is read-only; never imply an apply path.
	}

	deps, err := buildDeps(ctx, cc)
	if err != nil {
		// Honest failure: the dashboard renders a single FATAL rather than an
		// empty (false-clean) doctor view.
		return []modules.Finding{{
			Module:   "doctor",
			Check:    "doctor-deps",
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("doctor dependencies could not be initialized: %v", err),
		}}
	}

	return collectDoctorFindings(ctx, cc, deps)
}

// collectDoctorFindings is the unexported core shared by the exported
// CollectDoctorFindings and the doctor command's RunE. It assembles the full
// ordered finding slice from an already-built cmdContext + deps so the command
// (which builds them itself with its own flag-derived cmdContext) and the
// daemon entrypoint converge on one ordering.
//
// allRigs/strict fan-out is intentionally NOT performed here: it is a CLI-only
// concern (it SSHes to remote rigs) and the doctor RunE appends it separately
// after this call. The web-UI dashboard reflects only the local rig's posture.
func collectDoctorFindings(ctx context.Context, cc *cmdContext, deps modules.Deps) []modules.Finding {
	var findings []modules.Finding

	// Core modules (Runner.Doctor). A runner construction failure degrades to a
	// FATAL finding rather than aborting the whole posture view.
	if r, err := modules.NewRunner(allModules(deps), cc.cfg); err == nil {
		if coreFindings, derr := r.Doctor(ctx); derr == nil {
			findings = append(findings, coreFindings...)
		} else {
			slog.Warn("doctor: core module checks failed", "err", derr)
			findings = append(findings, modules.Finding{
				Module:   "doctor",
				Check:    "doctor-core",
				Severity: modules.SeverityFatal,
				Message:  fmt.Sprintf("core module checks failed: %v", derr),
			})
		}
	} else {
		slog.Warn("doctor: module runner construction failed", "err", err)
		findings = append(findings, modules.Finding{
			Module:   "doctor",
			Check:    "doctor-core",
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("module runner could not be constructed: %v", err),
		})
	}

	// Backend-specific + fleet findings.
	findings = appendBackendAndFleetFindings(ctx, cc, deps.Keychain, findings)

	// Supply-chain integrity advisories. Captured locally so the sec-* alias
	// (sec-binary-signed) reuses the result instead of re-downloading the
	// release artifacts a second time per doctor run (W8 / RESEARCH Pitfall 3).
	// `doctor --offline` (cc.offline) skips the networked download entirely.
	var supplyFinds []modules.Finding
	if cc.offline {
		supplyFinds = supplyChainFindingsOffline()
	} else {
		supplyFinds = supplyChainFindings(ctx, cc.runner, version, "")
	}
	findings = append(findings, supplyFinds...)

	// Tamper-evident audit-log posture. Captured locally so the sec cross-ref
	// alias reuses it (run-once pattern).
	var auditFinds []modules.Finding
	if logPath, lpErr := auditDefaultLogPath(); lpErr == nil {
		auditFinds = auditDoctorFindings(logPath, deps.Keychain)
		findings = append(findings, auditFinds...)
	} else {
		slog.Warn("doctor: audit log path unavailable; skipping audit checks", "err", lpErr)
	}

	// Observability metrics posture.
	metFinds := metricsDoctorFindings(cc.cfg, deps.MetricsRegistry(), resolveTailnetIP(ctx, cc))
	findings = append(findings, metFinds...)

	// ntfy port-binding posture (NET-01 / D-02).
	ntfyFinds := ntfyBindFindings(ctx, cc.runner, cc.cfg)
	findings = append(findings, ntfyFinds...)

	// Web UI posture.
	webuiFinds := webuiDoctorFindings(ctx, cc.cfg)
	findings = append(findings, webuiFinds...)

	// Security audit posture (reuses metFinds/webuiFinds/auditFinds for the 3
	// cross-ref aliases and supplyFinds for sec-binary-signed so the underlying
	// checks run exactly once — no second artifact download, W8).
	findings = append(findings, secDoctorFindings(ctx, cc, deps, false, metFinds, webuiFinds, auditFinds, supplyFinds)...)

	// Phase 21 optional-module posture.
	findings = append(findings, mod3DoctorFindings(ctx, cc.cfg, cc.runner)...)

	// Version-floor findings (DOC-04): ntfy < 2.21 FATAL, etc. Appended once
	// here so they surface in both `abysslink doctor` and (via Task 2) the
	// shared-set threat-model render. Appending after mod3 preserves the
	// canonical order and avoids double-emission (this is the only call site).
	findings = append(findings, versionFloorFindings(ctx, cc.runner)...)

	// Device CA/KRL drift findings (DEVC-05/DEVC-06 success criterion 5). Read-
	// only: compares the installed /etc/ssh CA-trust file + KRL against the
	// current device store. Gated on openssh-fallback mode (a tailscale-SSH
	// machine never wires the CA) AND a keychain-backed CA view; a nil view ⇒
	// the family emits nothing (fail-safe — no false WARN where auto-trust is
	// not in play). Appended after versionFloor preserves canonical order; this
	// is the only call site (no double-emission). The web-UI dashboard inherits
	// the family automatically via the exported CollectDoctorFindings.
	if cc.cfg.Modules.SSH.Mode == "openssh-fallback" {
		findings = append(findings, devSSHDriftFindings(ctx, cc.runner, devSSHCAView(deps))...)
	}

	// Content-store / credential-pull preflight (Phase 28.2): pings the daemon
	// over the unix socket and reads its /status content_store field so a silent
	// pull failure (daemon down, tailnet HTTPS certs disabled, tcp:2587 closed in
	// the ACL) surfaces as a WARN instead of leaving doctor green. WARN only —
	// the content store being off is a valid choice; appended last so it never
	// reorders the established families.
	findings = append(findings, contentStoreDoctorFindings(ctx, cc.cfg)...)

	// Push-gateway posture (Phase 29 / PUSH-06): 10 checks covering cred
	// accessibility (from daemon context), file permission / cloud-location floor,
	// experimental flag awareness, stale token surface, ntfy.sh sovereignty gap,
	// iOS UnifiedPush gap, and content-store bind-floor runtime recheck. Appended
	// after content-store so the two unix-socket seam calls are co-located.
	findings = append(findings, pushGatewayDoctorFindings(ctx, cc.cfg)...)

	return findings
}

// devSSHCAView builds the keychain-backed read-only CA view the drift check
// consumes, returning a nil caKRLView (not a typed-nil interface) when no
// keychain is available or the store path cannot be resolved — so
// devSSHDriftFindings's `ca == nil` fail-safe fires correctly. It reuses the
// same construction caProviderFor uses for the ssh module's wiring, keeping the
// two views in lockstep.
func devSSHCAView(deps modules.Deps) caKRLView {
	if deps.Keychain == nil {
		return nil
	}
	path, err := deviceStorePath()
	if err != nil {
		slog.Warn("doctor: device store path unavailable; skipping CA/KRL drift check", "err", err)
		return nil
	}
	// nil audit writer: this view never mutates the records file (read-only).
	return device.New(path, nil, deps.Keychain, nil)
}
