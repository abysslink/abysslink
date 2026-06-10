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

	// Supply-chain integrity advisories.
	findings = append(findings, supplyChainFindings(ctx, cc.runner, version, "")...)

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
	// cross-ref aliases so the underlying checks run exactly once).
	findings = append(findings, secDoctorFindings(ctx, cc, deps, false, metFinds, webuiFinds, auditFinds)...)

	// Phase 21 optional-module posture.
	findings = append(findings, mod3DoctorFindings(ctx, cc.cfg, cc.runner)...)

	// Version-floor findings (DOC-04): ntfy < 2.21 FATAL, etc. Appended once
	// here so they surface in both `abysslink doctor` and (via Task 2) the
	// shared-set threat-model render. Appending after mod3 preserves the
	// canonical order and avoids double-emission (this is the only call site).
	findings = append(findings, versionFloorFindings(ctx, cc.runner)...)

	return findings
}
