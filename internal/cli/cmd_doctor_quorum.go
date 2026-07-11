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
	"slices"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/quorum"
)

// sec-quorum-* check IDs (E4.1 §8). All four checks are deterministic and
// hermetic — embedded fixtures only, no live host probes — so none needs a
// volatileDoctorChecks entry and the doctor golden stays parity-safe.
const (
	checkSecQuorumEnabled  = "sec-quorum-enabled"
	checkSecQuorumFloor    = "sec-quorum-floor"
	checkSecQuorumSelftest = "sec-quorum-selftest"
	checkSecQuorumTripwire = "sec-quorum-tripwire" //nolint:gosec // G101: doctor check identifier, not a credential
)

// quorumShippedFloorManifest is the doctor's OWN copy of the shipped deny-
// floor manifest. sec-quorum-floor compares quorum.FloorRuleCodes() against
// it: a binary whose compiled floor set drifted (a rule removed or renamed)
// is a FATAL finding — the immutable floor must be provably intact.
var quorumShippedFloorManifest = []string{
	"funnel-enable",
	"filevault-disable",
	"luks-erase",
	"audit-log-destruction",
	"tailnet-lock-disable",
	"ntfy-bind-all",
	"canary-tripwire",
}

// quorumDoctorFindings runs the four sec-quorum-* posture checks in stable
// order (E4.1 §8).
func quorumDoctorFindings(ctx context.Context, cfg *config.Config) []modules.Finding {
	return []modules.Finding{
		secQuorumEnabledCheck(cfg),
		secQuorumFloorCheck(ctx),
		secQuorumSelftestCheck(ctx),
		secQuorumTripwireCheck(ctx),
	}
}

// quorumProbeEngine builds a hermetic default-config engine for the doctor
// probes: no runner (V4 fails closed), no audit appender (probes are not real
// decisions), discard logger (doctor output stays clean).
func quorumProbeEngine() *quorum.Engine {
	return quorum.New(quorum.Config{}, quorum.WithLogger(slog.New(slog.DiscardHandler)))
}

// secQuorumEnabledCheck reports whether the quorum gate can actually block:
// OK when quorum.enabled && gate.enforcing; WARN when evaluating in shadow
// only; WARN when disabled. `--profile at-risk` tightens the WARNs to FATAL
// via atRiskTightenedChecks.
func secQuorumEnabledCheck(cfg *config.Config) modules.Finding {
	switch {
	case cfg.Quorum.Enabled && cfg.Gate.Enforcing:
		return modules.Finding{
			Module:   "sec",
			Check:    checkSecQuorumEnabled,
			Severity: modules.SeverityOK,
			Message:  "quorum action gate is evaluating and enforcing",
		}
	case cfg.Quorum.Enabled:
		return modules.Finding{
			Module:   "sec",
			Check:    checkSecQuorumEnabled,
			Severity: modules.SeverityWarning,
			Message:  "quorum evaluating in shadow only (gate.enforcing=false) — decisions are audited but nothing is blocked",
		}
	default:
		return modules.Finding{
			Module:   "sec",
			Check:    checkSecQuorumEnabled,
			Severity: modules.SeverityWarning,
			Message:  "quorum is disabled (quorum.enabled=false) — an enforcing gate falls back to approval-for-every-exec",
		}
	}
}

// secQuorumFloorCheck verifies the immutable deny-floor is intact: the
// compiled floor manifest must match the shipped list, and every compiled
// floor probe fixture must evaluate to DENY with its own rule. Config cannot
// weaken the floor (no key exists); this check proves the BINARY has not
// either.
func secQuorumFloorCheck(ctx context.Context) modules.Finding {
	if got := quorum.FloorRuleCodes(); !slices.Equal(got, quorumShippedFloorManifest) {
		return modules.Finding{
			Module:   "sec",
			Check:    checkSecQuorumFloor,
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("compiled deny-floor manifest drifted from the shipped set: got %v", got),
		}
	}
	e := quorumProbeEngine()
	for _, probe := range quorum.FloorProbes() {
		d, err := e.Evaluate(ctx, probe.Name, probe.Args)
		if err != nil {
			return modules.Finding{
				Module:   "sec",
				Check:    checkSecQuorumFloor,
				Severity: modules.SeverityFatal,
				Message:  fmt.Sprintf("floor probe %s failed to evaluate: %v", probe.Rule, err),
			}
		}
		if d.Outcome != quorum.OutcomeDeny || d.FloorRule != probe.Rule {
			return modules.Finding{
				Module:   "sec",
				Check:    checkSecQuorumFloor,
				Severity: modules.SeverityFatal,
				Message:  fmt.Sprintf("floor probe %s did not DENY (outcome %s, rule %q) — the immutable deny-floor is compromised", probe.Rule, d.Outcome, d.FloorRule),
			}
		}
	}
	return modules.Finding{
		Module:   "sec",
		Check:    checkSecQuorumFloor,
		Severity: modules.SeverityOK,
		Message:  fmt.Sprintf("immutable deny-floor intact (%d rules, all probes deny)", len(quorumShippedFloorManifest)),
	}
}

// secQuorumSelftestCheck runs the embedded hermetic adversarial mini-corpus
// end-to-end: any entry evaluating to ALLOW means the verifiers are no longer
// failing closed — FATAL.
func secQuorumSelftestCheck(ctx context.Context) modules.Finding {
	if err := quorum.SelfTest(ctx); err != nil {
		return modules.Finding{
			Module:   "sec",
			Check:    checkSecQuorumSelftest,
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("quorum adversarial self-test failed: %v", err),
		}
	}
	return modules.Finding{
		Module:   "sec",
		Check:    checkSecQuorumSelftest,
		Severity: modules.SeverityOK,
		Message:  "quorum verifiers alive and failing closed (embedded adversarial corpus holds)",
	}
}

// secQuorumTripwireCheck verifies the canary tripwires are armed: a synthetic
// argv carrying the compiled default marker must DENY.
func secQuorumTripwireCheck(ctx context.Context) modules.Finding {
	e := quorumProbeEngine()
	d, err := e.Evaluate(ctx, "printf", []string{quorum.DefaultCanaryMarker})
	if err != nil || d.Outcome != quorum.OutcomeDeny {
		return modules.Finding{
			Module:   "sec",
			Check:    checkSecQuorumTripwire,
			Severity: modules.SeverityFatal,
			Message:  "the default canary marker did not DENY — tripwires are DISARMED",
		}
	}
	return modules.Finding{
		Module:   "sec",
		Check:    checkSecQuorumTripwire,
		Severity: modules.SeverityOK,
		Message:  "canary tripwires armed (default marker denies)",
	}
}
