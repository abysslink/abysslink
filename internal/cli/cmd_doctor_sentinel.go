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

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/modules/sentinel"
)

// sec-sentinel-* check IDs (P-B2 / E4.2). Both checks are deterministic and
// hermetic — no live host probes — so neither needs a volatileDoctorChecks
// entry and the doctor golden stays parity-safe.
const (
	checkSecSentinelEnabled = "sec-sentinel-enabled"
	checkSecSentinelRules   = "sec-sentinel-rules"
)

// sentinelDoctorFindings runs the two sec-sentinel-* posture checks in stable
// order. It is appended after the quorum family in collectDoctorFindings so it
// groups under the same "sec" module heading.
func sentinelDoctorFindings(ctx context.Context, cfg *config.Config) []modules.Finding {
	return []modules.Finding{
		secSentinelEnabledCheck(cfg),
		secSentinelRulesCheck(ctx),
	}
}

// secSentinelEnabledCheck reports the detector posture. OK when the detector is
// armed; WARN when it is off (the opt-in default — the exfil-pattern signal and
// audit trail are absent). `--profile at-risk` tightens the WARN to FATAL via
// atRiskTightenedChecks.
func secSentinelEnabledCheck(cfg *config.Config) modules.Finding {
	if cfg.Sentinel.Enabled {
		posture := "flag+audit"
		if cfg.Sentinel.Quarantine {
			posture = "flag+audit+quarantine (reversible lockdown)"
		}
		return modules.Finding{
			Module:   "sec",
			Check:    checkSecSentinelEnabled,
			Severity: modules.SeverityOK,
			Message:  fmt.Sprintf("compromised-agent exfil-pattern detector active (%s)", posture),
		}
	}
	return modules.Finding{
		Module:   "sec",
		Check:    checkSecSentinelEnabled,
		Severity: modules.SeverityWarning,
		Message:  "compromised-agent exfil-pattern detector is OFF (sentinel.enabled=false) — no read-then-egress signal or audit trail; defense-in-depth only, not a boundary",
	}
}

// secSentinelRulesCheck runs the embedded hermetic self-test: the canonical
// exfil pair must fire exactly once and a canned benign sequence must stay
// silent. A failure means the compiled detector is broken or vacuous — FATAL in
// every profile.
func secSentinelRulesCheck(ctx context.Context) modules.Finding {
	if err := sentinel.SelfTest(ctx); err != nil {
		return modules.Finding{
			Module:   "sec",
			Check:    checkSecSentinelRules,
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("sentinel rule self-test failed: %v", err),
		}
	}
	return modules.Finding{
		Module:   "sec",
		Check:    checkSecSentinelRules,
		Severity: modules.SeverityOK,
		Message:  "sentinel rules intact (exfil pair fires, benign/allowlisted sequences stay silent)",
	}
}
