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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
)

// TestSecSentinelEnabled_OffWarns: the opt-in default (detector OFF) is an
// honest WARN.
func TestSecSentinelEnabled_OffWarns(t *testing.T) {
	cfg := config.Defaults()
	f := secSentinelEnabledCheck(cfg)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	assert.Equal(t, checkSecSentinelEnabled, f.Check)
	assert.Contains(t, f.Message, "OFF")
}

// TestSecSentinelEnabled_OnIsOK: an armed detector is OK, and the message
// reflects the quarantine posture.
func TestSecSentinelEnabled_OnIsOK(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sentinel.Enabled = true
	f := secSentinelEnabledCheck(cfg)
	assert.Equal(t, modules.SeverityOK, f.Severity)
	assert.Contains(t, f.Message, "flag+audit")

	cfg.Sentinel.Quarantine = true
	f = secSentinelEnabledCheck(cfg)
	assert.Equal(t, modules.SeverityOK, f.Severity)
	assert.Contains(t, f.Message, "quarantine")
}

// TestSecSentinelEnabled_AtRiskFATAL: --profile at-risk escalates the disabled
// WARN to FATAL and never loosens the OK posture.
func TestSecSentinelEnabled_AtRiskFATAL(t *testing.T) {
	cfg := config.Defaults()
	findings := []modules.Finding{secSentinelEnabledCheck(cfg)}
	require.Equal(t, modules.SeverityWarning, findings[0].Severity)

	tightened := tightenAtRiskProfile(findings, cfg)
	got := findingByCheck(tightened, checkSecSentinelEnabled)
	require.NotNil(t, got)
	assert.Equal(t, modules.SeverityFatal, got.Severity,
		"at-risk must escalate a disabled sentinel WARN to FATAL")

	cfg.Sentinel.Enabled = true
	okFindings := tightenAtRiskProfile([]modules.Finding{secSentinelEnabledCheck(cfg)}, cfg)
	okGot := findingByCheck(okFindings, checkSecSentinelEnabled)
	require.NotNil(t, okGot)
	assert.Equal(t, modules.SeverityOK, okGot.Severity)
}

// TestSecSentinelRules_Intact: the embedded rule self-test holds on a healthy
// binary with the default config.
func TestSecSentinelRules_Intact(t *testing.T) {
	f := secSentinelRulesCheck(context.Background(), config.Defaults())
	assert.Equal(t, modules.SeverityOK, f.Severity, "message: %s", f.Message)
}

// TestSecSentinelRules_LiveVacuousConfigFatal: an over-broad egress allowlist
// that swallows the canned exfil host makes the LIVE detector vacuous, and the
// rules check must catch it (FATAL) rather than replaying the compiled defaults
// and staying green.
func TestSecSentinelRules_LiveVacuousConfigFatal(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sentinel.Enabled = true
	// A narrow-but-swallowing suffix the config validator does not reject (it has
	// a dot, so it is not a bare-TLD wildcard) yet covers exfil.example.net.
	cfg.Sentinel.EgressAllowlist = []string{"*.example.net"}
	f := secSentinelRulesCheck(context.Background(), cfg)
	assert.Equal(t, modules.SeverityFatal, f.Severity,
		"a live config that swallows the exfil probe host must fail the rules check; message: %s", f.Message)
}

// TestSentinelDoctorFindings_StableOrder: the family emits both checks in the
// documented order under the sec module heading (golden stability).
func TestSentinelDoctorFindings_StableOrder(t *testing.T) {
	findings := sentinelDoctorFindings(context.Background(), config.Defaults())
	require.Len(t, findings, 2)
	assert.Equal(t, checkSecSentinelEnabled, findings[0].Check)
	assert.Equal(t, checkSecSentinelRules, findings[1].Check)
	for _, f := range findings {
		assert.Equal(t, "sec", f.Module)
	}
}
