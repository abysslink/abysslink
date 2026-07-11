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

// TestSecQuorumEnabled_OK: enabled + enforcing gate is the OK posture.
func TestSecQuorumEnabled_OK(t *testing.T) {
	cfg := config.Defaults()
	cfg.Quorum.Enabled = true
	cfg.Gate.Enforcing = true
	f := secQuorumEnabledCheck(cfg)
	assert.Equal(t, modules.SeverityOK, f.Severity)
	assert.Equal(t, checkSecQuorumEnabled, f.Check)
}

// TestSecQuorumEnabled_ShadowGapWarns: default config (quorum on, gate not
// enforcing) is an honest WARN — evaluating but blocking nothing.
func TestSecQuorumEnabled_ShadowGapWarns(t *testing.T) {
	cfg := config.Defaults()
	f := secQuorumEnabledCheck(cfg)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	assert.Contains(t, f.Message, "shadow")
}

// TestSecQuorumEnabled_DisabledWarns: a disabled quorum is a WARN.
func TestSecQuorumEnabled_DisabledWarns(t *testing.T) {
	cfg := config.Defaults()
	cfg.Quorum.Enabled = false
	f := secQuorumEnabledCheck(cfg)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	assert.Contains(t, f.Message, "disabled")
}

// TestSecQuorumEnabled_AtRiskFATAL: --profile at-risk tightens the quorum
// WARN to FATAL and never loosens anything else (T-32-28).
func TestSecQuorumEnabled_AtRiskFATAL(t *testing.T) {
	cfg := config.Defaults()
	findings := []modules.Finding{secQuorumEnabledCheck(cfg)}
	require.Equal(t, modules.SeverityWarning, findings[0].Severity)

	tightened := tightenAtRiskProfile(findings, cfg)
	got := findingByCheck(tightened, checkSecQuorumEnabled)
	require.NotNil(t, got)
	assert.Equal(t, modules.SeverityFatal, got.Severity,
		"at-risk must escalate sec-quorum-enabled WARN to FATAL")

	// The OK posture stays OK under the profile (only-tightens invariant).
	cfg.Gate.Enforcing = true
	okFindings := tightenAtRiskProfile([]modules.Finding{secQuorumEnabledCheck(cfg)}, cfg)
	okGot := findingByCheck(okFindings, checkSecQuorumEnabled)
	require.NotNil(t, okGot)
	assert.Equal(t, modules.SeverityOK, okGot.Severity)
}

// TestSecQuorumFloor_Intact: on a healthy binary every floor probe denies.
func TestSecQuorumFloor_Intact(t *testing.T) {
	f := secQuorumFloorCheck(context.Background())
	assert.Equal(t, modules.SeverityOK, f.Severity, "message: %s", f.Message)
}

// TestSecQuorumFloor_ProbeFailureIsFatal: a manifest drift is FATAL. The
// probe-failure leg is exercised by mutating the doctor's shipped manifest
// copy (the compiled floor itself is immutable by construction).
func TestSecQuorumFloor_ProbeFailureIsFatal(t *testing.T) {
	orig := quorumShippedFloorManifest
	quorumShippedFloorManifest = []string{"funnel-enable"} // simulate drift
	defer func() { quorumShippedFloorManifest = orig }()

	f := secQuorumFloorCheck(context.Background())
	assert.Equal(t, modules.SeverityFatal, f.Severity,
		"a floor manifest mismatch must be FATAL — the immutable floor is not provably intact")
}

// TestSecQuorumSelftest_CorpusHolds: the embedded adversarial corpus holds on
// a healthy binary.
func TestSecQuorumSelftest_CorpusHolds(t *testing.T) {
	f := secQuorumSelftestCheck(context.Background())
	assert.Equal(t, modules.SeverityOK, f.Severity, "message: %s", f.Message)
}

// TestSecQuorumTripwire_Armed: the default canary marker denies.
func TestSecQuorumTripwire_Armed(t *testing.T) {
	f := secQuorumTripwireCheck(context.Background())
	assert.Equal(t, modules.SeverityOK, f.Severity, "message: %s", f.Message)
}

// TestQuorumDoctorFindings_StableOrder: the family emits all four checks in
// the documented order (golden stability).
func TestQuorumDoctorFindings_StableOrder(t *testing.T) {
	findings := quorumDoctorFindings(context.Background(), config.Defaults())
	require.Len(t, findings, 4)
	assert.Equal(t, checkSecQuorumEnabled, findings[0].Check)
	assert.Equal(t, checkSecQuorumFloor, findings[1].Check)
	assert.Equal(t, checkSecQuorumSelftest, findings[2].Check)
	assert.Equal(t, checkSecQuorumTripwire, findings[3].Check)
	for _, f := range findings {
		assert.Equal(t, "sec", f.Module)
	}
}
