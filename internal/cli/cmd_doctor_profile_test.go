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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
)

// TestDoctorProfileAtRisk_TightensWarnToFatal asserts a check that is WARN by
// default becomes FATAL under the at-risk profile, and that the dead-man-enabled
// case adds no deadman-required FATAL.
func TestDoctorProfileAtRisk_TightensWarnToFatal(t *testing.T) {
	in := []modules.Finding{
		{Module: "sec", Check: "sec-disk-encryption", Severity: modules.SeverityWarning, Message: "warn"},
		{Module: "transport", Check: "tailscale-version", Severity: modules.SeverityWarning, Message: "warn"},
		{Module: "ntfy", Check: "ntfy-bind", Severity: modules.SeverityWarning, Message: "warn"},
		{Module: "other", Check: "some-unrelated-check", Severity: modules.SeverityWarning, Message: "warn"},
	}
	cfg := config.Defaults()
	cfg.Deadman.Enabled = true // configured ⇒ no deadman-required FATAL

	out := tightenAtRiskProfile(in, cfg)

	disk := findingByCheck(out, "sec-disk-encryption")
	require.NotNil(t, disk)
	assert.Equal(t, modules.SeverityFatal, disk.Severity, "disk-encryption WARN must tighten to FATAL")

	ts := findingByCheck(out, "tailscale-version")
	require.NotNil(t, ts)
	assert.Equal(t, modules.SeverityFatal, ts.Severity, "version-floor WARN must tighten to FATAL")

	ntfy := findingByCheck(out, "ntfy-bind")
	require.NotNil(t, ntfy)
	assert.Equal(t, modules.SeverityFatal, ntfy.Severity, "ntfy-bind WARN must tighten to FATAL")

	// An unrelated check is NOT tightened.
	other := findingByCheck(out, "some-unrelated-check")
	require.NotNil(t, other)
	assert.Equal(t, modules.SeverityWarning, other.Severity, "unrelated checks must be untouched")

	// Dead-man enabled ⇒ no deadman-required finding.
	assert.Nil(t, findingByCheck(out, deadmanRequiredCheck),
		"an enabled dead-man switch must not add a deadman-required FATAL")
}

// TestAtRisk_TightensNewChecks asserts the three Phase-38 host-posture checks
// (sec-tailnet-lock / sec-autologin / sec-remote-login) are WARN by default and
// tighten to FATAL under --profile at-risk, while an OK finding on the same check
// stays OK (BKLG-01/04).
func TestAtRisk_TightensNewChecks(t *testing.T) {
	in := []modules.Finding{
		{Module: "sec", Check: "sec-tailnet-lock", Severity: modules.SeverityWarning, Message: "lock off"},
		{Module: "sec", Check: "sec-autologin", Severity: modules.SeverityWarning, Message: "auto-login on"},
		{Module: "sec", Check: "sec-remote-login", Severity: modules.SeverityWarning, Message: "remote login on"},
		// An OK on a tightened check must stay OK (only WARN tightens).
		{Module: "sec", Check: "sec-remote-login", Severity: modules.SeverityOK, Message: "off"},
	}
	cfg := config.Defaults()
	cfg.Deadman.Enabled = true // isolate: no deadman-required FATAL

	out := tightenAtRiskProfile(in, cfg)

	for _, check := range []string{"sec-tailnet-lock", "sec-autologin", "sec-remote-login"} {
		require.True(t, atRiskTightenedChecks[check], "%s must be in atRiskTightenedChecks", check)
	}
	assert.Equal(t, modules.SeverityFatal, out[0].Severity, "sec-tailnet-lock WARN must tighten to FATAL")
	assert.Equal(t, modules.SeverityFatal, out[1].Severity, "sec-autologin WARN must tighten to FATAL")
	assert.Equal(t, modules.SeverityFatal, out[2].Severity, "sec-remote-login WARN must tighten to FATAL")
	assert.Equal(t, modules.SeverityOK, out[3].Severity, "an OK sec-remote-login must stay OK")
}

// TestDoctorProfileAtRisk_RequiresDeadman asserts the at-risk profile adds a
// FATAL deadman-required finding when the switch is OFF, and not when it is ON.
func TestDoctorProfileAtRisk_RequiresDeadman(t *testing.T) {
	in := []modules.Finding{
		{Module: "sec", Check: "sec-audit-log-exists", Severity: modules.SeverityOK, Message: "ok"},
	}

	cfgOff := config.Defaults()
	cfgOff.Deadman.Enabled = false
	outOff := tightenAtRiskProfile(in, cfgOff)
	dm := findingByCheck(outOff, deadmanRequiredCheck)
	require.NotNil(t, dm, "an unconfigured dead-man switch must add a deadman-required finding")
	assert.Equal(t, modules.SeverityFatal, dm.Severity)
	hasFatal, _ := findingsSeverityFlags(outOff)
	assert.True(t, hasFatal, "deadman-required must drive a FATAL exit")

	cfgOn := config.Defaults()
	cfgOn.Deadman.Enabled = true
	outOn := tightenAtRiskProfile(in, cfgOn)
	assert.Nil(t, findingByCheck(outOn, deadmanRequiredCheck),
		"a configured dead-man switch must not add the FATAL")
}

// TestDoctorProfileAtRisk_OnlyTightens asserts the profile NEVER downgrades an
// existing FATAL to WARN and leaves OK findings alone (T-32-28).
func TestDoctorProfileAtRisk_OnlyTightens(t *testing.T) {
	in := []modules.Finding{
		// An existing FATAL on a tightened check must stay FATAL.
		{Module: "sec", Check: "sec-disk-encryption", Severity: modules.SeverityFatal, Message: "fatal"},
		// An OK on a tightened check must stay OK (only WARN tightens).
		{Module: "transport", Check: "openssh-version", Severity: modules.SeverityOK, Message: "ok"},
	}
	cfg := config.Defaults()
	cfg.Deadman.Enabled = true

	out := tightenAtRiskProfile(in, cfg)

	disk := findingByCheck(out, "sec-disk-encryption")
	require.NotNil(t, disk)
	assert.Equal(t, modules.SeverityFatal, disk.Severity, "existing FATAL must never be downgraded")

	ssh := findingByCheck(out, "openssh-version")
	require.NotNil(t, ssh)
	assert.Equal(t, modules.SeverityOK, ssh.Severity, "OK must not be tightened (only WARN→FATAL)")
}

// TestDoctorProfile_DefaultPathUnchanged asserts the no-profile path leaves the
// findings slice byte-for-byte unchanged (no regression). tightenAtRiskProfile
// is simply not invoked when the profile flag is empty; this asserts the input
// is not mutated even if it were called, and that an empty profile yields the
// same severities.
func TestDoctorProfile_DefaultPathUnchanged(t *testing.T) {
	in := []modules.Finding{
		{Module: "sec", Check: "sec-disk-encryption", Severity: modules.SeverityWarning, Message: "warn"},
		{Module: "transport", Check: "tailscale-version", Severity: modules.SeverityWarning, Message: "warn"},
	}
	// Snapshot the input severities.
	before := make([]modules.Severity, len(in))
	for i, f := range in {
		before[i] = f.Severity
	}

	// The default path does not call tightenAtRiskProfile at all; emulate it by
	// asserting the input is untouched after a tightening call (returns a NEW
	// slice, never mutating the caller's).
	cfg := config.Defaults()
	cfg.Deadman.Enabled = true
	_ = tightenAtRiskProfile(in, cfg)

	for i, f := range in {
		assert.Equal(t, before[i], f.Severity, "tightenAtRiskProfile must not mutate the input slice")
	}
}

// TestDoctorProfileFlagRegistered asserts the --profile flag exists on the
// doctor command.
func TestDoctorProfileFlagRegistered(t *testing.T) {
	cmd := newDoctorCmd()
	f := cmd.Flags().Lookup("profile")
	require.NotNil(t, f, "doctor must register a --profile flag")
}
