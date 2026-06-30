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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpRefusesWhenNotInitialised: `up --apply` on a machine with no
// abysslink.yaml must fail closed (exit 2) and route the user to `init`. It must
// never fall back to config.Defaults() and converge a zero-identity config (the
// `<your-rig>` apply bug). Mirrors the doctor/status not-initialised guards.
func TestUpRefusesWhenNotInitialised(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no abysslink.yaml here

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"up", "--apply"})

	err := root.ExecuteContext(context.Background())
	require.Error(t, err, "up with no config must not silently converge on Defaults")
	var ee *exitError
	require.True(t, errors.As(err, &ee), "expected exitError, got %v", err)
	assert.Equal(t, exitCodeFatal, ee.ExitCode(), "missing config is fail-closed (exit 2)")

	assert.Contains(t, out.String(), "not initialised")
	assert.Contains(t, out.String(), "abysslink init")
	assert.NotContains(t, out.String(), "applying", "must not enter the apply phase")
	assert.NotContains(t, out.String(), "converged", "must not converge anything")
}

// TestUpRefusesWhenNotInitialised_JSON: the --json path emits a structured
// not-initialised record and still exits 2, so scripted callers fail closed too.
func TestUpRefusesWhenNotInitialised_JSON(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--json", "up", "--apply"})

	err := root.ExecuteContext(context.Background())
	require.Error(t, err)
	var ee *exitError
	require.True(t, errors.As(err, &ee), "expected exitError, got %v", err)
	assert.Equal(t, exitCodeFatal, ee.ExitCode())
	assert.Contains(t, out.String(), "not-initialised")
}

// unknownDiskFinding returns a FATAL hardening finding that carries the
// Plan 02 UNKNOWN-state marker substring ("disk-encryption state is UNKNOWN").
// The gate in cmd_up.go must detect this substring and refuse --force-unsafe.
func unknownDiskFinding() modules.Finding {
	return modules.Finding{
		Module:   "hardening",
		Check:    "filevault",
		Severity: modules.SeverityFatal,
		Message:  "disk-encryption state is UNKNOWN — fdesetup returned unexpected output; verify encryption manually",
	}
}

// knownOffDiskFinding returns a FATAL hardening finding that does NOT carry the
// UNKNOWN marker — it represents a disk that is known to be fully unencrypted.
// The existing --force-unsafe path must still bypass this (preserved behavior).
func knownOffDiskFinding() modules.Finding {
	return modules.Finding{
		Module:   "hardening",
		Check:    "filevault",
		Severity: modules.SeverityFatal,
		Message:  "FileVault is Off — full-disk encryption is required",
	}
}

// TestUpDiskEncryption_UnknownBlocksWithForceUnsafe asserts that a FATAL
// disk-encryption finding carrying the UNKNOWN-state marker ("disk-encryption
// state is UNKNOWN") blocks up EVEN when --force-unsafe is set. This is the
// D-05 / CLAUDE.md immutable default: unknown state is non-overridable.
//
// RED gate: this fails until the gate distinguishes UNKNOWN from known-off.
func TestUpDiskEncryption_UnknownBlocksWithForceUnsafe(t *testing.T) {
	blockers := []modules.Finding{unknownDiskFinding()}
	err := diskEncryptionGate(blockers, true /* forceUnsafe */)
	require.Error(t, err, "unknown disk-encryption state must block up even with --force-unsafe")
	// The error message must explain manual verification, NOT offer --force-unsafe as a bypass.
	assert.NotContains(t, err.Error(), "--force-unsafe",
		"unknown-state error must NOT mention --force-unsafe as a way out")
	assert.True(t,
		strings.Contains(err.Error(), "verify") || strings.Contains(err.Error(), "manual"),
		"unknown-state error must explain how to verify encryption manually")
}

// TestUpDiskEncryption_UnknownBlocksWithoutForceUnsafe asserts that a
// UNKNOWN-state finding blocks up regardless of whether --force-unsafe is set.
func TestUpDiskEncryption_UnknownBlocksWithoutForceUnsafe(t *testing.T) {
	blockers := []modules.Finding{unknownDiskFinding()}
	err := diskEncryptionGate(blockers, false /* forceUnsafe */)
	require.Error(t, err, "unknown disk-encryption state must block up without --force-unsafe")
}

// TestUpDiskEncryption_KnownOffAllowsForceUnsafe asserts that a known-off
// (fully unencrypted, NOT unknown) FATAL finding is still bypassable via
// --force-unsafe — the pre-existing behavior must be preserved.
func TestUpDiskEncryption_KnownOffAllowsForceUnsafe(t *testing.T) {
	blockers := []modules.Finding{knownOffDiskFinding()}
	err := diskEncryptionGate(blockers, true /* forceUnsafe */)
	assert.NoError(t, err, "known-off (not unknown) disk-encryption state must be bypassable with --force-unsafe")
}

// TestUpDiskEncryption_NoBlockers asserts that an empty blocker slice
// returns no error regardless of --force-unsafe.
func TestUpDiskEncryption_NoBlockers(t *testing.T) {
	assert.NoError(t, diskEncryptionGate(nil, false))
	assert.NoError(t, diskEncryptionGate(nil, true))
}

// TestInteractiveActionsFromActions_TailscaleLogin asserts that an action whose
// Description contains "tailscale login" is detected as an interactive action.
func TestInteractiveActionsFromActions_TailscaleLogin(t *testing.T) {
	actions := []modules.Action{{
		Module:      "tailscale",
		Description: "ACTION REQUIRED: run `tailscale login` to authenticate (opens browser), then re-run `abysslink up --apply`",
	}}
	result := interactiveActionsFromActions(actions)
	assert.NotEmpty(t, result, "action containing 'tailscale login' must be detected as interactive")
}

// TestInteractiveActionsFromActions_NoMatch asserts that actions NOT containing
// "tailscale login" are not detected as interactive.
func TestInteractiveActionsFromActions_NoMatch(t *testing.T) {
	actions := []modules.Action{{
		Module:      "tailscale",
		Description: "run tailscale set --ssh",
	}}
	result := interactiveActionsFromActions(actions)
	assert.Empty(t, result, "action without 'tailscale login' must not be detected as interactive")
}

// TestApplyAnimationEnabled_TailscaleLogin asserts that applyAnimationEnabled
// returns false when interactive actions (tailscale login) are present, preventing
// BubbleTea raw-mode stdin contention with RunInteractive.
func TestApplyAnimationEnabled_TailscaleLogin(t *testing.T) {
	interactiveLines := interactiveActionsFromActions([]modules.Action{{
		Description: "run `tailscale login` to authenticate",
	}})
	assert.False(t, applyAnimationEnabled(false, nil, interactiveLines),
		"applyAnimationEnabled must return false when interactive actions are present")
}

// TestApplyAnimationEnabled_NoInteractiveOrSudo asserts that animation falls
// through to animationEnabled() when there are no sudo or interactive actions.
// In a headless test environment, animationEnabled(false) returns false (no TTY),
// so the overall result is false — matching the DisabledWhenNotTTY contract.
// The key property under test: no additional false is introduced by nil slices.
func TestApplyAnimationEnabled_NoInteractiveOrSudo(t *testing.T) {
	// applyAnimationEnabled(false, nil, nil) must equal animationEnabled(false)
	// — the two nil slices must not introduce an extra false gate.
	assert.Equal(t, animationEnabled(false), applyAnimationEnabled(false, nil, nil),
		"applyAnimationEnabled with nil slices must delegate directly to animationEnabled")
}

// TestApplyAnimationEnabled_SudoStillDisables asserts that the existing sudo path
// still disables animation even with no interactive actions.
func TestApplyAnimationEnabled_SudoStillDisables(t *testing.T) {
	assert.False(t, applyAnimationEnabled(false, []string{"pmset notice"}, nil),
		"applyAnimationEnabled must return false when sudo actions are present")
}

// TestApplyAnimationEnabled_JsonOutDisables asserts that jsonOut=true disables
// animation regardless of interactive or sudo lines.
func TestApplyAnimationEnabled_JsonOutDisables(t *testing.T) {
	assert.False(t, applyAnimationEnabled(true, nil, nil),
		"applyAnimationEnabled must return false when jsonOut=true")
}
