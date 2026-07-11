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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
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

// lockStatusCall scripts a `tailscale lock status --json` reply for the lock gate.
func lockStatusCall(enabled bool) shell.Call {
	body := `{"Enabled":false}`
	if enabled {
		body = `{"Enabled":true}`
	}
	return shell.Call{Result: shell.Result{Stdout: body}}
}

// newLockGateCC builds a minimal cmdContext driving lockGate with a scripted
// `tailscale lock status --json` reply.
func newLockGateCC(t *testing.T, statusCall shell.Call) (*cmdContext, Printer, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cc := &cmdContext{cfg: config.Defaults(), runner: shell.NewMockRunner(statusCall)}
	return cc, &testPrinter{out: &buf}, &buf
}

// TestLockGate_Enabled_Passes: live Tailnet Lock ON ⇒ gate passes, no audit entry.
func TestLockGate_Enabled_Passes(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cc, p, _ := newLockGateCC(t, lockStatusCall(true))

	require.NoError(t, lockGate(context.Background(), p, cc, false),
		"Tailnet Lock enabled must pass the gate")
	assert.NoFileExists(t, auditLogPathForTest(t), "no audit entry when the gate simply passes")
}

// TestLockGate_OffWithoutFlag_Refuses: live lock OFF and no override flag ⇒ the
// gate refuses (fail-closed) and the message names --accept-lock-disabled.
func TestLockGate_OffWithoutFlag_Refuses(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cc, p, _ := newLockGateCC(t, lockStatusCall(false))

	err := lockGate(context.Background(), p, cc, false)
	require.Error(t, err, "lock off + no flag must refuse")
	assert.Contains(t, err.Error(), "--accept-lock-disabled",
		"the refusal must name the explicit opt-out flag")
	assert.NoFileExists(t, auditLogPathForTest(t),
		"a refusal (no override exercised) must not write a consent audit entry")
}

// TestLockGate_ConfigDisabledStillGated: config `tailnet.lock.enabled=false`
// (intent only) plus a live-off tailnet and no flag ⇒ STILL refuses. Proves the
// gate keys off LIVE status, not config — config cannot bypass it.
func TestLockGate_ConfigDisabledStillGated(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cc, p, _ := newLockGateCC(t, lockStatusCall(false))
	cc.cfg.Tailnet.Lock.Enabled = false // intent to disable — must NOT act as consent

	err := lockGate(context.Background(), p, cc, false)
	require.Error(t, err, "config lock-disabled must not bypass the live-status gate")
	assert.Contains(t, err.Error(), "--accept-lock-disabled")
}

// TestLockGate_NonLockerBackendConfigStillLiveGated: config `backend.type=headscale`
// (whose adapter is NOT a backend.Locker) must NOT make the lock gate "not
// applicable". The tailscale module is always in allModules and still shells
// `tailscale set --ssh`, so the gate keys off the LIVE `tailscale lock status`
// and refuses when lock is off — regardless of the config backend capability
// (LOCK-BACKEND-01). Proves the gate no longer branches on cc.backend().
func TestLockGate_NonLockerBackendConfigStillLiveGated(t *testing.T) {
	for _, backendType := range []string{"headscale", "netbird"} {
		t.Run(backendType, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			cc, p, _ := newLockGateCC(t, lockStatusCall(false))
			cc.cfg.Backend.Type = backendType // non-Locker backend must NOT bypass the live gate

			err := lockGate(context.Background(), p, cc, false)
			require.Error(t, err, "a non-Locker backend config must not skip the live lock gate")
			assert.Contains(t, err.Error(), "--accept-lock-disabled",
				"the refusal must name the explicit opt-out flag")
			assert.NoFileExists(t, auditLogPathForTest(t),
				"a refusal (no override exercised) must not write a consent audit entry")
		})
	}
}

// TestLockGate_NonLockerBackendOverrideAudits: with a non-Locker backend config
// AND --accept-lock-disabled, the gate proceeds via the LIVE probe and still
// writes the audited consent entry — parity with the Tailscale path. Guards
// against the fix regressing into a config-keyed bypass that skips the audit.
func TestLockGate_NonLockerBackendOverrideAudits(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cc, p, _ := newLockGateCC(t, lockStatusCall(false))
	cc.cfg.Backend.Type = "headscale"

	require.NoError(t, lockGate(context.Background(), p, cc, true),
		"lock off WITH the override flag must proceed even on a non-Locker backend config")

	raw, err := os.ReadFile(auditLogPathForTest(t))
	require.NoError(t, err, "override must write a consent audit entry")
	assert.Contains(t, string(raw), "lock-override-consent")
	assert.Contains(t, string(raw), "tailnet-lock")
}

// TestLockGate_OffWithFlag_ProceedsAndAudits: live lock OFF + --accept-lock-disabled
// ⇒ proceeds (nil) AND writes an audit entry op=lock-override-consent,
// target=tailnet-lock, with no secret/body bytes (content=nil).
func TestLockGate_OffWithFlag_ProceedsAndAudits(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cc, p, _ := newLockGateCC(t, lockStatusCall(false))

	require.NoError(t, lockGate(context.Background(), p, cc, true),
		"lock off WITH the override flag must proceed")

	raw, err := os.ReadFile(auditLogPathForTest(t))
	require.NoError(t, err, "override must write a consent audit entry")
	s := string(raw)
	assert.Contains(t, s, "lock-override-consent", "audit op must be lock-override-consent")
	assert.Contains(t, s, "tailnet-lock", "audit target must be tailnet-lock")
	// No secret/body ever: content=nil, so no disablement-secret material can leak.
	assert.NotContains(t, s, "tlsdis:", "audit entry must not contain a disablement secret")
	assert.NotContains(t, s, "tlpub:", "audit entry must not contain lock key material")
}

// TestLockGate_UnknownFailsClosed_NonOverridable: an undeterminable lock status
// (exec error / non-zero exit / unparseable JSON) refuses EVEN WITH the override
// flag — UNKNOWN is fail-closed and non-overridable (D-05 posture).
func TestLockGate_UnknownFailsClosed_NonOverridable(t *testing.T) {
	cases := map[string]shell.Call{
		"exec-error":    {Err: errors.New("socket unreachable")},
		"non-zero-exit": {Result: shell.Result{ExitCode: 1, Stderr: "not logged in"}},
		"garbage-json":  {Result: shell.Result{Stdout: "wat, not json"}},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			cc, p, _ := newLockGateCC(t, call)

			// Even WITH the override flag, UNKNOWN must refuse.
			err := lockGate(context.Background(), p, cc, true)
			require.Error(t, err, "UNKNOWN lock status must refuse even with --accept-lock-disabled")
			assert.Contains(t, err.Error(), "cannot be overridden",
				"UNKNOWN refusal must state it is non-overridable")
			assert.NoFileExists(t, auditLogPathForTest(t),
				"a non-overridable UNKNOWN refusal must not write a consent audit entry")
		})
	}
}

// auditLogPathForTest returns the audit-log path under the test's XDG_STATE_HOME.
func auditLogPathForTest(t *testing.T) string {
	t.Helper()
	return filepath.Join(os.Getenv("XDG_STATE_HOME"), "abysslink", "audit.log")
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

// TestSudoActionsFromActions_RequiresSudoFlag asserts an action that declares
// RequiresSudo is detected even when its description matches no keyword — the
// mosh "make mosh-server reachable" case that raced the spinner and garbled the
// sudo password prompt before the flag existed.
func TestSudoActionsFromActions_RequiresSudoFlag(t *testing.T) {
	acts := []modules.Action{
		{Module: "mosh", Description: "make mosh-server reachable: link onto PATH and allow through firewall", RequiresSudo: true},
		{Module: "notify", Description: "send a test notification"}, // no sudo
		{Module: "power", Description: "disable pmset sleep"},       // keyword fallback
	}
	got := sudoActionsFromActions(acts)
	assert.Len(t, got, 2, "mosh (flag) and power (keyword) require sudo; notify does not")
	joined := strings.Join(got, "\n")
	assert.Contains(t, joined, "mosh", "RequiresSudo action must be detected")
	assert.NotContains(t, joined, "notify", "non-sudo action must not be flagged")

	// The whole point: a RequiresSudo action force-disables the apply spinner.
	assert.False(t, applyAnimationEnabled(false, sudoActionsFromActions(acts), nil),
		"a RequiresSudo action must disable the animated spinner")
}
