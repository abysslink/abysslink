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

package quorum

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/approve"
)

// TestRegression_WrapperCloaking is the QG-1 red-team battery: a floor-DENY or
// V1-catastrophe action cloaked behind a privilege/exec wrapper (sudo, env,
// nice, timeout) OR wrapped in a shell interpreter -c payload MUST still refuse
// — never auto-approve as unanimous ALLOW@High. Each case is the exact argv
// the adversarial audit demonstrated flowing through to OutcomeAllow.
func TestRegression_WrapperCloaking(t *testing.T) {
	cases := []struct {
		label     string
		name      string
		args      []string
		want      Outcome
		floorRule string // non-empty ⇒ the expected stage-0 floor rule
		v1Code    string // non-empty ⇒ the expected V1 veto/escalate code
	}{
		{"sh -c tailscale funnel", "sh", []string{"-c", "tailscale funnel 2586"}, OutcomeDeny, floorFunnelEnable, ""},
		{"env tailscale funnel", "env", []string{"tailscale", "funnel", "2586"}, OutcomeDeny, floorFunnelEnable, ""},
		{"sudo fdesetup disable", "sudo", []string{"fdesetup", "disable"}, OutcomeDeny, floorFileVaultDisable, ""},
		{"sh -c tailscale lock disable", "sh", []string{"-c", "tailscale lock disable"}, OutcomeDeny, floorTailnetLockDisable, ""},
		{"sudo cryptsetup luksErase", "sudo", []string{"cryptsetup", "luksErase", "/dev/sda1"}, OutcomeDeny, floorLUKSErase, ""},
		{"sudo rm -rf /", "sudo", []string{"rm", "-rf", "/"}, OutcomeDeny, "", codeRmRoot},
		{"nice dd to block device", "nice", []string{"dd", "if=/dev/zero", "of=/dev/disk0"}, OutcomeDeny, "", codeDDBlockDevice},
		{"timeout mkfs", "timeout", []string{"9", "mkfs.ext4", "/dev/sda"}, OutcomeDeny, "", codeMkfs},
		{"bash -c rm -rf /", "bash", []string{"-c", "rm -rf /"}, OutcomeDeny, "", codeRmRoot},
		{"python3 -c rmtree", "python3", []string{"-c", "import shutil;shutil.rmtree('/etc')"}, OutcomeEscalate, "", codeOpaqueCommand},
		// Nested cloaking: wrapper wrapping an interpreter wrapping a catastrophe.
		{"sudo sh -c rm -rf /", "sudo", []string{"sh", "-c", "rm -rf /"}, OutcomeDeny, "", codeRmRoot},
		{"ssh host rm -rf /", "ssh", []string{"host", "rm", "-rf", "/"}, OutcomeDeny, "", codeRmRoot},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			e := New(Config{}, WithLogger(discardLogger()))
			d, err := e.Evaluate(context.Background(), c.name, c.args)
			require.NoError(t, err)
			assert.NotEqual(t, OutcomeAllow, d.Outcome,
				"%s must NEVER auto-approve — a wrapper must not launder a catastrophe", c.label)
			assert.Equal(t, c.want, d.Outcome, "%s outcome", c.label)
			if c.floorRule != "" {
				assert.Equal(t, c.floorRule, d.FloorRule, "%s must trip the deny-floor", c.label)
			}
			if c.v1Code != "" {
				assert.Contains(t, d.Matched, c.v1Code, "%s must match the expected V1 rule", c.label)
			}
		})
	}
}

// TestRegression_WrapperCloaking_BenignStillAllows guards the escalate-net from
// over-firing: a benign command behind a wrapper (with no catastrophe inside)
// is re-classified on its effective binary and still allowed.
func TestRegression_WrapperCloaking_BenignStillAllows(t *testing.T) {
	e := New(Config{}, WithLogger(discardLogger()))
	d, err := e.Evaluate(context.Background(), "sudo", []string{"ls", "-la", "/tmp"})
	require.NoError(t, err)
	assert.Equal(t, OutcomeAllow, d.Outcome, "sudo ls must re-classify to a benign ALLOW")
}

// TestRegression_NtfyBindAllInterfaces is the QG-2 floor gap: an ntfy bind to
// ALL interfaces expressed as an empty host or the IPv6 unspecified address
// evades the literal-"0.0.0.0" match. Each must DENY with the ntfy-bind-all
// floor rule; a real tailnet IP must not.
func TestRegression_NtfyBindAllInterfaces(t *testing.T) {
	deny := []struct {
		label string
		args  []string
	}{
		{"empty host value", []string{"serve", "--listen-http", ":2586"}},
		{"empty host attached", []string{"serve", "--listen-http=:2586"}},
		{"ipv6 unspecified bracketed", []string{"serve", "--listen-http", "[::]:2586"}},
		{"ipv6 unspecified triple-colon", []string{"serve", "--listen-http", ":::2586"}},
		{"ipv6 expanded all-zero", []string{"serve", "--listen-http", "[0:0:0:0:0:0:0:0]:2586"}},
		{"literal 0.0.0.0 control", []string{"serve", "--listen-http", "0.0.0.0:2586"}},
	}
	e := New(Config{}, WithLogger(discardLogger()))
	for _, c := range deny {
		t.Run(c.label, func(t *testing.T) {
			d, err := e.Evaluate(context.Background(), "ntfy", c.args)
			require.NoError(t, err)
			assert.Equal(t, OutcomeDeny, d.Outcome, "%s must DENY", c.label)
			assert.Equal(t, floorNtfyBindAll, d.FloorRule, "%s must trip ntfy-bind-all", c.label)
		})
	}

	allow := []struct {
		label string
		args  []string
	}{
		{"tailnet IP", []string{"serve", "--listen-http", "100.64.0.7:2586"}},
		{"loopback", []string{"serve", "--listen-http", "127.0.0.1:2586"}},
	}
	for _, c := range allow {
		t.Run(c.label, func(t *testing.T) {
			d, err := e.Evaluate(context.Background(), "ntfy", c.args)
			require.NoError(t, err)
			assert.NotEqual(t, floorNtfyBindAll, d.FloorRule, "%s must NOT trip ntfy-bind-all", c.label)
		})
	}
}

// TestRegression_RmRootEquivalents is the QG-3 narrowing: root-equivalent rm
// targets must hit the un-askable DENY, not leak to the milder
// rm-recursive-force ESCALATE a phone approver could rubber-stamp.
func TestRegression_RmRootEquivalents(t *testing.T) {
	cases := [][]string{
		{"-rf", "/."},
		{"-rf", "//"},
		{"-rf", "/*/"},
		{"-rf", "/usr"},
		{"-rf", "/etc"},
		{"-r", "-f", "/.."},
	}
	for _, args := range cases {
		v := checkV1(t, nil, "rm", args...)
		assert.Equal(t, VerdictDeny, v.Verdict, "rm %v must DENY (root-equivalent)", args)
		assert.Equal(t, codeRmRoot, v.Code, "rm %v must be rm-root", args)
	}
	// A genuine workspace path stays at the milder rm-recursive-force ESCALATE.
	v := checkV1(t, nil, "rm", "-rf", "./build")
	assert.Equal(t, VerdictEscalate, v.Verdict)
	assert.Equal(t, codeRmRecursiveForce, v.Code)
}

// TestRegression_ForcePushRefspec is the git '+refspec' fail-open: a protected-
// branch force-push using the leading-'+' refspec syntax is a real force-push
// that both V1 and V2 previously missed. Even with V3's dry-run-first
// precondition warmed (the attacker controls it), the action must NOT allow.
func TestRegression_ForcePushRefspec(t *testing.T) {
	// Unit: both detectors now fire.
	assert.True(t, gitForceFlags([]string{"push", "origin", "+main:main"}), "+refspec is a force flag")
	assert.True(t, matchForcePushProtected("git", []string{"push", "origin", "+main:main"}),
		"V1 must flag a +refspec force-push to a protected branch")

	v2 := checkV2(t, nil, nil, "git", "push", "origin", "+refs/heads/main")
	assert.Equal(t, VerdictEscalate, v2.Verdict)
	assert.Equal(t, approve.TierCritical, v2.Tier)
	assert.Equal(t, codeForcePushProtected, v2.Code, "V2 must flag a +refspec force-push to a protected branch")

	// End-to-end with V3's dry-run-first precondition warmed (the finding's
	// self-controlled warming): the ONLY thing catching the force-push is the
	// V1/V2 refspec detection.
	e := New(Config{}, WithLogger(discardLogger()))
	e.RecordExec("git", []string{"push", "--dry-run", "origin", "main"})
	d, err := e.Evaluate(context.Background(), "git", []string{"push", "origin", "+main:main"})
	require.NoError(t, err)
	assert.NotEqual(t, OutcomeAllow, d.Outcome, "a warmed +refspec force-push must not auto-approve")
	assert.Contains(t, d.Matched, codeForcePushProtected)
}

// TestRegression_RateWindowOverflow is the tighten-only bypass: a huge
// rate_window_seconds must not multiply into a NEGATIVE duration that disables
// the destructive-op rate cap. newBehaviorVerifier clamps defensively so the
// cap keeps firing (config load also rejects the value — see the config test).
func TestRegression_RateWindowOverflow(t *testing.T) {
	base := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	cur := base
	clock := func() time.Time { return cur }

	const hugeWindow = 10000000000 // 1e10s — overflows time.Duration*Second unguarded

	v := newBehaviorVerifier(0, 0, hugeWindow, clock, nil)
	assert.Positive(t, int64(v.rateWindow), "clamped window must be positive, never a wrapped-negative")
	assert.Equal(t, time.Duration(MaxRateWindowSeconds)*time.Second, v.rateWindow, "window must clamp to the safe ceiling")

	// 12 destructive ops inside the window exceed the default cap of 10.
	cur = base
	for range 12 {
		v.record("mv", []string{"/nonexistent-src", "/nonexistent-dst"})
		cur = cur.Add(25 * time.Second)
	}
	vote := v.check(context.Background(), action{name: "mv", args: []string{"/nonexistent-a", "/nonexistent-b"}, binary: "mv"})
	assert.Equal(t, VerdictEscalate, vote.Verdict, "the destructive-op rate cap must still fire under an absurd window")
	assert.Equal(t, codeRateWindow, vote.Code)
}

// TestRegression_HomeUnsetFailsClosed is the buildProtectedPaths shrink: when
// os.UserHomeDir fails (HOME unset), the home-based protected scopes vanish
// from the set. V2 and V4 must fail closed (ABSTAIN ⇒ escalate) instead of
// silently allowing a write that could be landing in ~/.ssh.
func TestRegression_HomeUnsetFailsClosed(t *testing.T) {
	sshTarget := filepath.Join("/Users", "victim", ".ssh", "authorized_keys")

	t.Run("V2 abstains for a write with home unresolved", func(t *testing.T) {
		t.Setenv("HOME", "")
		v := newPolicyVerifier(nil, nil)
		require.False(t, v.homeGrounded, "test precondition: HOME must be unresolvable")
		vote := v.check(context.Background(), action{name: "cp", args: []string{"/tmp/evilpubkey", sshTarget}, binary: "cp"})
		assert.Equal(t, VerdictAbstain, vote.Verdict, "V2 must fail closed, not ALLOW, when home is unresolved")
		assert.NotEqual(t, OutcomeAllow, effectiveOutcome(vote))
	})

	t.Run("V4 abstains for a mutating action with home unresolved", func(t *testing.T) {
		t.Setenv("HOME", "")
		v := newReversibilityVerifier(nil, nil, time.Now)
		require.False(t, v.homeGrounded)
		target := tempTarget(t) // a real existing path so the stat sweep is non-empty
		vote := v.check(context.Background(), action{name: "rm", args: []string{"-rf", target}, binary: "rm"})
		assert.NotEqual(t, OutcomeAllow, effectiveOutcome(vote), "V4 must fail closed when home is unresolved")
	})

	t.Run("engine escalates the cloaked ~/.ssh write", func(t *testing.T) {
		t.Setenv("HOME", "")
		e := New(Config{}, WithLogger(discardLogger()))
		d, err := e.Evaluate(context.Background(), "cp", []string{"/tmp/evilpubkey", sshTarget})
		require.NoError(t, err)
		assert.NotEqual(t, OutcomeAllow, d.Outcome,
			"a write into ~/.ssh must not auto-approve merely because HOME is unset")
	})
}

// TestRegression_EvalErrorAudited is the row-7 forensic gap: an evaluation that
// refuses via error (canceled context / exceeded budget) must still append a
// quorum-decision audit entry, so gate-probing leaves a hash-chained trail.
func TestRegression_EvalErrorAudited(t *testing.T) {
	app := &fakeAppender{}
	e := New(Config{}, WithLogger(discardLogger()), WithAuditAppender(app))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := e.Evaluate(canceled, "echo", []string{"hello"})
	require.Error(t, err, "a canceled evaluation must refuse the exec")

	entries := app.all()
	require.Len(t, entries, 1, "a refused-by-error evaluation must still be audited")
	assert.Equal(t, opQuorumDecision, entries[0].op)

	var rec decisionRecord
	require.NoError(t, json.Unmarshal(entries[0].content, &rec))
	assert.Equal(t, "deny", rec.Outcome, "the recorded outcome must be a fail-closed DENY")
	assert.Contains(t, rec.Matched, "eval-error")
	assert.Contains(t, rec.Matched, "context-canceled")
}

// TestRegression_SpendThresholdInertWithoutFunc pins the documented caveat: the
// V3 spend-threshold rule is INERT until a spend source is wired (nil spend
// func ⇒ no escalation even above the threshold). The daemon ships no spend
// source today; the docs now say so, and this guards that contract.
func TestRegression_SpendThresholdInertWithoutFunc(t *testing.T) {
	v := newBehaviorVerifier(1.0 /* $1 threshold */, 0, 0, time.Now, nil /* no spend source */)
	vote := v.check(context.Background(), action{name: "echo", args: []string{"hi"}, binary: "echo"})
	assert.Equal(t, VerdictAllow, vote.Verdict, "with no spend source the spend-threshold rule must stay inert")
	assert.NotEqual(t, codeSpendThreshold, vote.Code)
}
