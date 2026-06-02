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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exitCodeOf extracts the process exit code an aggregate run resolved to. A nil
// error is exit 0; an *exitError carries its own code; any other error is a
// generic exit 1 (matching cobra's RunE convention).
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return exitCodeOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return exitCodeError
}

func TestAuditRollupExitCode(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		findings := []modules.Finding{
			{Module: "sec", Check: "a", Severity: modules.SeverityOK},
			{Module: "sec", Check: "b", Severity: modules.SeverityOK},
		}
		assert.Equal(t, exitCodeOK, aggregateExitCode(findings))
	})
	t.Run("warn_only", func(t *testing.T) {
		findings := []modules.Finding{
			{Module: "sec", Check: "a", Severity: modules.SeverityOK},
			{Module: "sec", Check: "b", Severity: modules.SeverityWarning},
		}
		assert.Equal(t, exitCodeError, aggregateExitCode(findings))
	})
	t.Run("fatal", func(t *testing.T) {
		findings := []modules.Finding{
			{Module: "sec", Check: "a", Severity: modules.SeverityWarning},
			{Module: "sec", Check: "b", Severity: modules.SeverityFatal},
		}
		assert.Equal(t, exitCodeFatal, aggregateExitCode(findings))
	})
}

func TestAuditDedup(t *testing.T) {
	in := []modules.Finding{
		{Module: "sec", Check: "dup", Severity: modules.SeverityFatal, Message: "first"},
		{Module: "metrics", Check: "dup", Severity: modules.SeverityOK, Message: "second"},
		{Module: "sec", Check: "unique", Severity: modules.SeverityOK},
	}
	out := dedupFindings(in)
	require.Len(t, out, 2, "dup collapsed to one, unique kept")
	// First occurrence wins.
	var dup modules.Finding
	for _, f := range out {
		if f.Check == "dup" {
			dup = f
		}
	}
	assert.Equal(t, "first", dup.Message, "first occurrence of a check ID wins")
}

func TestAuditAggregate(t *testing.T) {
	t.Run("clean_chain_no_break", func(t *testing.T) {
		logPath, kc := newSignedLog(t, 2)
		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		cc := newAggregateTestContext(t)
		// A clean chain must NOT emit a CHAIN BROKEN diagnostic. The aggregate
		// may still exit non-zero because the test environment legitimately has
		// FATAL posture findings (no audit log at the tempdir path, MockRunner
		// keychain unavailable, fdesetup unavailable). That is correct behavior —
		// the roll-up exit code is unit-tested separately in TestAuditRollupExitCode.
		_ = runAuditAggregate(context.Background(), cc, p, logPath, kc, aggregateOpts{})
		assert.NotContains(t, out.String(), "CHAIN BROKEN", "clean chain must not report a break")
	})

	t.Run("chain_broken", func(t *testing.T) {
		logPath, kc := newSignedLog(t, 4)
		// Corrupt the prev_hash at entry index 2 to break the chain.
		data, rerr := os.ReadFile(logPath) //nolint:gosec // G304: test reads a fixture under the test's own temp dir, not user input
		require.NoError(t, rerr)
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		require.GreaterOrEqual(t, len(lines), 4)
		var e map[string]any
		require.NoError(t, json.Unmarshal([]byte(lines[2]), &e))
		e["prev_hash"] = "deadbeef"
		mangled, merr := json.Marshal(e)
		require.NoError(t, merr)
		lines[2] = string(mangled)
		require.NoError(t, os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		cc := newAggregateTestContext(t)
		err := runAuditAggregate(context.Background(), cc, p, logPath, kc, aggregateOpts{})
		assert.Equal(t, exitCodeFatal, exitCodeOf(t, err), "chain break → exit 2")
		assert.Contains(t, out.String(), "CHAIN BROKEN")
	})
}

// TestAuditAggregateIncludesMod3 guards B1: collectAggregateFindings must run
// the Phase-21 mod3DoctorFindings source so `abysslink audit verify` does not
// silently drop the optional-module checks. Enabling Upsnap makes the FATAL
// wol-apply-gate finding deterministic.
func TestAuditAggregateIncludesMod3(t *testing.T) {
	cc := newAggregateTestContext(t)
	cc.cfg.Modules.Upsnap.Enabled = true
	logPath, kc := newSignedLog(t, 2)

	var out, errOut bytes.Buffer
	p := NewJSONPrinterTo(&out, &errOut)
	_ = runAuditAggregate(context.Background(), cc, p, logPath, kc, aggregateOpts{format: "json"})

	var got []doctorFinding
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out.String())), &got))

	checks := make(map[string]bool, len(got))
	for _, f := range got {
		checks[f.Check] = true
	}
	assert.True(t, checks["wol-apply-gate"], "aggregate must include the Phase-21 wol-apply-gate mod3 check (B1)")
}

func TestAuditPentest(t *testing.T) {
	t.Run("no_pentest_no_panic", func(t *testing.T) {
		logPath, kc := newSignedLog(t, 2)
		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		cc := newAggregateTestContext(t)
		require.NotPanics(t, func() {
			_ = runAuditAggregate(context.Background(), cc, p, logPath, kc, aggregateOpts{pentest: false})
		})
	})
	t.Run("pentest_no_panic", func(t *testing.T) {
		logPath, kc := newSignedLog(t, 2)
		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		cc := newAggregateTestContext(t)
		require.NotPanics(t, func() {
			_ = runAuditAggregate(context.Background(), cc, p, logPath, kc, aggregateOpts{pentest: true})
		})
	})
}

func TestAuditFormatJSON(t *testing.T) {
	logPath, kc := newSignedLog(t, 2)
	var out, errOut bytes.Buffer
	p := NewJSONPrinterTo(&out, &errOut)
	cc := newAggregateTestContext(t)
	_ = runAuditAggregate(context.Background(), cc, p, logPath, kc, aggregateOpts{format: "json"})
	// stdout must be a valid JSON array of finding objects (chain banner → stderr).
	trimmed := strings.TrimSpace(out.String())
	require.True(t, strings.HasPrefix(trimmed, "["), "json output starts with array: %q", trimmed)
	var got []doctorFinding
	require.NoError(t, json.Unmarshal([]byte(trimmed), &got))
	assert.NotEmpty(t, got, "at least one finding emitted")
}

func TestAuditFix(t *testing.T) {
	t.Run("dry_run_does_not_chmod_or_record", func(t *testing.T) {
		// CR-01/WR-01: a --fix dry-run is a PURE read-only preview — it must not
		// chmod and must record NOTHING in the audit log (recording a dry-run made
		// the preview non-idempotent and, with the unsigned writer, poisoned the
		// signed chain). Isolate the default audit-log path so any stray write
		// would be detectable here, not in the developer's real log.
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		logPath := filepath.Join(t.TempDir(), "audit.log")
		require.NoError(t, os.WriteFile(logPath, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(logPath, 0o644)) // lax perms, bypass umask

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		// dryRun=true (no --apply): print would-be chmod, do NOT mutate or record.
		runAuditFix(context.Background(), p, logPath, nil, true)

		fi, err := os.Stat(logPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "dry-run must not chmod")
		assert.Contains(t, out.String(), "would chmod")

		// The dry-run must NOT append to the default log (no traceless-vs-trail
		// trade-off: a read-only preview writes nothing — CR-01).
		defLog, err := audit.DefaultLogPath()
		require.NoError(t, err)
		entries, err := audit.ReadLog(defLog)
		require.NoError(t, err)
		assert.Empty(t, entries, "dry-run --fix must record NOTHING")
	})

	t.Run("apply_chmods_audit_log", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "audit.log")
		require.NoError(t, os.WriteFile(logPath, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(logPath, 0o644)) // lax perms

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		runAuditFix(context.Background(), p, logPath, nil, false) // dryRun=false → apply

		fi, err := os.Stat(logPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "apply tightens to 0600")
	})

	t.Run("sshd_config_untouched", func(t *testing.T) {
		// A path containing "sshd" must be refused even when --apply is set.
		dir := t.TempDir()
		sshdPath := filepath.Join(dir, "sshd_config")
		require.NoError(t, os.WriteFile(sshdPath, []byte("PermitRootLogin yes\n"), 0o600))
		require.NoError(t, os.Chmod(sshdPath, 0o644))

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		applied := secFixChmod(context.Background(), p, sshdPath, sshdPath, nil, false) // dryRun=false → would apply if not refused
		assert.False(t, applied, "sshd path must be refused")

		fi, err := os.Stat(sshdPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "sshd config left unchanged")
	})

	t.Run("symlink_target_refused", func(t *testing.T) {
		// WR-02: if the flagged path is (or is swapped to) a symlink pointing at a
		// sensitive file, --fix --apply must REFUSE and must NOT chmod the target.
		// The audit append now runs only AFTER a successful chmod (CR-01), so the
		// refused path writes nothing; the isolation here is belt-and-braces.
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		dir := t.TempDir()
		secret := filepath.Join(dir, "authorized_keys")
		require.NoError(t, os.WriteFile(secret, []byte("ssh-ed25519 AAAA...\n"), 0o600))
		require.NoError(t, os.Chmod(secret, 0o644)) // distinguishable from 0o600

		link := filepath.Join(dir, "abysslink.yaml")
		require.NoError(t, os.Symlink(secret, link))

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		applied := secFixChmod(context.Background(), p, link, link, nil, false) // dryRun=false → would apply if not refused
		assert.False(t, applied, "symlinked path must be refused")

		fi, err := os.Lstat(secret)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(),
			"chmod must not follow the symlink to the sensitive target")
	})
}

// TestAuditFixSignedChainIntact is the CR-01 regression: --fix --apply against a
// real SIGNED chain must EXTEND it (signed sec-fix entry), so the very next
// audit.Verify still returns OK. The iteration-1 bug appended an UNSIGNED entry
// (empty prev_hash) into the signed chain, which walkChain reported as CHAIN
// BROKEN → false tamper alarm. It also asserts a dry-run writes nothing.
func TestAuditFixSignedChainIntact(t *testing.T) {
	ctx := context.Background()

	t.Run("apply_extends_signed_chain", func(t *testing.T) {
		// Build a real signed chain at the resolved DEFAULT log path (the chain
		// appendSecFixRecord extends when --apply is used), with lax perms so the
		// fix walk flags it.
		state := t.TempDir()
		t.Setenv("XDG_STATE_HOME", state)
		logPath, err := audit.DefaultLogPath()
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(logPath), 0o700))

		kc := secrets.NewMockStore()
		sa, err := audit.NewSigned(logPath, kc)
		require.NoError(t, err)
		for i := 0; i < 3; i++ {
			var dh [32]byte
			dh[0] = byte(i)
			require.NoError(t, sa.Append(ctx, audit.SignInput{Title: "write", DiffHash: dh}, "/tmp/x", false))
		}
		require.NoError(t, os.Chmod(logPath, 0o644)) // lax perms → fix flags it

		// Pre-condition: the seeded chain verifies.
		pre, err := audit.Verify(ctx, logPath, kc)
		require.NoError(t, err)
		require.True(t, pre.OK, "seeded signed chain must verify before --fix")

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		// --fix --apply: chmod the log to 0600 and record via the SIGNED writer.
		runAuditFix(ctx, p, logPath, kc, false)

		fi, err := os.Stat(logPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "apply tightens to 0600")

		// CR-01 core assertion: the chain still verifies (no CHAIN BROKEN). The
		// sec-fix entry must extend the signed chain, not break it.
		post, err := audit.Verify(ctx, logPath, kc)
		require.NoError(t, err)
		assert.True(t, post.OK, "signed chain must still verify after --fix --apply; reason: %s", post.Reason)
		assert.NotContains(t, post.Reason, "CHAIN BROKEN")

		// The applied (non-dry-run) sec-fix record was appended and signed.
		entries, err := audit.ReadLog(logPath)
		require.NoError(t, err)
		require.NotEmpty(t, entries)
		last := entries[len(entries)-1]
		assert.Equal(t, "sec-fix", last.Op)
		assert.False(t, last.DryRun, "applied record must NOT be tagged DryRun")
		assert.NotEmpty(t, last.Sig, "sec-fix entry must be signed on a signed chain")
		assert.NotEmpty(t, last.PrevHash, "sec-fix entry must chain (non-empty prev_hash)")
	})

	t.Run("dry_run_writes_nothing_to_signed_chain", func(t *testing.T) {
		logPath, kc := newSignedLog(t, 2)
		require.NoError(t, os.Chmod(logPath, 0o644)) // lax perms → fix flags it

		before, err := audit.ReadLog(logPath)
		require.NoError(t, err)

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		runAuditFix(ctx, p, logPath, kc, true) // dryRun → preview only

		after, err := audit.ReadLog(logPath)
		require.NoError(t, err)
		assert.Len(t, after, len(before), "dry-run must not append to the signed chain")

		res, err := audit.Verify(ctx, logPath, kc)
		require.NoError(t, err)
		assert.True(t, res.OK, "chain unchanged by dry-run must still verify")
	})
}

// newAggregateTestContext builds a cmdContext with default config pointed at an
// isolated tempdir HOME so the aggregate run never reads the developer's real
// config or audit log. The MockRunner makes sshd -T fail (degrading to the
// sshd_config parse / sshd-absent path).
func newAggregateTestContext(t *testing.T) *cmdContext {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cfg := config.Defaults()
	cfg.Observability.Metrics.BindAddr = "100.64.0.1:9090"
	cfg.WebUI.BindAddr = "100.64.0.1:8443"
	return &cmdContext{cfg: cfg, runner: shell.NewMockRunner(), dryRun: true}
}
