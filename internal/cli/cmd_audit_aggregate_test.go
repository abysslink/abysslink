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
	t.Run("dry_run_does_not_chmod", func(t *testing.T) {
		// WR-01: a dry-run now records the would-be mutation, so isolate the
		// audit-log path (DefaultLogPath honors XDG_STATE_HOME) to keep the
		// developer's real log clean.
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		logPath := filepath.Join(t.TempDir(), "audit.log")
		require.NoError(t, os.WriteFile(logPath, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(logPath, 0o644)) // lax perms, bypass umask

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		// dryRun=true (no --apply): print would-be chmod, do NOT mutate.
		runAuditFix(p, logPath, true)

		fi, err := os.Stat(logPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "dry-run must not chmod")
		assert.Contains(t, out.String(), "would chmod")

		// WR-01: the dry-run must leave an audit record (DryRun=true) so a --fix
		// preview that enumerates targets is not a traceless action.
		defLog, err := audit.DefaultLogPath()
		require.NoError(t, err)
		entries, err := audit.ReadLog(defLog)
		require.NoError(t, err)
		require.NotEmpty(t, entries, "dry-run --fix must record the would-be mutation")
		last := entries[len(entries)-1]
		assert.Equal(t, "sec-fix", last.Op)
		assert.True(t, last.DryRun, "dry-run record must be tagged DryRun=true")
	})

	t.Run("apply_chmods_audit_log", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "audit.log")
		require.NoError(t, os.WriteFile(logPath, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(logPath, 0o644)) // lax perms

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		runAuditFix(p, logPath, false) // dryRun=false → apply

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
		applied := secFixChmod(p, sshdPath, false) // dryRun=false → would apply if not refused
		assert.False(t, applied, "sshd path must be refused")

		fi, err := os.Stat(sshdPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "sshd config left unchanged")
	})

	t.Run("symlink_target_refused", func(t *testing.T) {
		// WR-02: if the flagged path is (or is swapped to) a symlink pointing at a
		// sensitive file, --fix --apply must REFUSE and must NOT chmod the target.
		// Isolate the audit-log path so the pre-chmod audit append (which runs
		// before the symlink guard refuses) never touches the developer's log.
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		dir := t.TempDir()
		secret := filepath.Join(dir, "authorized_keys")
		require.NoError(t, os.WriteFile(secret, []byte("ssh-ed25519 AAAA...\n"), 0o600))
		require.NoError(t, os.Chmod(secret, 0o644)) // distinguishable from 0o600

		link := filepath.Join(dir, "abysslink.yaml")
		require.NoError(t, os.Symlink(secret, link))

		var out bytes.Buffer
		p := NewHumanPrinterTo(&out, &out)
		applied := secFixChmod(p, link, false) // dryRun=false → would apply if not refused
		assert.False(t, applied, "symlinked path must be refused")

		fi, err := os.Lstat(secret)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(),
			"chmod must not follow the symlink to the sensitive target")
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
