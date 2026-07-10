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

// styles_parity_test.go — byte-stability golden tests for the cli status and
// doctor surfaces (Plan 34-02 / TUI-08 success criterion 3).
//
// These goldens are captured BEFORE the Plan 03 color consolidation so that
// any accidental byte change on a non-TTY / NO_COLOR / --json path fails a
// test instead of shipping silently.
//
// Isolation contract (identical to TestUpDryRunParity in parity_test.go):
//   - NO_COLOR=1, CLICOLOR=0 — lipgloss strips all ANSI codes.
//   - XDG_STATE_HOME=t.TempDir() — no real home-dir writes.
//   - noopRunner injected via newRunner seam — no real subprocesses.
//   - notify.HealthProbe overridden to deterministic-unreachable stub.
//   - fetchDaemonStatus overridden to deterministic-unreachable error.
//   - statusNow pinned to a fixed instant — timestamp is byte-stable.
//   - Scoped to darwin to match the up_dryrun_v1.golden convention.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/attest"
	"github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/require"
)

// fixedStatusTime is the pinned clock instant used for the status golden so
// the Timestamp field in the status panel is byte-stable across runs.
var fixedStatusTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// errDaemonUnreachable is the deterministic daemon-unreachable signal injected
// into styles parity tests so the status panel never tries to dial the real
// abysslinkd Unix socket.
var errDaemonUnreachable = errors.New("styles_parity: daemon forced unreachable")

// setupStylesParityEnv sets the standard NO_COLOR / CLICOLOR / XDG_STATE_HOME
// env vars, injects noopRunner + notify.HealthProbe + fetchDaemonStatus +
// statusNow seams, and returns a cleanup function via t.Cleanup (the caller
// need not call it explicitly — t.Cleanup handles it).
//
// Must be called before buildRootCmd() so seam overrides are in place for the
// whole command execution.
func setupStylesParityEnv(t *testing.T) {
	t.Helper()

	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR", "0")
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	// noopRunner: every shell command returns ExitCode=1, nil error — modules
	// produce deterministic "not installed / unavailable" findings.
	origNewRunner := newRunner
	newRunner = func() shell.Runner { return &noopRunner{} }
	t.Cleanup(func() { newRunner = origNewRunner })

	// Deterministic ntfy-unreachable stub (bypasses noopRunner — live dial).
	origProbe := notify.HealthProbe
	notify.HealthProbe = func(_ context.Context, _ string) error { return errProbeUnreachable }
	t.Cleanup(func() { notify.HealthProbe = origProbe })

	// Deterministic daemon-unreachable stub (bypasses noopRunner — live dial).
	origFetch := fetchDaemonStatus
	fetchDaemonStatus = func(_ context.Context) (*statusDaemonExtras, error) {
		return nil, errDaemonUnreachable
	}
	t.Cleanup(func() { fetchDaemonStatus = origFetch })

	// Point the device store at a nonexistent path in the temp dir so that
	// localDeviceEntries() returns nil instead of reading from the developer's
	// real device store (~/.local/state/abysslink/devices.json). The daemon
	// fetch is already forced unreachable above, but without this override the
	// status fallback reads from the real store and bakes real device names
	// into the golden (making it machine-specific and non-deterministic).
	stableDir := t.TempDir()
	origDeviceStorePath := deviceStorePath
	deviceStorePath = func() (string, error) {
		return filepath.Join(stableDir, "devices.json"), nil
	}
	t.Cleanup(func() { deviceStorePath = origDeviceStorePath })

	// Override BOTH audit-path seams to a constant fixed path that does NOT
	// include any process-specific ID. t.TempDir() paths embed a run-unique
	// number (e.g. TestDoctorParity3674253904) that bakes into the doctor
	// output when the sec-audit-log-exists finding renders the path — making
	// the golden non-deterministic. A fixed fake path produces stable finding
	// text across runs.
	//   auditDefaultLogPath — used by audit / cli doctor findings (cmd_doctor.go)
	//   secAuditLogPath     — used by sec-audit-log-{exists,perms} (cmd_doctor_sec.go)
	const fixedAuditPath = "/tmp/abysslink-parity-test/abysslink/audit.log"
	origAuditLogPath := auditDefaultLogPath
	auditDefaultLogPath = func() (string, error) { return fixedAuditPath, nil }
	t.Cleanup(func() { auditDefaultLogPath = origAuditLogPath })

	origSecAuditLogPath := secAuditLogPath
	secAuditLogPath = func() (string, error) { return fixedAuditPath, nil }
	t.Cleanup(func() { secAuditLogPath = origSecAuditLogPath })

	// Pin the clock so the Timestamp field is byte-stable.
	origNow := statusNow
	statusNow = func() time.Time { return fixedStatusTime }
	t.Cleanup(func() { statusNow = origNow })

	// Pin the Phase 37 status seams: v1.yaml carries no hardware_keys stanza
	// (KeyKind omitted) and the boot-state summary is forced to the honest
	// indeterminate value so the golden never depends on the host's SIP /
	// Secure Boot posture.
	origKeyKind := collectKeyKind
	collectKeyKind = func(_ context.Context, _ *cmdContext) string { return "" }
	t.Cleanup(func() { collectKeyKind = origKeyKind })

	origAttestation := collectAttestation
	collectAttestation = func(_ context.Context, _ *cmdContext) string { return "unverified" }
	t.Cleanup(func() { collectAttestation = origAttestation })

	// Point the doctor's attest prober at an empty efivars fixture so the
	// linux secureboot probe (if this ever runs off-darwin) cannot read the
	// host's real efivarfs; on darwin the probes go through noopRunner anyway.
	origProber := newAttestProber
	emptyEFI := filepath.Join(t.TempDir(), "efi", "efivars")
	newAttestProber = func(r shell.Runner) *attest.Prober {
		p := attest.New(r)
		p.EFIVarsDir = emptyEFI
		p.LookPath = func(string) bool { return false }
		return p
	}
	t.Cleanup(func() { newAttestProber = origProber })
}

// captureOrAssertGolden is the shared capture-on-first-run / assert-on-subsequent-run
// helper used by every styles parity test. It mirrors the pattern in TestUpDryRunParity.
func captureOrAssertGolden(t *testing.T, goldenPath, got string) {
	t.Helper()
	if _, statErr := os.Stat(goldenPath); os.IsNotExist(statErr) {
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o750))
		require.NoError(t, os.WriteFile(goldenPath, []byte(got), 0o600),
			"failed to write golden file %s", goldenPath)
		t.Logf("golden captured at %s (%d bytes)", goldenPath, len(got))
		return
	}
	golden, err := os.ReadFile(goldenPath) //nolint:gosec // G304: test reads a committed fixture path, not user input
	require.NoError(t, err)
	require.Equal(t, string(golden), got,
		"output differs from golden %s; if the change is intentional, delete the golden and re-run to regenerate", goldenPath)
}

// TestStatusParity captures the byte-for-byte `abysslink status` non-TTY output
// as a golden fixture (internal/cli/testdata/status_v1.golden).
//
// The status panel renders a bordered box (styleStatusBox uses boxBorder() which
// returns the ASCII +/-/| fallback when NOT a TTY) and status-icon glyphs from
// styles.go (●/○/⚠/✕/→/✓). This golden carries the box-border + status-icon
// coverage for the surfaces Plan 03 leaves untouched in the recolor.
func TestStatusParity(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("parity golden is darwin-scoped; status output differs per-OS")
	}

	setupStylesParityEnv(t)

	cfgPath := filepath.Join("testdata", "v1.yaml")

	var buf bytes.Buffer
	cmd := buildRootCmd()
	cmd.SetArgs([]string{"status", "--config", cfgPath})
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	_ = cmd.Execute()

	got := buf.String()

	goldenPath := filepath.Join("testdata", "status_v1.golden")
	captureOrAssertGolden(t, goldenPath, got)

	// Box-border + status-icon coverage assertions:
	// The status panel renders styleStatusBox which uses boxBorder() → ASCII
	// +/-/| fallback under non-TTY (stdoutIsTTY() is false in the test harness).
	// At least one of the box corner/top characters must appear in the output.
	// The panel also renders icon glyphs for every row (●/○/⚠/✕/→/✓); at least
	// one must be present.
	require.NotEmpty(t, got, "status output must not be empty")
	// box-border: ASCII +/- corner from boxBorder() (non-TTY path).
	require.Contains(t, got, "+", "status golden must contain a box-border corner (+) from boxBorder() ASCII fallback")
	require.Contains(t, got, "-", "status golden must contain a box-border top run (-) from boxBorder() ASCII fallback")
	// status-icon: at least one icon glyph from styles.go (iconOK/Neutral/Warn/Fatal/Arrow/Done).
	hasIcon := false
	for _, glyph := range []string{"●", "○", "⚠", "✕", "→", "✓"} {
		if bytes.Contains([]byte(got), []byte(glyph)) {
			hasIcon = true
			break
		}
	}
	require.True(t, hasIcon, "status golden must contain at least one status icon glyph (● ○ ⚠ ✕ → ✓)")
}

// TestDoctorParity captures the byte-for-byte `abysslink doctor` non-TTY output
// as a golden fixture (internal/cli/testdata/doctor_dryrun_v1.golden).
//
// doctor is a non-mutating, read-only invocation (no --apply flag exists for
// doctor — every check is read-only). The noopRunner makes all shell-calling
// checks produce deterministic "not installed / unavailable" findings.
// volatileDoctorChecks are doctor checks whose presence/severity depends on the
// host environment rather than the styled output under test, so they cannot be
// byte-stable in a styling golden:
//   - network-coupled: what is bound to a local port during the run (real
//     localhost probes that bypass noopRunner).
//   - filesystem-coupled: whether ~/.claude exists. When it does, claudecode
//     emits the deeper hook/settings findings; when it does not (e.g. a clean CI
//     runner) it short-circuits to claude_dir_exists. The claudecode probe is a
//     real os.Stat that bypasses noopRunner, so the finding set flips per host.
//
//nolint:gochecknoglobals // read-only test fixture list.
var volatileDoctorChecks = []string{
	"ntfy_health", "ntfy-loopback", "met-disabled-listener",
	"claude_dir_exists", "stop_hook_configured", "notification_hook_configured", "settings_json_exists",
	// Phase 37 boot-state attestation: presence/severity depends on the host
	// hardware posture, not the styled output under test (the probes are
	// pinned through newAttestProber + noopRunner, but the IDs stay listed so
	// the golden can never flake on a seam drift).
	"sec-attest-sip", "sec-attest-secureboot", "sec-attest-tpm",
}

// normalizeDoctorParity removes the network-coupled finding lines (and any fix:
// continuation that follows them) and replaces the severity-counts summary —
// which shifts when those findings appear/disappear — with a fixed token. Every
// other line (section headers, separator rules, box borders, finding icons and
// their colour bytes) is left intact so the styling parity coverage is preserved.
func normalizeDoctorParity(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	dropFollowingFix := false
	for _, ln := range lines {
		volatile := false
		for _, v := range volatileDoctorChecks {
			if strings.Contains(ln, v) {
				volatile = true
				break
			}
		}
		if volatile {
			dropFollowingFix = true
			continue
		}
		if dropFollowingFix {
			if strings.HasPrefix(strings.TrimSpace(ln), "fix:") {
				continue
			}
			dropFollowingFix = false
		}
		// Severity-counts summary, e.g. "  ✓ 25 ok · ⚠ 32 warn · ✕ 7 fatal".
		if strings.Contains(ln, "ok ·") && strings.Contains(ln, "warn ·") && strings.Contains(ln, "fatal") {
			out = append(out, "  <severity counts normalized for parity>")
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func TestDoctorParity(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("parity golden is darwin-scoped; doctor output differs per-OS")
	}

	setupStylesParityEnv(t)

	cfgPath := filepath.Join("testdata", "v1.yaml")

	var buf bytes.Buffer
	cmd := buildRootCmd()
	cmd.SetArgs([]string{"doctor", "--config", cfgPath})
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	_ = cmd.Execute()

	// This is a STYLING parity golden (box borders, separator rules, finding-icon
	// glyphs, colour bytes) — not a live-network assertion. A few doctor findings
	// dial localhost (ntfy_health → :2586, ntfy-loopback → :2586,
	// met-disabled-listener → :9090) and so flip with whatever else on the machine
	// happens to bind those ports during the run, which made the byte-for-byte
	// golden flaky between an isolated `-run` and a full-suite run. Normalise those
	// network-coupled lines (and the severity-counts summary they shift) out before
	// the compare; every styled/structural line is still byte-checked.
	got := normalizeDoctorParity(buf.String())

	goldenPath := filepath.Join("testdata", "doctor_dryrun_v1.golden")
	captureOrAssertGolden(t, goldenPath, got)

	// doctor output must be non-empty and contain at least one status icon
	// (✓/⚠/✕) — doctor uses iconDoneStr/iconWarnStr/iconFatalStr for findings.
	require.NotEmpty(t, got, "doctor output must not be empty")
	hasIcon := false
	for _, glyph := range []string{"✓", "⚠", "✕"} {
		if bytes.Contains([]byte(got), []byte(glyph)) {
			hasIcon = true
			break
		}
	}
	require.True(t, hasIcon, "doctor golden must contain at least one finding icon glyph (✓ ⚠ ✕)")
}
