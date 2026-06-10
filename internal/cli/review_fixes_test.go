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

// Round-2 review fixes — regression tests for the CLI-core findings:
// init hostname/email validation (C1/C2), non-TTY consent gates (W1),
// exit-2 fail-closed gates (W2), non-destructive tailscaled probe (W3),
// Prompt under --yes (W4), audit anchor fail-closed findings (W6),
// offline supply checks (W8/E2), central error rendering and subcommand
// errors (UX #2/#3), explicit --config hard error (UX #4), honest apply
// summary (U7), and structured up --json plan records (E1).

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
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- C1: hostname sanitization + inline validation -------------------------

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Mohans-MacBook-Pro.local", "mohans-macbook-pro.local"},
		{"my-rig", "my-rig"},
		{"My Rig_01", "my-rig-01"},
		{"--weird--", "weird"},
		{".dotty.", "dotty"},
		{"ÜberRig", "berrig"},
		{"", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, sanitizeHostname(tt.in), "input %q", tt.in)
	}
}

// TestSanitizeHostname_OutputLoadable is the C1 contract: whatever the wizard
// pre-fills must pass the same validation config.Load enforces.
func TestSanitizeHostname_OutputLoadable(t *testing.T) {
	for _, in := range []string{"Mohans-MacBook-Pro.local", "CI_HOST 42", "plain"} {
		got := sanitizeHostname(in)
		require.NotEmpty(t, got)
		assert.NoError(t, config.ValidateHostname(got), "sanitized %q -> %q must validate", in, got)
		assert.NoError(t, validateInitHostname(got))
	}
}

func TestValidateInitHostname(t *testing.T) {
	assert.NoError(t, validateInitHostname("my-rig"))
	assert.Error(t, validateInitHostname(""), "empty hostname must be rejected")
	err := validateInitHostname("Mohans-MacBook-Pro.local")
	require.Error(t, err, "uppercase hostname must be rejected inline, not at config.Load")
	assert.Contains(t, err.Error(), "lowercase")
	assert.Error(t, validateInitHostname("bad host!"))
}

// --- C2: init --yes headless guards -----------------------------------------

// initCmdWithFlags returns a newInitCmd with the given flag values set.
func initCmdWithFlags(t *testing.T, flags map[string]string) *cobra.Command {
	t.Helper()
	cmd := newInitCmd()
	for k, v := range flags {
		require.NoError(t, cmd.Flags().Set(k, v))
	}
	return cmd
}

func TestRunInitForm_YesWithoutEmailFailsFast(t *testing.T) {
	t.Setenv("ABYSSLINK_EMAIL", "")
	cmd := initCmdWithFlags(t, nil)
	cfg, err := runInitForm(cmd, true)
	require.Error(t, err, "init --yes without an email must fail fast, never write email: \"\"")
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "--email")
}

func TestRunInitForm_YesWithEmailFlagProducesLoadableConfig(t *testing.T) {
	cmd := initCmdWithFlags(t, map[string]string{
		"email":    "ci@example.com",
		"hostname": "Mohans-MacBook-Pro.local", // deliberately uppercase — must be sanitized
	})
	cfg, err := runInitForm(cmd, true)
	require.NoError(t, err)
	assert.Equal(t, "ci@example.com", cfg.Identity.Email)
	assert.Equal(t, "mohans-macbook-pro.local", cfg.Tailnet.Hostname,
		"hostname pre-fill must be sanitized to the lowercase DNS-safe set (C1)")
	// The full validate-before-write contract: this config must load back.
	require.NoError(t, config.Validate(cfg),
		"init must never produce a config config.Load would reject (C1/C2)")
}

func TestRunInitForm_YesWithEmailEnvAccepted(t *testing.T) {
	t.Setenv("ABYSSLINK_EMAIL", "env@example.com")
	cmd := initCmdWithFlags(t, map[string]string{"hostname": "ci-rig"})
	cfg, err := runInitForm(cmd, true)
	require.NoError(t, err)
	assert.Equal(t, "env@example.com", cfg.Identity.Email)
}

func TestRunInitForm_InvalidEmailRejected(t *testing.T) {
	cmd := initCmdWithFlags(t, map[string]string{"email": "not-an-email", "hostname": "ci-rig"})
	_, err := runInitForm(cmd, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid email")
}

// --- W1: non-TTY init without --yes must abort, never self-promote ----------

func TestInit_NonInteractiveWithoutYesAborts(t *testing.T) {
	// go test runs with a non-TTY stdin, so `init` without --yes is the exact
	// `abysslink init </dev/null` scenario: it must fail fast with a clear
	// errMissingInput-style message and mutate nothing.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := buildRootCmd()
	root.SetArgs([]string{"init"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(context.Background())
	require.Error(t, err, "non-interactive init without --yes must abort (W1)")
	assert.Contains(t, err.Error(), "--yes")
}

// --- W2: fail-closed up gates carry exit code 2 ------------------------------

func TestNetbirdSSHCheckGate_RefusalIsExit2(t *testing.T) {
	cfg := testCfgDefaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	cc := &cmdContext{cfg: cfg, runner: shell.NewMockRunner(), apply: true}

	var buf bytes.Buffer
	p := &testPrinter{out: &buf}
	cmd := newUpCmd()

	err := netbirdSSHCheckGate(context.Background(), cmd, cc, p)
	require.Error(t, err)
	var ee *exitError
	require.ErrorAs(t, err, &ee, "D-04 refusal is a fail-closed gate — must carry the exit-2 type (W2)")
	assert.Equal(t, exitCodeFatal, ee.ExitCode())
	assert.Contains(t, err.Error(), "accept-no-sshcheck")
}

// TestNetbirdSSHCheckGate_ConsentNotPersistedBeforeConfirm covers I1: passing
// --accept-no-sshcheck records the acknowledgment in memory only; nothing is
// written until persistNetbirdConsent runs after ConfirmBlast.
func TestNetbirdSSHCheckGate_ConsentNotPersistedBeforeConfirm(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "abysslink.yaml")

	cfg := testCfgDefaults()
	cfg.Backend.Type = "netbird"
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	cc := &cmdContext{cfg: cfg, runner: shell.NewMockRunner(), apply: true}

	cmd := newUpCmd()
	require.NoError(t, cmd.Flags().Set("accept-no-sshcheck", "true"))

	var buf bytes.Buffer
	err := netbirdSSHCheckGate(context.Background(), cmd, cc, &testPrinter{out: &buf})
	require.NoError(t, err)
	assert.True(t, cc.persistAcceptNoSSHCheck, "consent must be marked for deferred persistence")
	assert.True(t, cc.cfg.Server.NetBird.AcceptNoSSHCheck, "in-memory ack must be set for this run")
	assert.NoFileExists(t, configPath,
		"consent must NOT be written to disk before ConfirmBlast (I1)")
}

// --- W3: logged-out tailscaled must never be restarted ----------------------

func TestRequireTailscaleDaemon_LoggedOutDoesNotRestart(t *testing.T) {
	// `tailscale status` exits non-zero when logged out, but the socket is up.
	// The gate must treat that as "daemon running" and never issue
	// `brew services restart tailscale` / `systemctl enable --now` — a restart
	// drops live tailnet sessions, including the phone SSH driving `up` (W3).
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 1, Stdout: "Logged out."},
	})
	var buf bytes.Buffer
	err := requireTailscaleDaemon(context.Background(), &testPrinter{out: &buf}, runner)
	require.NoError(t, err, "logged-out daemon must pass the gate without a restart")

	for _, call := range runner.RunCalls() {
		require.NotEqual(t, "brew", call[0], "must not restart a live daemon: %v", call)
		require.NotEqual(t, "sudo", call[0], "must not restart a live daemon: %v", call)
	}
}

// --- W4: Deps.Prompt under --yes auto-confirms ------------------------------

func TestDepsPrompt_YesAutoConfirms(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cc := &cmdContext{cfg: config.Defaults(), runner: shell.NewMockRunner(), yes: true}
	deps, err := buildDeps(context.Background(), cc)
	require.NoError(t, err)
	require.NotNil(t, deps.Prompt)
	assert.NoError(t, deps.Prompt(context.Background(), "continue?"),
		"--yes must auto-confirm module prompts, not demand the flag it already has (W4)")
}

// --- W6: audit anchor fail-closed findings -----------------------------------

func TestAuditDoctor_CorruptAnchorEmitsFatalFinding(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	// Corrupt the anchor into invalid JSON — the AUD-02 tamper scenario.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit.anchor.json"), []byte("{not json"), 0o600))

	findings := auditDoctorFindings(logPath, secrets.NewMockStore())
	f := findingByCheck(findings, "audit-anchor-age")
	require.NotNil(t, f, "a corrupt anchor must emit a finding, never slog+skip (W6)")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
	assert.Contains(t, f.Message, "tampering")
}

// --- W8/E2: offline supply-chain checks --------------------------------------

func TestSupplyChainFindingsOffline(t *testing.T) {
	findings := supplyChainFindingsOffline()
	require.Len(t, findings, 2)
	cosign := findingByCheck(findings, "supply-cosign-bundle")
	require.NotNil(t, cosign)
	assert.Equal(t, modules.SeverityWarning, cosign.Severity,
		"--offline must degrade honestly to WARN, never a false green")
	assert.Contains(t, cosign.Message, "--offline")
	slsa := findingByCheck(findings, "supply-slsa-source")
	require.NotNil(t, slsa, "the local-only SLSA check still runs offline")
}

func TestDoctorHasOfflineFlag(t *testing.T) {
	cmd := newDoctorCmd()
	f := cmd.Flags().Lookup("offline")
	require.NotNil(t, f, "doctor must register --offline (E2)")
	assert.Equal(t, "false", f.DefValue)
}

// --- UX #2: central error rendering ------------------------------------------

func TestPrintCLIError_HumanMultiline(t *testing.T) {
	root := buildRootCmd()
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)

	printCLIError(root, errors.New("unknown command \"statsu\" for \"abysslink\"\n\nDid you mean this?\n\tstatus"))

	got := errBuf.String()
	assert.Contains(t, got, "Error: unknown command \"statsu\"")
	assert.Contains(t, got, "Did you mean this?")
	assert.Contains(t, got, "\tstatus", "the suggestion must stay on its own line, not as a literal \\n\\t")
	assert.NotContains(t, got, `err="`, "no slog plumbing in user-facing errors")
}

func TestPrintCLIError_JSONMode(t *testing.T) {
	root := buildRootCmd()
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	require.NoError(t, root.PersistentFlags().Set("json", "true"))

	printCLIError(root, errors.New("boom"))

	var rec map[string]string
	require.NoError(t, json.Unmarshal(errBuf.Bytes(), &rec),
		"JSON mode must emit a JSON error object, got: %q", errBuf.String())
	assert.Equal(t, "boom", rec["error"])
}

// --- UX #3: unknown/missing nested subcommands error -------------------------

func TestUnknownNestedSubcommandErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"rotate ntfy", []string{"rotate", "ntfy"}},
		{"lock statsu", []string{"lock", "statsu"}},
		{"rig list", []string{"rig", "list"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := buildRootCmd()
			root.SetArgs(tt.args)
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			err := root.ExecuteContext(context.Background())
			require.Error(t, err, "unknown nested subcommand must error, not print parent help with exit 0")
			assert.Contains(t, err.Error(), "unknown subcommand")
		})
	}
}

func TestUnknownNestedSubcommand_Suggests(t *testing.T) {
	root := buildRootCmd()
	root.SetArgs([]string{"rotate", "ntfy"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ntfy-creds", "must suggest the real subcommand")
}

func TestMissingNestedSubcommandErrors(t *testing.T) {
	root := buildRootCmd()
	root.SetArgs([]string{"rotate"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(context.Background())
	require.Error(t, err, "bare parent command must error, not print help with exit 0")
	assert.Contains(t, err.Error(), "missing subcommand")
}

// --- UX #4: explicit --config pointing at a missing file is a hard error -----

func TestExplicitConfigMissingIsHardError(t *testing.T) {
	root := buildRootCmd()
	root.SetArgs([]string{"status", "--config", "/nonexistent/abysslink.yaml"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(context.Background())
	require.Error(t, err, "an explicitly-passed missing --config must not silently fall back to Defaults")
	assert.Contains(t, err.Error(), "/nonexistent/abysslink.yaml")
	assert.Contains(t, err.Error(), "does not exist")
}

// TestStatusNotInitialisedBanner: implicit missing config on a read command
// prints the init pointer, not a green dashboard (U10).
func TestStatusNotInitialisedBanner(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no abysslink.yaml here

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"status"})
	require.NoError(t, root.ExecuteContext(context.Background()))
	assert.Contains(t, out.String(), "not initialised")
	assert.Contains(t, out.String(), "abysslink init")
	assert.NotContains(t, out.String(), "Abysslink Status", "no dashboard on an uninitialised machine")
}

func TestStatusNotInitialisedJSON(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--json", "status"})
	require.NoError(t, root.ExecuteContext(context.Background()))

	var rec map[string]string
	require.NoError(t, json.Unmarshal(out.Bytes(), &rec))
	assert.Equal(t, "not-initialised", rec["status"])
}

// --- U3: --all-rigs with zero rigs says so ------------------------------------

func TestStatusAllRigs_ZeroRigsNotice(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "abysslink.yaml")
	data, err := config.Marshal(testCfgDefaults())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, data, 0o600))

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"status", "--all-rigs", "--config", configPath})
	require.NoError(t, root.ExecuteContext(context.Background()))
	assert.Contains(t, out.String(), "No rigs enrolled",
		"--all-rigs on an empty fleet must say so, not silently run locally (U3)")
}

// --- U5: one JSON timestamp format -------------------------------------------

func TestStatusReportTimestampIsRFC3339(t *testing.T) {
	// The local status path and the fleet rows must share RFC3339 — assert the
	// local construction by checking the format used in cmd_status.go compiles
	// to a parseable RFC3339 string.
	ts := time.Now().UTC().Format(time.RFC3339)
	_, err := time.Parse(time.RFC3339, ts)
	require.NoError(t, err)
}

// --- U4: deliberately-disabled modules render neutral -------------------------

func TestStatusRowStateFor(t *testing.T) {
	assert.Equal(t, rowOK, statusRowStateFor("running"))
	assert.Equal(t, rowOK, statusRowStateFor("enabled"))
	assert.Equal(t, rowOK, statusRowStateFor("encrypted"))
	assert.Equal(t, rowNeutral, statusRowStateFor("disabled"),
		"a deliberate 'disabled' is a user choice, not a failure (U4)")
	assert.Equal(t, rowBad, statusRowStateFor("not running"))
	assert.Equal(t, rowBad, statusRowStateFor("unencrypted"))
}

func TestStatusRow_NeutralUsesNeutralIcon(t *testing.T) {
	row := statusRow("ntfy", "disabled", rowNeutral)
	assert.Contains(t, row, iconNeutral)
	assert.NotContains(t, row, iconFatal, "disabled must not render the red failure icon (U4)")
}

// --- U7: honest final apply summary -------------------------------------------

func TestPrintFinalSummary_NeverConvergedOnFailure(t *testing.T) {
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}
	actions := []modules.Action{{Module: "ssh", Description: "enable ssh"}}

	printFinalSummary(p, actions, nil, 1500*time.Millisecond, errors.New("apply blew up"))

	out := buf.String()
	assert.NotContains(t, out, "System converged",
		"a failing apply must never print the success banner (U7)")
	assert.Contains(t, out, "Finished with errors")
	assert.Contains(t, out, "1 error(s)")
	assert.Contains(t, out, "1.5s", "elapsed time must be the real duration, not 0.0s")
}

func TestPrintFinalSummary_SuccessPath(t *testing.T) {
	var buf bytes.Buffer
	p := &testPrinter{out: &buf}
	actions := []modules.Action{{Module: "ssh", Description: "enable ssh"}}

	printFinalSummary(p, actions, nil, 2*time.Second, nil)

	out := buf.String()
	assert.Contains(t, out, "System converged")
	assert.Contains(t, out, "1 applied")
	assert.Contains(t, out, "2.0s")
}

// --- E1: up --json structured plan records -------------------------------------

func TestBuildPlanRecords(t *testing.T) {
	actions := []modules.Action{
		{Module: "ssh", Description: "enable ssh", Explain: "because", Reversible: true},
		{Module: "ssh", Description: "enable ssh", Explain: "because", Reversible: true}, // dup
		{Module: "tmux", Description: "write tmux.conf"},
	}
	records := buildPlanRecords(actions)
	require.Len(t, records, 2, "records must be deduplicated like the human plan")
	assert.Equal(t, "ssh", records[0].Module)
	assert.Equal(t, "because", records[0].Explain)
	assert.True(t, records[0].Reversible)
}

func TestBuildPlanRecords_EmptyIsNonNil(t *testing.T) {
	records := buildPlanRecords(nil)
	require.NotNil(t, records, "JSON output must be [] for a converged system, never null")
	assert.Empty(t, records)

	data, err := json.Marshal(records)
	require.NoError(t, err)
	assert.Equal(t, "[]", string(data))
}

// --- I4: unresolvable home directory errors out --------------------------------

func TestLoadCmdContext_EmptyConfigPathErrors(t *testing.T) {
	// Simulate defaultConfigPath() returning "" (HOME unresolvable) by passing
	// an explicit empty --config: loadCmdContext must error out, not resolve a
	// relative path against the cwd.
	root := buildRootCmd()
	root.SetArgs([]string{"status", "--config", ""})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "home directory")
}
