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

package acl

import (
	"bytes"
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestACLManager builds an ACLManager (via the tailscale adapter) using a
// mock runner. This is the test-layer boundary: tests use backend.ACLManager
// rather than importing internal/tailscale directly (depguard).
func newTestACLManager(t *testing.T) (backend.ACLManager, shell.Runner) {
	t.Helper()
	r := shell.NewMockRunner()
	cfg := config.Defaults()
	b, err := backend.New(cfg, r)
	require.NoError(t, err)
	aclMgr, ok := b.(backend.ACLManager)
	require.True(t, ok, "tailscale adapter must implement ACLManager")
	return aclMgr, r
}

func TestApplyDesired_Idempotent(t *testing.T) {
	aclMgr, _ := newTestACLManager(t)
	owner := "owner@example.com"
	user := "alice"

	editor, err := aclMgr.NewACLEditor(aclMgr.DefaultACL(owner, user))
	require.NoError(t, err)

	// First application against the default ACL is a no-op (default already has it).
	before := append([]byte(nil), editor.Bytes()...)
	require.NoError(t, applyDesired(editor, owner, user, "12h"))
	assert.True(t, bytes.Equal(before, editor.Bytes()), "applying to a converged ACL must not change it")

	// Re-applying is still a no-op.
	again := append([]byte(nil), editor.Bytes()...)
	require.NoError(t, applyDesired(editor, owner, user, "12h"))
	assert.True(t, bytes.Equal(again, editor.Bytes()))
}

func TestApplyDesired_AddsToEmptyACL(t *testing.T) {
	aclMgr, _ := newTestACLManager(t)

	editor, err := aclMgr.NewACLEditor([]byte(`{}`))
	require.NoError(t, err)

	before := append([]byte(nil), editor.Bytes()...)
	require.NoError(t, applyDesired(editor, "owner@example.com", "bob", "6h"))
	assert.False(t, bytes.Equal(before, editor.Bytes()), "an empty ACL must gain the abysslink grant + ssh rule")

	out := string(editor.Bytes())
	assert.Contains(t, out, "tag:mobile")
	assert.Contains(t, out, "tcp:22")
	assert.Contains(t, out, "udp:60000-61000")
	assert.Contains(t, out, "6h")
}

func TestHasAdminCreds(t *testing.T) {
	cfg := config.Defaults()
	m := New(modules.Deps{Cfg: cfg})
	assert.False(t, m.hasAdminCreds(), "no creds configured by default")

	cfg.Tailnet.Admin.Tailnet = "example.com"
	cfg.Tailnet.Admin.OAuthClientID = "abc"
	t.Setenv("ABYSSLINK_TS_OAUTH_SECRET", "shh")
	assert.True(t, m.hasAdminCreds(), "all three present → admin mode")
}

func TestSSHUserFallback(t *testing.T) {
	cfg := config.Defaults()
	m := New(modules.Deps{Cfg: cfg})
	cfg.Identity.UnixUser = "configured"
	assert.Equal(t, "configured", m.sshUser())

	cfg.Identity.UnixUser = ""
	t.Setenv("USER", "envuser")
	assert.Equal(t, "envuser", m.sshUser())
}

// TestApplyManual_PausesBeforeAndAfterOpenURL asserts that applyManual calls
// m.prompt at least twice: once before opening the browser (the pre-open
// instruction notice) and once after (the post-paste confirmation).
// This is the regression guard for the fix in plan 260530-8mf.
// mockACLBackend is a test double that implements backend.Client +
// backend.ACLManager. GetACL returns the pre-canned bytes given at construction;
// DefaultACL and NewACLEditor delegate to the real tailscale adapter so the
// HuJSON round-trip is accurate.
type mockACLBackend struct {
	backend.Client
	aclMgr backend.ACLManager
	raw    []byte
}

func (m *mockACLBackend) GetACL(_ context.Context) ([]byte, string, error) {
	return m.raw, `"test-etag"`, nil
}

func (m *mockACLBackend) SetACL(_ context.Context, _ []byte, _ string) error { return nil }

func (m *mockACLBackend) NewACLEditor(raw []byte) (backend.ACLEditor, error) {
	return m.aclMgr.NewACLEditor(raw)
}

func (m *mockACLBackend) DefaultACL(owner, sshUser string) []byte {
	return m.aclMgr.DefaultACL(owner, sshUser)
}

func (m *mockACLBackend) Diff(oldBytes, newBytes []byte) string {
	return m.aclMgr.Diff(oldBytes, newBytes)
}

func TestACLDriftOK(t *testing.T) {
	// Clean path: Verify is called with admin creds set and the live ACL is
	// already converged (bytes.Equal == true) → must return a SeverityOK finding
	// with Check=="acl_drift".
	t.Setenv("ABYSSLINK_TS_OAUTH_SECRET", "test-secret")

	cfg := config.Defaults()
	cfg.Identity.Email = "owner@example.com"
	cfg.Identity.UnixUser = "alice"
	cfg.Mobile.SSHCheckPeriod = "12h"
	cfg.Tailnet.Admin.Tailnet = "example.com"
	cfg.Tailnet.Admin.OAuthClientID = "client-id"

	// Build the real tailscale adapter to use its NewACLEditor / DefaultACL.
	r := shell.NewMockRunner()
	realBknd, err := backend.New(cfg, r)
	require.NoError(t, err)
	realACLMgr, ok := realBknd.(backend.ACLManager)
	require.True(t, ok)

	// Build the already-converged ACL (default ACL already contains the required grant).
	raw := realACLMgr.DefaultACL(cfg.Identity.Email, cfg.Identity.UnixUser)

	mock := &mockACLBackend{Client: realBknd, aclMgr: realACLMgr, raw: raw}
	m := New(modules.Deps{Cfg: cfg, Runner: r, Backend: mock})

	findings, verifyErr := m.Verify(context.Background())
	require.NoError(t, verifyErr)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "acl_drift" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"acl_drift\" on no-drift path, got none")
	}
	assert.Equal(t, modules.SeverityOK, found.Severity, "no-drift path must emit SeverityOK for acl_drift")
}

func TestApplyManual_PausesBeforeAndAfterOpenURL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	auditLog := filepath.Join(dir, "audit.log")
	a := audit.New(auditLog)

	// MockRunner handles two shell calls applyManual issues in order:
	//   1. RunWithStdin(..., "pbcopy"|"wl-copy"|"xclip", ...) — clipboard copy
	//   2. Run(..., "open"|"xdg-open", aclEditorURL) — browser open
	// Both succeed with zero exit code so applyManual proceeds normally.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}}, // clipboard
		shell.Call{Result: shell.Result{ExitCode: 0}}, // openURL
	)

	promptCount := 0
	countingPrompt := func(_ context.Context, _ string) error {
		promptCount++
		return nil
	}

	cfg := config.Defaults()
	cfg.Identity.Email = "owner@example.com"
	cfg.Identity.UnixUser = "testuser"
	cfg.Mobile.SSHCheckPeriod = "12h"

	// Build a backend.Client (tailscale adapter) so ACLManager assertions succeed.
	bknd, err := backend.New(cfg, r)
	require.NoError(t, err)

	m := New(modules.Deps{
		Cfg:     cfg,
		Runner:  r,
		Backend: bknd,
		Audit:   a,
		Prompt:  countingPrompt,
	})

	// Build a valid desired ACL the same way applyManual does internally so we
	// can confirm the function reaches the prompt calls and does not bail early.
	owner := cfg.Identity.Email
	user := cfg.Identity.UnixUser
	checkPeriod := cfg.Mobile.SSHCheckPeriod

	aclMgr, ok := bknd.(backend.ACLManager)
	require.True(t, ok, "tailscale adapter must implement ACLManager")

	err = m.applyManual(context.Background(), aclMgr, owner, user, checkPeriod)
	require.NoError(t, err, "applyManual must succeed with valid config and a mock runner")

	assert.GreaterOrEqual(t, promptCount, 2,
		"applyManual must call m.prompt at least twice: once before openURL (pre-open notice) and once after (post-paste confirmation); got %d", promptCount)
}

// newManualTestModule builds a Module wired for the applyManual path: temp HOME,
// real audit writer, the provided MockRunner, and the given Prompt /
// DeferManualStep hooks. Returns the module and the ACLManager handle.
func newManualTestModule(t *testing.T, r shell.Runner, prompt func(context.Context, string) error, deferStep func(modules.ManualStep)) (*Module, backend.ACLManager) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfg := config.Defaults()
	cfg.Identity.Email = "owner@example.com"
	cfg.Identity.UnixUser = "testuser"
	cfg.Mobile.SSHCheckPeriod = "12h"

	bknd, err := backend.New(cfg, r)
	require.NoError(t, err)
	aclMgr, ok := bknd.(backend.ACLManager)
	require.True(t, ok, "tailscale adapter must implement ACLManager")

	m := New(modules.Deps{
		Cfg:             cfg,
		Runner:          r,
		Backend:         bknd,
		Audit:           audit.New(filepath.Join(dir, "audit.log")),
		Prompt:          prompt,
		DeferManualStep: deferStep,
	})
	return m, aclMgr
}

// TestApplyManual_DefersStepInsteadOfPrompting is the F-59 regression guard:
// when DeferManualStep is wired (the CLI always wires it), applyManual must
// NOT prompt and must NOT open the browser — a second TUI/interaction while
// the CLI's live apply table owns the terminal races for stdin and corrupts
// terminal state. Instead the module registers a ManualStep carrying the
// notice text, the editor URL, and the post-paste confirmation, then returns.
func TestApplyManual_DefersStepInsteadOfPrompting(t *testing.T) {
	// Script generously: clipboard may take 1 call (darwin: pbcopy) or 2
	// (linux: wl-copy --version probe + copy). openURL must NOT consume any.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)

	promptCalled := false
	var steps []modules.ManualStep
	m, aclMgr := newManualTestModule(t, r,
		func(_ context.Context, _ string) error { promptCalled = true; return nil },
		func(s modules.ManualStep) { steps = append(steps, s) },
	)

	err := m.applyManual(context.Background(), aclMgr, "owner@example.com", "testuser", "12h")
	require.NoError(t, err)

	assert.False(t, promptCalled,
		"applyManual must never call m.prompt when DeferManualStep is wired (F-59)")
	for _, c := range r.RecordedCalls() {
		assert.NotContains(t, []string{"open", "xdg-open"}, c.Name,
			"applyManual must not open the browser itself when DeferManualStep is wired (F-59)")
	}

	require.Len(t, steps, 1, "exactly one manual step must be registered")
	s := steps[0]
	assert.Equal(t, "ACL manual step", s.Title)
	assert.Equal(t, aclEditorURL, s.URL)
	assert.Contains(t, s.Body, "copied to your clipboard",
		"clipboard-ok variant must say the ACL is on the clipboard")
	assert.Contains(t, s.Body, aclEditorURL, "body must carry the editor URL for non-interactive replay")
	assert.Contains(t, s.Confirm, "pasted and SAVED",
		"confirm text must instruct the user to paste and save before continuing")
}

// TestApplyManual_DefersStep_ClipboardFailureVariant asserts the deferred step
// carries the paste-from-path fallback text when the clipboard copy fails.
func TestApplyManual_DefersStep_ClipboardFailureVariant(t *testing.T) {
	// Every clipboard call fails (darwin: pbcopy; linux: probe + xclip).
	clipErr := assert.AnError
	r := shell.NewMockRunner(
		shell.Call{Err: clipErr},
		shell.Call{Err: clipErr},
	)

	var steps []modules.ManualStep
	m, aclMgr := newManualTestModule(t, r, nil,
		func(s modules.ManualStep) { steps = append(steps, s) },
	)

	err := m.applyManual(context.Background(), aclMgr, "owner@example.com", "testuser", "12h")
	require.NoError(t, err, "clipboard failure is non-fatal; the step falls back to paste-from-path")

	require.Len(t, steps, 1)
	s := steps[0]
	assert.NotContains(t, s.Body, "copied to your clipboard")
	assert.Contains(t, s.Body, "Could not copy to clipboard — paste from: ")
	assert.Contains(t, s.Body, filepath.Join(".config", "abysslink", "generated", "acl.hujson"),
		"fallback variant must name the generated policy path")
	assert.Equal(t, aclEditorURL, s.URL)
}

// TestApplyManual_DeferredStepHasRecopy is the F-60 guard: the deferred manual
// step must carry a Recopy action, and invoking it must exec the platform
// clipboard tool again with the same ACL bytes — so a user who overwrote the
// clipboard mid-flow can pick "Copy ACL to clipboard again" in the prompt.
func TestApplyManual_DeferredStepHasRecopy(t *testing.T) {
	// Script generously: initial copy takes 1 call (darwin: pbcopy) or 2
	// (linux: wl-copy --version probe + copy); the Recopy invocation takes
	// the same again. 4 scripted successes covers both platforms.
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)

	var steps []modules.ManualStep
	m, aclMgr := newManualTestModule(t, r, nil,
		func(s modules.ManualStep) { steps = append(steps, s) },
	)

	require.NoError(t, m.applyManual(context.Background(), aclMgr, "owner@example.com", "testuser", "12h"))
	require.Len(t, steps, 1)
	require.NotNil(t, steps[0].Recopy, "deferred ACL step must carry a Recopy action (F-60)")

	clipboardCalls := func() []shell.Call {
		var out []shell.Call
		for _, c := range r.RecordedCalls() {
			switch c.Name {
			case "pbcopy", "wl-copy", "xclip":
				if c.Stdin != "" { // the copy itself, not the wl-copy --version probe
					out = append(out, c)
				}
			}
		}
		return out
	}

	before := clipboardCalls()
	require.Len(t, before, 1, "applyManual must perform exactly one initial clipboard copy")

	require.NoError(t, steps[0].Recopy(context.Background()))

	after := clipboardCalls()
	require.Len(t, after, 2, "invoking Recopy must exec the clipboard tool again")
	assert.Equal(t, before[0].Stdin, after[1].Stdin,
		"Recopy must pipe the same desired ACL bytes to the clipboard tool")
	assert.Contains(t, after[1].Stdin, "tag:mobile", "recopied payload must be the generated ACL")
}

// TestApplyManual_RecopySetEvenWhenInitialCopyFails: the paste-from-path
// variant benefits most from Recopy — a later retry may succeed even though
// the copy during applyManual failed.
func TestApplyManual_RecopySetEvenWhenInitialCopyFails(t *testing.T) {
	// Initial clipboard attempts all fail; the Recopy retry then succeeds.
	// Call counts differ per platform: darwin issues 1 call per copy (pbcopy),
	// linux issues 2 (wl-copy --version probe + copy), so script exactly.
	var script []shell.Call
	if runtime.GOOS == "darwin" {
		script = []shell.Call{
			{Err: assert.AnError},               // initial pbcopy fails
			{Result: shell.Result{ExitCode: 0}}, // recopy pbcopy succeeds
		}
	} else {
		script = []shell.Call{
			{Err: assert.AnError},               // initial probe fails → xclip
			{Err: assert.AnError},               // initial xclip fails
			{Result: shell.Result{ExitCode: 0}}, // recopy probe succeeds → wl-copy
			{Result: shell.Result{ExitCode: 0}}, // recopy wl-copy succeeds
		}
	}
	r := shell.NewMockRunner(script...)

	var steps []modules.ManualStep
	m, aclMgr := newManualTestModule(t, r, nil,
		func(s modules.ManualStep) { steps = append(steps, s) },
	)

	require.NoError(t, m.applyManual(context.Background(), aclMgr, "owner@example.com", "testuser", "12h"))
	require.Len(t, steps, 1)
	require.NotNil(t, steps[0].Recopy,
		"Recopy must be set even when the initial copy failed (paste-from-path variant)")
	require.NoError(t, steps[0].Recopy(context.Background()),
		"a later Recopy retry must be able to succeed")
}

// TestEnforceCheckPeriodCeiling covers the NET-01 module-level gate that
// mirrors checkPeriodGate in cmd_up.go: checkPeriod is settable down but never
// up past 12h without explicit consent, and malformed values fail closed.
func TestEnforceCheckPeriodCeiling(t *testing.T) {
	// Allowed without consent: empty (defaults to 12h), 12h, and lower.
	require.NoError(t, enforceCheckPeriodCeiling("", false), "empty defaults to 12h and must pass")
	require.NoError(t, enforceCheckPeriodCeiling("12h", false), "12h is the default and must pass")
	require.NoError(t, enforceCheckPeriodCeiling("6h", false), "lowering below 12h must pass")

	// Blocked without consent: anything above 12h.
	assert.Error(t, enforceCheckPeriodCeiling("12h1m", false), "raising above 12h must be blocked")
	assert.Error(t, enforceCheckPeriodCeiling("24h", false))
	assert.Error(t, enforceCheckPeriodCeiling("168h", false), "config.Validate allows 168h — the module gate must not")

	// Allowed with explicit consent threaded in.
	assert.NoError(t, enforceCheckPeriodCeiling("24h", true), "above 12h allowed with explicit consent")
	assert.NoError(t, enforceCheckPeriodCeiling("168h", true))

	// Malformed durations fail closed regardless of consent.
	assert.Error(t, enforceCheckPeriodCeiling("not-a-duration", false))
	assert.Error(t, enforceCheckPeriodCeiling("not-a-duration", true), "malformed must fail closed even with consent")
}

// TestApply_CheckPeriodCeilingEnforced is the NET-01 regression test:
// `abysslink repair` and `acl apply` reach Module.Apply without passing
// through cmd_up's checkPeriodGate, so the module itself must refuse to push
// an extended checkPeriod into the tailnet ACL unless the acceptance flag was
// threaded in via modules.Deps.
func TestApply_CheckPeriodCeilingEnforced(t *testing.T) {
	t.Setenv("ABYSSLINK_TS_OAUTH_SECRET", "test-secret")

	cfg := config.Defaults()
	cfg.Identity.Email = "owner@example.com"
	cfg.Identity.UnixUser = "alice"
	cfg.Mobile.SSHCheckPeriod = "24h" // above the immutable 12h default
	cfg.Tailnet.Admin.Tailnet = "example.com"
	cfg.Tailnet.Admin.OAuthClientID = "client-id"

	r := shell.NewMockRunner() // no shell calls may happen on the refusal path
	realBknd, err := backend.New(cfg, r)
	require.NoError(t, err)
	realACLMgr, ok := realBknd.(backend.ACLManager)
	require.True(t, ok)
	raw := realACLMgr.DefaultACL(cfg.Identity.Email, cfg.Identity.UnixUser)
	mock := &mockACLBackend{Client: realBknd, aclMgr: realACLMgr, raw: raw}

	// Without consent: Apply must refuse before touching the backend.
	m := New(modules.Deps{Cfg: cfg, Runner: r, Backend: mock})
	err = m.Apply(context.Background())
	require.Error(t, err, "Apply must refuse to push checkPeriod 24h without consent")
	assert.Contains(t, err.Error(), "accept-checkperiod-extension",
		"error must tell the user how to consent explicitly")

	// Repair delegates to Apply — the exact path NET-01 flagged as bypassing
	// the cmd_up gate.
	err = m.Repair(context.Background())
	require.Error(t, err, "Repair must hit the same ceiling gate as Apply")

	// With explicit consent threaded through Deps, Apply proceeds.
	m2 := New(modules.Deps{Cfg: cfg, Runner: r, Backend: mock, AcceptCheckPeriodExtension: true})
	require.NoError(t, m2.Apply(context.Background()),
		"Apply must proceed when the user explicitly accepted the extension")
}
