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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// oauthSecretEnv is the environment variable holding the Tailscale admin OAuth
// client secret. The secret is never stored in abysslink.yaml or on disk.
const oauthSecretEnv = "ABYSSLINK_TS_OAUTH_SECRET" //nolint:gosec // env var name, not a secret value

// aclEditorURL is the Tailscale admin ACL file editor (manual-mode fallback).
const aclEditorURL = "https://login.tailscale.com/admin/acls/file"

// Module implements the acl module.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
	bknd   backend.Client
	audit  audit.AuditWriter
	prompt func(ctx context.Context, msg string) error
	// deferManualStep registers the manual paste-and-save step with the CLI,
	// which replays it AFTER its own TUI (live apply table) has closed. When
	// set, applyManual must never call prompt/openURL itself: running a huh
	// form while the Bubble Tea live table owns the terminal races for stdin
	// and corrupts terminal state (F-59). Nil only for tests/embedders that
	// do not collect steps — then the legacy prompt+openURL fallback runs.
	deferManualStep func(step modules.ManualStep)
	// acceptCheckPeriodExt records explicit user consent (the
	// --accept-checkperiod-extension flag) to raise the SSH re-auth interval
	// above the immutable 12h security default. Threaded in via
	// modules.Deps.AcceptCheckPeriodExtension (NET-01).
	acceptCheckPeriodExt bool
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{
		runner:               d.Runner,
		cfg:                  d.Cfg,
		bknd:                 d.Backend,
		audit:                d.Audit,
		prompt:               d.Prompt,
		deferManualStep:      d.DeferManualStep,
		acceptCheckPeriodExt: d.AcceptCheckPeriodExtension,
	}
}

// Name returns the module name.
func (m *Module) Name() string { return "acl" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// hasAdminCreds reports whether full admin-API automation is available.
func (m *Module) hasAdminCreds() bool {
	return m.cfg.Tailnet.Admin.Tailnet != "" &&
		m.cfg.Tailnet.Admin.OAuthClientID != "" &&
		os.Getenv(oauthSecretEnv) != ""
}

// sshUser returns the configured UNIX user, falling back to $USER.
func (m *Module) sshUser() string {
	if m.cfg.Identity.UnixUser != "" {
		return m.cfg.Identity.UnixUser
	}
	return os.Getenv("USER")
}

// Detect reports whether the ACL can be managed automatically.
func (m *Module) Detect(_ context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding
	if m.cfg.Identity.Email == "" {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "identity",
			Severity: modules.SeverityWarning,
			Message:  "identity.email not set — cannot generate tailnet ACL tag owners",
		})
	}
	if !m.hasAdminCreds() {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "admin_credentials",
			Severity: modules.SeverityWarning,
			Message:  "no Tailscale admin OAuth client configured — ACL will be applied in manual (clipboard) mode",
		})
	}
	return findings, nil
}

// Plan computes actions needed.
func (m *Module) Plan(_ context.Context, _ bool) ([]modules.Action, error) {
	if m.cfg.Identity.Email == "" {
		return nil, nil
	}
	// Gate on ACLManager capability: if the backend does not support ACL management,
	// emit a WARN finding and skip the plan entry (mirrors Detect WARN idiom :96-103).
	if m.bknd != nil {
		if _, ok := m.bknd.(backend.ACLManager); !ok {
			slog.Warn("acl: backend does not support ACL management — skipping ACL plan entry",
				"backend", m.cfg.Backend.Type)
			return nil, nil
		}
	}
	mode := "push via admin API"
	if !m.hasAdminCreds() {
		mode = "copy to clipboard + open admin editor (manual)"
	}
	return []modules.Action{{
		Module:      m.Name(),
		Description: "ensure tailnet ACL restricts tag:mobile → tag:laptop to tcp/22 + tcp/2586 + udp/60000-61000",
		Explain:     "Locks the phone down to SSH, ntfy (push notifications), and mosh on the laptop; any broader access is denied. " + mode + ".",
		Reversible:  false,
	}}, nil
}

// Apply converges the tailnet ACL: tag owners, the mobile→laptop grant, and the
// SSH check rule. With admin credentials it pushes via the API; otherwise it
// writes the desired policy, copies it to the clipboard, and opens the editor.
func (m *Module) Apply(ctx context.Context) error {
	if m.cfg.Identity.Email == "" {
		return fmt.Errorf("acl apply: identity.email is required to generate the ACL")
	}
	aclMgr, ok := m.bknd.(backend.ACLManager)
	if !ok {
		return fmt.Errorf("acl apply: backend %q has no ACL management support", m.cfg.Backend.Type)
	}
	owner := m.cfg.Identity.Email
	user := m.sshUser()
	checkPeriod := m.cfg.Mobile.SSHCheckPeriod

	// Enforce the 12h ceiling HERE, not only in the CLI's checkPeriodGate
	// (cmd_up.go): `abysslink repair` and `abysslink acl apply` also reach this
	// code path and must not push an extended checkPeriod into the tailnet ACL
	// without explicit consent (NET-01).
	if err := enforceCheckPeriodCeiling(checkPeriod, m.acceptCheckPeriodExt); err != nil {
		return err
	}

	if !m.hasAdminCreds() {
		return m.applyManual(ctx, aclMgr, owner, user, checkPeriod)
	}
	return m.applyAdmin(ctx, aclMgr, owner, user, checkPeriod)
}

// applyAdmin pulls the current ACL, applies the desired changes idempotently,
// and pushes the result with optimistic-concurrency (ETag).
func (m *Module) applyAdmin(ctx context.Context, aclMgr backend.ACLManager, owner, user, checkPeriod string) error {
	cur, etag, err := aclMgr.GetACL(ctx)
	if err != nil {
		return fmt.Errorf("acl apply: pull current ACL: %w", err)
	}

	editor, err := aclMgr.NewACLEditor(cur)
	if err != nil {
		return fmt.Errorf("acl apply: parse current ACL: %w", err)
	}
	before := append([]byte(nil), editor.Bytes()...)
	if err := applyDesired(editor, owner, user, checkPeriod); err != nil {
		return fmt.Errorf("acl apply: edit ACL: %w", err)
	}
	if bytes.Equal(before, editor.Bytes()) {
		slog.Info("acl apply: tailnet ACL already converged")
		return nil
	}

	if err := aclMgr.SetACL(ctx, editor.Bytes(), etag); err != nil {
		return fmt.Errorf("acl apply: push ACL: %w", err)
	}
	slog.Info("acl apply: pushed updated tailnet ACL via admin API")
	return nil
}

// applyManual writes the desired ACL to the generated dir, copies it to the
// clipboard, and opens the admin editor for the user to paste and save.
func (m *Module) applyManual(ctx context.Context, aclMgr backend.ACLManager, owner, user, checkPeriod string) error {
	desired := aclMgr.DefaultACL(owner, user)
	if checkPeriod != "" && checkPeriod != "12h" {
		editor, err := aclMgr.NewACLEditor(desired)
		if err == nil {
			if err := editor.EnsureSSHRule(owner, user, checkPeriod); err == nil {
				desired = editor.Bytes()
			}
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("acl apply: home dir: %w", err)
	}
	genPath := filepath.Join(home, ".config", "abysslink", "generated", "acl.hujson")
	if err := os.MkdirAll(filepath.Dir(genPath), 0o700); err != nil {
		return fmt.Errorf("acl apply: mkdir generated: %w", err)
	}
	if err := m.audit.WriteFile(genPath, desired, 0o600, false); err != nil {
		return fmt.Errorf("acl apply: write generated ACL: %w", err)
	}

	clipOK := true
	if err := m.copyToClipboard(ctx, desired); err != nil {
		slog.Warn("acl apply: could not copy ACL to clipboard; paste it manually", "path", genPath, "err", err)
		clipOK = false
	}

	// Pause so the user reads the instruction before the browser steals focus.
	notice := "\n  ✦  ACL manual step\n"
	if clipOK {
		notice += "     The ACL has been copied to your clipboard.\n"
	} else {
		notice += "     Could not copy to clipboard — paste from: " + genPath + "\n"
	}
	notice += "     Press [Enter] to open the Tailscale ACL editor, then paste and Save.\n"
	notice += "     URL: " + aclEditorURL + "\n"

	const confirmMsg = "\n  ✦  Press [Enter] once you have pasted and SAVED the ACL in the Tailscale admin editor.\n"

	// F-59: never run an interactive prompt from inside Apply — this code may
	// execute while the CLI's live Bubble Tea table owns the terminal, and a
	// concurrent huh form races for stdin (inverted arrow keys, prompt
	// timeouts) and corrupts terminal state on exit. Defer the manual step to
	// the CLI, which replays it (pause → open editor → confirm) after its own
	// TUI has fully closed.
	if m.deferManualStep != nil {
		// Capture the desired ACL bytes so the CLI can re-copy them on demand
		// (F-60: "Copy ACL to clipboard again"). Set regardless of whether the
		// initial copy succeeded — the paste-from-path variant benefits most,
		// since a later retry may succeed (e.g. clipboard tool became available
		// or the user freed the clipboard).
		recopyData := append([]byte(nil), desired...)
		m.deferManualStep(modules.ManualStep{
			Title:   "ACL manual step",
			Body:    notice,
			URL:     aclEditorURL,
			Confirm: confirmMsg,
			Recopy: func(ctx context.Context) error {
				return m.copyToClipboard(ctx, recopyData)
			},
		})
		return nil
	}

	// Legacy fallback (DeferManualStep not wired — tests/embedders only):
	// prompt + open the editor inline. Safe here because no CLI TUI is running.
	m.runManualInteractionFallback(ctx, notice, confirmMsg)
	return nil
}

// runManualInteractionFallback is the pre-F-59 inline interaction: pause on the
// notice, open the admin editor, pause again until the user has pasted and
// saved. Only reachable when Deps.DeferManualStep is nil (tests/embedders) —
// the CLI always wires DeferManualStep so no second TUI ever runs while its
// live table owns the terminal.
func (m *Module) runManualInteractionFallback(ctx context.Context, notice, confirmMsg string) {
	if m.prompt != nil {
		if err := m.prompt(ctx, notice); err != nil {
			slog.Warn("acl apply: prompt interrupted", "err", err)
		}
	}

	if err := m.openURL(ctx, aclEditorURL); err != nil {
		slog.Warn("acl apply: could not open the admin ACL editor; visit it manually", "url", aclEditorURL)
	}

	// Second pause: wait for the user to paste and save before returning.
	// In non-interactive contexts (non-TTY, --yes), the prompt implementation
	// returns nil immediately so this never blocks automated runs.
	if m.prompt != nil {
		if err := m.prompt(ctx, confirmMsg); err != nil {
			slog.Warn("acl apply: post-paste prompt interrupted", "err", err)
		}
	}
}

// Verify checks the live ACL still contains the required grant + SSH rule.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	if m.cfg.Identity.Email == "" || !m.hasAdminCreds() {
		return nil, nil // cannot verify without admin API; manual mode is user-attested
	}
	aclMgr, ok := m.bknd.(backend.ACLManager)
	if !ok {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "acl_manager",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("backend %q has no ACL management support — cannot verify ACL", m.cfg.Backend.Type),
		}}, nil
	}
	cur, _, err := aclMgr.GetACL(ctx)
	if err != nil {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "acl_reachable",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("could not pull ACL to verify: %v", err),
		}}, nil
	}
	editor, err := aclMgr.NewACLEditor(cur)
	if err != nil {
		return nil, fmt.Errorf("acl verify: parse ACL: %w", err)
	}
	before := append([]byte(nil), editor.Bytes()...)
	if err := applyDesired(editor, m.cfg.Identity.Email, m.sshUser(), m.cfg.Mobile.SSHCheckPeriod); err != nil {
		return nil, fmt.Errorf("acl verify: %w", err)
	}
	if !bytes.Equal(before, editor.Bytes()) {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "acl_drift",
			Severity: modules.SeverityWarning,
			Message:  "tailnet ACL is missing the abysslink mobile→laptop grant or SSH rule; run `abysslink up --apply`",
		}}, nil
	}
	// Emit explicit OK so "check ran and passed" is distinguishable from
	// "check never ran" in the threat-model tri-state (D-03 / DOC-01).
	return []modules.Finding{{
		Module:   m.Name(),
		Check:    "acl_drift",
		Severity: modules.SeverityOK,
		Message:  "acl_drift: tailnet ACL matches the required abysslink grant and SSH rule",
	}}, nil
}

// Repair re-applies the ACL.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}

// enforceCheckPeriodCeiling mirrors checkPeriodGate in internal/cli/cmd_up.go:
// the SSH re-auth interval (checkPeriod) is an immutable security default that
// may be lowered but never raised above 12h without the user explicitly passing
// --accept-checkperiod-extension. config.Validate allows values up to 168h, so
// this module-level gate is the last line of defense for code paths that bypass
// the `up` command gate (repair, acl apply) — NET-01.
//
// Semantics mirrored from checkPeriodGate:
//   - empty period: OK (applyDesired falls back to the 12h default)
//   - malformed duration: fail closed (never silently bypass the ceiling)
//   - >12h without consent: error instructing the user how to proceed
func enforceCheckPeriodCeiling(period string, accept bool) error {
	if period == "" {
		return nil // applyDesired defaults empty to "12h"
	}
	d, err := time.ParseDuration(period)
	if err != nil {
		// Fail closed: a malformed duration must NOT silently bypass the 12h
		// re-auth ceiling (an immutable security default).
		return fmt.Errorf("acl apply: mobile.ssh_check_period %q is not a valid duration; refusing to apply (fail-closed)", period)
	}
	if d > 12*time.Hour && !accept {
		return fmt.Errorf("acl apply: mobile.ssh_check_period %s exceeds the 12h security default; "+
			"re-run `abysslink up --apply --accept-checkperiod-extension` to consent to a longer "+
			"re-auth interval, or lower mobile.ssh_check_period to 12h or less", period)
	}
	return nil
}

// applyDesired applies abysslink's required ACL edits idempotently.
func applyDesired(editor backend.ACLEditor, owner, user, checkPeriod string) error {
	if checkPeriod == "" {
		checkPeriod = "12h"
	}
	if err := editor.EnsureTagOwners(owner); err != nil {
		return err
	}
	if err := editor.EnsureGrant(); err != nil {
		return err
	}
	return editor.EnsureSSHRule(owner, user, checkPeriod)
}

// copyToClipboard pipes data into the platform clipboard tool.
func (m *Module) copyToClipboard(ctx context.Context, data []byte) error {
	var tool string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		tool = "pbcopy"
	default: // linux/other
		if _, err := m.runner.Run(ctx, "wl-copy", "--version"); err == nil {
			tool = "wl-copy"
		} else {
			tool, args = "xclip", []string{"-selection", "clipboard"}
		}
	}
	res, err := m.runner.RunWithStdin(ctx, bytes.NewReader(data), tool, args...)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited %d", tool, res.ExitCode)
	}
	return nil
}

// openURL opens a URL in the default browser.
func (m *Module) openURL(ctx context.Context, url string) error {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	_, err := m.runner.Run(ctx, opener, url)
	return err
}
