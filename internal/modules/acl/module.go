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

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tailscale"
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
	audit  *audit.Audit
	prompt func(ctx context.Context, msg string) error
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, audit: d.Audit, prompt: d.Prompt}
}

// Name returns the module name.
func (m *Module) Name() string { return "acl" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// adminClient builds an admin API client from config + the env-provided secret.
// In manual mode (no client ID/secret) the returned client degrades gracefully.
func (m *Module) adminClient() *tailscale.AdminClient {
	return tailscale.NewAdminClient(
		m.cfg.Tailnet.Admin.Tailnet,
		m.cfg.Tailnet.Admin.OAuthClientID,
		os.Getenv(oauthSecretEnv),
	)
}

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
	owner := m.cfg.Identity.Email
	user := m.sshUser()
	checkPeriod := m.cfg.Mobile.SSHCheckPeriod

	if !m.hasAdminCreds() {
		return m.applyManual(ctx, owner, user, checkPeriod)
	}
	return m.applyAdmin(ctx, owner, user, checkPeriod)
}

// applyAdmin pulls the current ACL, applies the desired changes idempotently,
// and pushes the result with optimistic-concurrency (ETag).
func (m *Module) applyAdmin(ctx context.Context, owner, user, checkPeriod string) error {
	admin := m.adminClient()
	cur, etag, err := admin.GetACL(ctx)
	if err != nil {
		return fmt.Errorf("acl apply: pull current ACL: %w", err)
	}

	editor, err := tailscale.NewACLEditor(cur)
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

	if err := admin.SetACL(ctx, editor.Bytes(), etag); err != nil {
		return fmt.Errorf("acl apply: push ACL: %w", err)
	}
	slog.Info("acl apply: pushed updated tailnet ACL via admin API")
	return nil
}

// applyManual writes the desired ACL to the generated dir, copies it to the
// clipboard, and opens the admin editor for the user to paste and save.
func (m *Module) applyManual(ctx context.Context, owner, user, checkPeriod string) error {
	desired := tailscale.DefaultACL(owner, user)
	if checkPeriod != "" && checkPeriod != "12h" {
		editor, err := tailscale.NewACLEditor(desired)
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
		if err := m.prompt(ctx, "\n  ✦  Press [Enter] once you have pasted and SAVED the ACL in the Tailscale admin editor.\n"); err != nil {
			slog.Warn("acl apply: post-paste prompt interrupted", "err", err)
		}
	}

	return nil
}

// Verify checks the live ACL still contains the required grant + SSH rule.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	if m.cfg.Identity.Email == "" || !m.hasAdminCreds() {
		return nil, nil // cannot verify without admin API; manual mode is user-attested
	}
	admin := m.adminClient()
	cur, _, err := admin.GetACL(ctx)
	if err != nil {
		return []modules.Finding{{
			Module:   m.Name(),
			Check:    "acl_reachable",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("could not pull ACL to verify: %v", err),
		}}, nil
	}
	editor, err := tailscale.NewACLEditor(cur)
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
	return nil, nil
}

// Repair re-applies the ACL.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}

// applyDesired applies abysslink's required ACL edits idempotently.
func applyDesired(editor *tailscale.ACLEditor, owner, user, checkPeriod string) error {
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
