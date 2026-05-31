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
