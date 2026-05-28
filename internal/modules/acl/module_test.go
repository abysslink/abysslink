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
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/tailscale"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyDesired_Idempotent(t *testing.T) {
	owner := "owner@example.com"
	user := "alice"

	editor, err := tailscale.NewACLEditor(tailscale.DefaultACL(owner, user))
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
	editor, err := tailscale.NewACLEditor([]byte(`{}`))
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
