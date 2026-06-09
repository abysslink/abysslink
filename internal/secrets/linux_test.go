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

//go:build linux

package secrets_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

// newSecretToolStore builds a LinuxStore on the secret-tool backend with the
// given scripted calls following the `which secret-tool` probe.
func newSecretToolStore(t *testing.T, calls ...shell.Call) *secrets.LinuxStore {
	t.Helper()
	all := append([]shell.Call{{Result: shell.Result{ExitCode: 0}}}, calls...) // which secret-tool → found
	runner := shell.NewMockRunner(all...)
	store, err := secrets.NewLinuxStore(context.Background(), runner)
	require.NoError(t, err)
	require.Equal(t, "secret-tool", store.Backend())
	return store
}

// newPassStore builds a LinuxStore on the pass backend with the given scripted
// calls following the two `which` probes (secret-tool missing, pass found).
func newPassStore(t *testing.T, calls ...shell.Call) *secrets.LinuxStore {
	t.Helper()
	all := append([]shell.Call{
		{Result: shell.Result{ExitCode: 1}}, // which secret-tool → missing
		{Result: shell.Result{ExitCode: 0}}, // which pass → found
	}, calls...)
	runner := shell.NewMockRunner(all...)
	store, err := secrets.NewLinuxStore(context.Background(), runner)
	require.NoError(t, err)
	require.Equal(t, "pass", store.Backend())
	return store
}

// TestLinuxSecretTool_GetNotFound proves CORE-02: a silent non-zero exit
// (secret-tool's genuinely-not-found signature) maps to secrets.ErrNotFound.
func TestLinuxSecretTool_GetNotFound(t *testing.T) {
	store := newSecretToolStore(t, shell.Call{Result: shell.Result{ExitCode: 1}})

	_, err := store.Get(context.Background(), "svc", "acct")
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrNotFound))
	assert.Contains(t, err.Error(), "secret not found") // COMPAT substring
}

// TestLinuxSecretTool_GetUnavailableIsNotNotFound proves CORE-02: a non-zero
// exit WITH stderr output (dbus down, collection locked) must NOT be reported
// as "secret not found".
func TestLinuxSecretTool_GetUnavailableIsNotNotFound(t *testing.T) {
	store := newSecretToolStore(t, shell.Call{Result: shell.Result{
		ExitCode: 1,
		Stderr:   "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY",
	}})

	_, err := store.Get(context.Background(), "svc", "acct")
	require.Error(t, err)
	assert.False(t, errors.Is(err, secrets.ErrNotFound))
	assert.Contains(t, err.Error(), "keychain unavailable")
	assert.NotContains(t, err.Error(), "secret not found")
}

// TestLinuxPass_GetNotFound proves CORE-02 for the pass backend: the canonical
// "is not in the password store" stderr maps to secrets.ErrNotFound.
func TestLinuxPass_GetNotFound(t *testing.T) {
	store := newPassStore(t, shell.Call{Result: shell.Result{
		ExitCode: 1,
		Stderr:   "Error: svc/acct is not in the password store.",
	}})

	_, err := store.Get(context.Background(), "svc", "acct")
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrNotFound))
	assert.Contains(t, err.Error(), "secret not found") // COMPAT substring
}

// TestLinuxPass_GetUnavailableIsNotNotFound proves CORE-02: a gpg/agent
// failure must NOT be reported as "secret not found".
func TestLinuxPass_GetUnavailableIsNotNotFound(t *testing.T) {
	store := newPassStore(t, shell.Call{Result: shell.Result{
		ExitCode: 2,
		Stderr:   "gpg: decryption failed: No secret key",
	}})

	_, err := store.Get(context.Background(), "svc", "acct")
	require.Error(t, err)
	assert.False(t, errors.Is(err, secrets.ErrNotFound))
	assert.Contains(t, err.Error(), "keychain unavailable")
	assert.NotContains(t, err.Error(), "secret not found")
}
