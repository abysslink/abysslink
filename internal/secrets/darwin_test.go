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

//go:build darwin

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

// TestDarwinStore_SetRejectsControlChars proves CORE-01: any control byte in
// service, account, or secret is rejected BEFORE a `security -i` command line
// is composed — an embedded newline would otherwise inject a second keychain
// command into the line-oriented parser and truncate the stored secret.
func TestDarwinStore_SetRejectsControlChars(t *testing.T) {
	cases := []struct {
		name                     string
		service, account, secret string
	}{
		{"newline in secret", "svc", "acct", "top\nadd-generic-password -U -a evil -s evil -w pwned"},
		{"carriage return in secret", "svc", "acct", "top\rsecret"},
		{"newline in service", "svc\n", "acct", "secret"},
		{"newline in account", "svc", "acct\ninjected", "secret"},
		{"tab in service", "svc\t", "acct", "secret"},
		{"NUL in secret", "svc", "acct", "se\x00cret"},
		{"DEL in account", "svc", "acc\x7ft", "secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No calls scripted: the runner must NEVER be invoked.
			runner := shell.NewMockRunner()
			store := secrets.NewDarwinStore(runner)

			err := store.Set(context.Background(), tc.service, tc.account, tc.secret)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "control character")
			// The secret value must never be echoed in the error.
			assert.NotContains(t, err.Error(), "pwned")
		})
	}
}

// TestDarwinStore_SetAllowsPrintable verifies legitimate values (spaces,
// quotes, backslashes — all handled by shellQuote) still pass validation.
func TestDarwinStore_SetAllowsPrintable(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{ExitCode: 0}})
	store := secrets.NewDarwinStore(runner)

	err := store.Set(context.Background(), `my "svc"`, `acct\name`, "s3cr3t with spaces")
	require.NoError(t, err)
}

// TestDarwinStore_GetNotFound proves CORE-02: exit code 44 (errSecItemNotFound)
// maps to secrets.ErrNotFound — and ONLY that exit code.
func TestDarwinStore_GetNotFound(t *testing.T) {
	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{ExitCode: 44, Stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."},
	})
	store := secrets.NewDarwinStore(runner)

	_, err := store.Get(context.Background(), "svc", "acct")
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrNotFound), "exit 44 must map to ErrNotFound")
	// COMPAT: legacy substring matchers must keep working.
	assert.Contains(t, err.Error(), "secret not found")
}

// TestDarwinStore_GetUnavailableIsNotNotFound proves CORE-02: a locked/denied
// keychain (any non-44 exit) must NOT be reported as "secret not found".
func TestDarwinStore_GetUnavailableIsNotNotFound(t *testing.T) {
	for _, exitCode := range []int{1, 36, 51, 128} {
		runner := shell.NewMockRunner(shell.Call{
			Result: shell.Result{ExitCode: exitCode, Stderr: "security: SecKeychainItemCopyContent: User interaction is not allowed."},
		})
		store := secrets.NewDarwinStore(runner)

		_, err := store.Get(context.Background(), "svc", "acct")
		require.Error(t, err)
		assert.False(t, errors.Is(err, secrets.ErrNotFound), "exit %d must NOT map to ErrNotFound", exitCode)
		assert.Contains(t, err.Error(), "keychain unavailable")
		assert.NotContains(t, err.Error(), "secret not found")
	}
}
