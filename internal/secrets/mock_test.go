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

package secrets_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/secrets"
)

func TestMockStore_SetGetDelete(t *testing.T) {
	ctx := context.Background()
	store := secrets.NewMockStore()

	const svc, acct = "abysslink", "tailscale-key"
	testVal := "mock-test-value"

	// Set then Get returns the exact value.
	require.NoError(t, store.Set(ctx, svc, acct, testVal))
	got, err := store.Get(ctx, svc, acct)
	require.NoError(t, err)
	assert.Equal(t, testVal, got)

	// Delete then Get returns an error.
	require.NoError(t, store.Delete(ctx, svc, acct))
	_, err = store.Get(ctx, svc, acct)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found")
}

func TestMockStore_MissingKey(t *testing.T) {
	ctx := context.Background()
	store := secrets.NewMockStore()

	_, err := store.Get(ctx, "no-such-service", "no-such-account")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found")
}

func TestMockStore_DeleteIdempotent(t *testing.T) {
	ctx := context.Background()
	store := secrets.NewMockStore()

	// Deleting a key that was never set must not error.
	require.NoError(t, store.Delete(ctx, "svc", "acct"))
}

func TestMockStore_Overwrite(t *testing.T) {
	ctx := context.Background()
	store := secrets.NewMockStore()

	require.NoError(t, store.Set(ctx, "svc", "acct", "value-one"))
	require.NoError(t, store.Set(ctx, "svc", "acct", "value-two"))

	got, err := store.Get(ctx, "svc", "acct")
	require.NoError(t, err)
	assert.Equal(t, "value-two", got)
}

func TestMockStore_IsolatedKeys(t *testing.T) {
	ctx := context.Background()
	store := secrets.NewMockStore()

	// Same account under different services must not collide.
	require.NoError(t, store.Set(ctx, "service-a", "acct", "alpha"))
	require.NoError(t, store.Set(ctx, "service-b", "acct", "beta"))

	a, err := store.Get(ctx, "service-a", "acct")
	require.NoError(t, err)
	assert.Equal(t, "alpha", a)

	b, err := store.Get(ctx, "service-b", "acct")
	require.NoError(t, err)
	assert.Equal(t, "beta", b)
}

// TestMockStore_ImplementsInterface verifies MockStore satisfies KeychainStore
// at compile time.
func TestMockStore_ImplementsInterface(_ *testing.T) {
	var _ secrets.KeychainStore = secrets.NewMockStore()
}
