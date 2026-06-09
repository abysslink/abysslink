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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/secrets"
)

// TestErrNotFound_SubstringCompat pins the exact sentinel text: legacy callers
// matched on the "secret not found" substring before the sentinel existed, so
// the string inside ErrNotFound must not be reworded (CORE-02 back-compat).
func TestErrNotFound_SubstringCompat(t *testing.T) {
	assert.Equal(t, "secret not found", secrets.ErrNotFound.Error())
}

// TestMockStore_GetMissingIsErrNotFound proves the in-memory test double wraps
// the same sentinel as the real stores, so errors.Is-based callers behave
// identically under test and in production.
func TestMockStore_GetMissingIsErrNotFound(t *testing.T) {
	m := secrets.NewMockStore()

	_, err := m.Get(context.Background(), "svc", "acct")
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrNotFound))
	// COMPAT: substring matchers keep working on the wrapped error.
	assert.True(t, strings.Contains(err.Error(), "secret not found"))
}
