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

package secrets

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// MockStore is an in-memory KeychainStore for tests. It is goroutine-safe.
// It implements KeychainStore and can be used as a drop-in replacement for
// DarwinStore / LinuxStore in unit tests without invoking any real CLI tools.
//
// PRODUCTION-WIRING HAZARD (R2-I5): MockStore persists NOTHING — every secret
// lives only in process memory and is gone on exit. It compiles into
// production binaries because it cannot carry a build tag: external test
// packages across the repo (internal/cli, internal/audit, internal/fleet, …)
// import it, and a tag would exclude it from their default-tag test builds.
// NEVER wire MockStore into production code paths; the only production
// constructor is secrets.NewStore (store_darwin/linux/other.go). A mis-wire
// would silently "store" the audit HMAC key and other secrets in RAM.
type MockStore struct {
	mu      sync.Mutex
	entries map[string]string // key: service + "\x00" + account
}

// Compile-time guard that MockStore keeps satisfying the production interface
// (so a drift would fail here, in the test double, not at a call site).
var _ KeychainStore = (*MockStore)(nil)

// NewMockStore returns an empty MockStore.
func NewMockStore() *MockStore {
	return &MockStore{entries: make(map[string]string)}
}

func key(service, account string) string { return service + "\x00" + account }

// Set stores the secret in memory. It mirrors the real backends' single-line
// contract: both the darwin (`security -i`) and linux (`pass insert`) stores
// reject a secret containing a newline (it would truncate/inject the composed
// command). Enforcing the same rule here keeps the mock faithful, so a caller
// that tries to store a multi-line value (e.g. a raw PEM key) fails in tests
// the same way it would in production rather than silently "working".
func (m *MockStore) Set(_ context.Context, service, account, secret string) error {
	if strings.ContainsAny(secret, "\n\r") {
		return fmt.Errorf("secrets(mock): secret contains a newline; the real keychain backends reject this (store a single-line/encoded value)")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key(service, account)] = secret
	return nil
}

// Get retrieves the secret from memory.
// Returns an error if the entry was not previously Set.
func (m *MockStore) Get(_ context.Context, service, account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[key(service, account)]
	if !ok {
		// Wraps ErrNotFound so errors.Is matches, exactly like the real stores.
		return "", fmt.Errorf("%w: service=%s account=%s", ErrNotFound, service, account)
	}
	return v, nil
}

// Delete removes the secret from memory.
// It is not an error to delete a key that does not exist.
func (m *MockStore) Delete(_ context.Context, service, account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key(service, account))
	return nil
}
