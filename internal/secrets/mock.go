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
	"sync"
)

// MockStore is an in-memory KeychainStore for tests. It is goroutine-safe.
// It implements KeychainStore and can be used as a drop-in replacement for
// DarwinStore / LinuxStore in unit tests without invoking any real CLI tools.
type MockStore struct {
	mu      sync.Mutex
	entries map[string]string // key: service + "\x00" + account
}

// NewMockStore returns an empty MockStore.
func NewMockStore() *MockStore {
	return &MockStore{entries: make(map[string]string)}
}

func key(service, account string) string { return service + "\x00" + account }

// Set stores the secret in memory.
func (m *MockStore) Set(_ context.Context, service, account, secret string) error {
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
		return "", fmt.Errorf("secret not found: service=%s account=%s", service, account)
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
