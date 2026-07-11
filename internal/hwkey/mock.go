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

package hwkey

import (
	"context"
	"sync"
)

// MockProvider is a scripted Provider for internal/cli tests (mirrors
// secrets.MockStore): the real providers are never constructed in CLI tests,
// so no test can ever reach a live authenticator, keychain, or ssh-keygen -w.
type MockProvider struct {
	mu sync.Mutex

	// ProviderKind is returned by Kind (defaults to KindFIDO2 when empty).
	ProviderKind Kind
	// AvailableProbe is returned by Available.
	AvailableProbe Probe
	// EnrollResult / EnrollErr are returned by Enroll.
	EnrollResult *EnrolledKey
	EnrollErr    error
	// VerifyResult / VerifyErr are returned by Verify.
	VerifyResult KeyInfo
	VerifyErr    error

	// Recorded calls.
	AvailableCalls int
	EnrollCalls    []EnrollRequest
	VerifyCalls    []string
}

// NewMockProvider returns an empty MockProvider (zero-value scripting: probe
// not OK, Enroll returns nil/nil-error unless scripted).
func NewMockProvider() *MockProvider { return &MockProvider{} }

// Kind returns the scripted provider kind (KindFIDO2 when unset).
func (m *MockProvider) Kind() Kind {
	if m.ProviderKind == "" {
		return KindFIDO2
	}
	return m.ProviderKind
}

// Available records the call and returns the scripted probe.
func (m *MockProvider) Available(_ context.Context) Probe {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AvailableCalls++
	return m.AvailableProbe
}

// Enroll records the request and returns the scripted result.
func (m *MockProvider) Enroll(_ context.Context, req EnrollRequest) (*EnrolledKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EnrollCalls = append(m.EnrollCalls, req)
	return m.EnrollResult, m.EnrollErr
}

// Verify records the path and returns the scripted result.
func (m *MockProvider) Verify(_ context.Context, pubPath string) (KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.VerifyCalls = append(m.VerifyCalls, pubPath)
	return m.VerifyResult, m.VerifyErr
}
