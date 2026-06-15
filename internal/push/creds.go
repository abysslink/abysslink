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

package push

import (
	"context"
	"fmt"
	"sync"
)

// CredsSource loads provider credentials for the push gateway.
// Implementations: StubCredsSource (disabled legs), MockCredsSource (tests),
// FileCredsSource (D-04 fallback for LaunchDaemon / headless systemd).
//
// Returned credential bytes are secret-class and must never appear in logs,
// audit entries, or argv.
type CredsSource interface {
	// GetAPNsP8 returns the APNs .p8 key PEM bytes plus key metadata.
	// The pem bytes are secret-class — never log or place on argv.
	GetAPNsP8(ctx context.Context) (pem []byte, keyID, teamID string, err error)

	// GetFCMServiceAccount returns the FCM service-account JSON credential
	// bytes plus the GCP project ID.
	// The credJSON bytes are secret-class — never log or place on argv.
	GetFCMServiceAccount(ctx context.Context) (credJSON []byte, projectID string, err error)
}

// StubCredsSource returns errors for every method — used when the experimental
// APNs/FCM legs are disabled or no creds have been configured (D-14).
type StubCredsSource struct{}

// Compile-time interface guard.
var _ CredsSource = (*StubCredsSource)(nil)

// GetAPNsP8 always returns an error indicating APNs creds are not configured.
func (s *StubCredsSource) GetAPNsP8(_ context.Context) ([]byte, string, string, error) {
	return nil, "", "", fmt.Errorf("push: APNs creds not configured")
}

// GetFCMServiceAccount always returns an error indicating FCM creds are not configured.
func (s *StubCredsSource) GetFCMServiceAccount(_ context.Context) ([]byte, string, error) {
	return nil, "", fmt.Errorf("push: FCM creds not configured")
}

// apnsCredential holds in-memory APNs .p8 creds for MockCredsSource.
type apnsCredential struct {
	pem    []byte
	keyID  string
	teamID string
}

// fcmCredential holds in-memory FCM service-account creds for MockCredsSource.
type fcmCredential struct {
	credJSON  []byte
	projectID string
}

// MockCredsSource is an in-memory, goroutine-safe CredsSource for tests.
// Use SetAPNs and SetFCM to inject credentials; methods return errors if
// the corresponding credential has not been set.
type MockCredsSource struct {
	mu   sync.Mutex
	apns *apnsCredential
	fcm  *fcmCredential
}

// Compile-time interface guard.
var _ CredsSource = (*MockCredsSource)(nil)

// SetAPNs injects APNs credentials into the mock. Goroutine-safe.
func (m *MockCredsSource) SetAPNs(pem []byte, keyID, teamID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.apns = &apnsCredential{pem: pem, keyID: keyID, teamID: teamID}
}

// SetFCM injects FCM service-account credentials into the mock. Goroutine-safe.
func (m *MockCredsSource) SetFCM(credJSON []byte, projectID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fcm = &fcmCredential{credJSON: credJSON, projectID: projectID}
}

// GetAPNsP8 returns the injected APNs credentials, or an error if not set.
func (m *MockCredsSource) GetAPNsP8(_ context.Context) ([]byte, string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.apns == nil {
		return nil, "", "", fmt.Errorf("push: mock APNs creds not set")
	}
	return m.apns.pem, m.apns.keyID, m.apns.teamID, nil
}

// GetFCMServiceAccount returns the injected FCM credentials, or an error if not set.
func (m *MockCredsSource) GetFCMServiceAccount(_ context.Context) ([]byte, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fcm == nil {
		return nil, "", fmt.Errorf("push: mock FCM creds not set")
	}
	return m.fcm.credJSON, m.fcm.projectID, nil
}

// FileCredsSource reads provider credentials from a file at Path.
// The file must be mode 0600, owned by the daemon user, and located outside
// any cloud-synced or backup directory (D-04). Doctor checks enforce these
// constraints and fail closed if permissions loosen.
//
// GetAPNsP8 and GetFCMServiceAccount are implemented in Plan 04 when
// config wiring and the creds file format are finalized.
type FileCredsSource struct {
	// Path is the absolute path to the credentials file (mode 0600).
	Path string
}
