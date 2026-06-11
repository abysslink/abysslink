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

package device_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/secrets"
)

// parseCert extracts the *ssh.Certificate from a bundle's authorized_keys line.
func parseCert(t *testing.T, line string) *ssh.Certificate {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err)
	cert, ok := pub.(*ssh.Certificate)
	require.True(t, ok, "authorized key line must carry a certificate, got %T", pub)
	return cert
}

func TestCA_PersistsAcrossStoreInstances(t *testing.T) {
	ctx := context.Background()
	kc := secrets.NewMockStore()
	dir := t.TempDir()
	clk := newFakeClock()

	s1 := device.New(filepath.Join(dir, "a.json"), &fakeAudit{}, kc, clk.Now)
	s2 := device.New(filepath.Join(dir, "b.json"), &fakeAudit{}, kc, clk.Now)

	pub1, err := s1.CAPublicKey(ctx)
	require.NoError(t, err)
	pub2, err := s2.CAPublicKey(ctx)
	require.NoError(t, err)
	assert.Equal(t, pub1, pub2, "same keychain must yield the same CA public key")

	// The CA key lives at the documented keychain coordinates and is PEM.
	pemStr, err := kc.Get(ctx, "abysslink", "device-ssh-ca")
	require.NoError(t, err)
	assert.Contains(t, pemStr, "OPENSSH PRIVATE KEY")

	// The bundle's CA line matches CAPublicKey, and the cert is signed by it.
	b, err := s1.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	assert.Equal(t, pub1, b.CAPublicKeyAuthorizedKey)
	cert := parseCert(t, b.SSHCertAuthorizedKey)
	assert.Equal(t, ssh.FingerprintSHA256(cert.SignatureKey),
		ssh.FingerprintSHA256(parseAuthorizedKey(t, pub1)),
		"certificate must be signed by the persisted CA")

	// A different keychain mints a different CA.
	s3 := device.New(filepath.Join(dir, "c.json"), &fakeAudit{}, secrets.NewMockStore(), clk.Now)
	pub3, err := s3.CAPublicKey(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, pub1, pub3)
}

func parseAuthorizedKey(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err)
	return pub
}

func TestCert_Fields(t *testing.T) {
	s, _, _, _ := testStore(t)
	ctx := context.Background()

	b, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	cert := parseCert(t, b.SSHCertAuthorizedKey)

	assert.Equal(t, uint32(ssh.UserCert), cert.CertType)
	assert.Equal(t, "abysslink-device-phone", cert.KeyId)
	assert.Equal(t, []string{"phone"}, cert.ValidPrincipals)
	assert.Equal(t, uint64(1), cert.Serial)
	assert.Equal(t, uint64(baseTime.Add(-5*time.Minute).Unix()), cert.ValidAfter, "ValidAfter backdated 5m for clock skew")
	assert.Equal(t, uint64(baseTime.Add(90*24*time.Hour).Unix()), cert.ValidBefore, "ValidBefore now+90d")
	assert.True(t, b.CertNotAfter.Equal(baseTime.Add(90*24*time.Hour)))
	assert.Equal(t, map[string]string{"permit-pty": ""}, cert.Extensions,
		"least privilege: ONLY permit-pty — no forwarding, no agent, no X11")
	assert.Empty(t, cert.CriticalOptions)

	// The cert binds the bundle's private key (fingerprints agree).
	signer, err := ssh.ParsePrivateKey([]byte(b.SSHPrivateKeyPEM))
	require.NoError(t, err)
	assert.Equal(t, ssh.FingerprintSHA256(signer.PublicKey()), ssh.FingerprintSHA256(cert.Key))

	// Full validation through x/crypto's own checker.
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(parseAuthorizedKey(t, b.CAPublicKeyAuthorizedKey))
		},
		Clock: func() time.Time { return baseTime },
	}
	assert.NoError(t, checker.CheckCert("phone", cert))
	assert.Error(t, checker.CheckCert("root", cert), "only the device name is a valid principal")
}

func TestCert_SerialsMonotonicAcrossInstances(t *testing.T) {
	ctx := context.Background()
	kc := secrets.NewMockStore()
	path := filepath.Join(t.TempDir(), "devices.json")
	clk := newFakeClock()

	s1 := device.New(path, &fakeAudit{}, kc, clk.Now)
	b1, err := s1.Enroll(ctx, "a", "phone")
	require.NoError(t, err)
	b2, err := s1.Enroll(ctx, "b", "phone")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), parseCert(t, b1.SSHCertAuthorizedKey).Serial)
	assert.Equal(t, uint64(2), parseCert(t, b2.SSHCertAuthorizedKey).Serial)

	// A new Store over the same file continues the counter — never reuses.
	s2 := device.New(path, &fakeAudit{}, kc, clk.Now)
	b3, err := s2.Enroll(ctx, "c", "phone")
	require.NoError(t, err)
	assert.Equal(t, uint64(3), parseCert(t, b3.SSHCertAuthorizedKey).Serial)

	// Rotation consumes a fresh serial and revokes the old one.
	b4, err := s2.Rotate(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, uint64(4), parseCert(t, b4.SSHCertAuthorizedKey).Serial)
	assert.Equal(t, []uint64{1}, s2.RevokedSerials())
}
