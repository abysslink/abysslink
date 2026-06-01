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

// Internal (package backend) tests for the unexported checkNbTLS and
// checkNbMgmtBind doctor checks. These functions are unexported, so the tests
// must live in package backend (not backend_test).
package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
)

// ── Cert generation helper ──────────────────────────────────────────────────

// writeSelfSignedCert generates a self-signed ECDSA leaf certificate with the
// given validity window and SAN DNS names, writes PEM cert + key files into dir,
// and returns the two file paths. Used to exercise the cert-bearing branches of
// checkNbTLS hermetically (no network, no real CA).
func writeSelfSignedCert(t *testing.T, dir string, notBefore, notAfter time.Time, dnsNames []string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "abysslink-test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath
}

// writeMinimalNbConfigYAML writes a minimal valid NetBird config.yaml that
// parseNbConfigYAML decodes without error and which leaves server.tls and
// metricsListenAddress empty — so checkNbTLS falls through to the config-struct
// fields and checkNbMgmtBind reads only cfg.Server.NetBird.MgmtBindAddr.
func writeMinimalNbConfigYAML(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	const body = "server:\n  listenAddress: \"127.0.0.1:443\"\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// ── checkNbTLS tests ────────────────────────────────────────────────────────

// TestCheckNbTLS_NoCertConfiguredIsFatal covers the branch where neither the
// config.yaml nor the config struct provide a cert path: TLS is required, so the
// check must FAIL.
func TestCheckNbTLS_NoCertConfiguredIsFatal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeMinimalNbConfigYAML(t, dir)

	cfg := config.Defaults()
	cfg.Server.NetBird.ConfigPath = cfgPath
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	cfg.Server.NetBird.TLSCertFile = ""
	cfg.Server.NetBird.TLSKeyFile = ""

	f := checkNbTLS(context.Background(), cfg)
	assert.Equal(t, DoctorFatal, f.Severity, "missing cert must be FATAL")
	assert.Contains(t, f.Message, "no TLS certificate configured")
}

// TestCheckNbTLS_ValidCertIsOK covers the happy path: a cert that is currently
// valid, expires well beyond the 30-day window, and whose SAN matches the
// ServerURL hostname.
func TestCheckNbTLS_ValidCertIsOK(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeMinimalNbConfigYAML(t, dir)
	now := time.Now()
	certPath, keyPath := writeSelfSignedCert(t, dir,
		now.Add(-1*time.Hour), now.Add(365*24*time.Hour), []string{"nb.example.com"})

	cfg := config.Defaults()
	cfg.Server.NetBird.ConfigPath = cfgPath
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	cfg.Server.NetBird.TLSCertFile = certPath
	cfg.Server.NetBird.TLSKeyFile = keyPath

	f := checkNbTLS(context.Background(), cfg)
	assert.Equal(t, DoctorOK, f.Severity, "valid cert must be OK")
	assert.Contains(t, f.Message, "TLS certificate is valid")
}

// TestCheckNbTLS_ExpiredCertIsFatal covers the expired-cert branch: NotAfter is
// in the past, so the check must FAIL before the SAN check is reached.
func TestCheckNbTLS_ExpiredCertIsFatal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeMinimalNbConfigYAML(t, dir)
	now := time.Now()
	certPath, keyPath := writeSelfSignedCert(t, dir,
		now.Add(-48*time.Hour), now.Add(-24*time.Hour), []string{"nb.example.com"})

	cfg := config.Defaults()
	cfg.Server.NetBird.ConfigPath = cfgPath
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	cfg.Server.NetBird.TLSCertFile = certPath
	cfg.Server.NetBird.TLSKeyFile = keyPath

	f := checkNbTLS(context.Background(), cfg)
	assert.Equal(t, DoctorFatal, f.Severity, "expired cert must be FATAL")
	assert.Contains(t, f.Message, "certificate expired")
}

// TestCheckNbTLS_NearExpiryIsWarning covers the <30-day expiry branch: cert is
// still valid but expires inside the warning threshold, so the check WARNs.
func TestCheckNbTLS_NearExpiryIsWarning(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeMinimalNbConfigYAML(t, dir)
	now := time.Now()
	// Expires in ~10 days — inside the 30-day warn window.
	certPath, keyPath := writeSelfSignedCert(t, dir,
		now.Add(-1*time.Hour), now.Add(10*24*time.Hour), []string{"nb.example.com"})

	cfg := config.Defaults()
	cfg.Server.NetBird.ConfigPath = cfgPath
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	cfg.Server.NetBird.TLSCertFile = certPath
	cfg.Server.NetBird.TLSKeyFile = keyPath

	f := checkNbTLS(context.Background(), cfg)
	assert.Equal(t, DoctorWarning, f.Severity, "near-expiry cert must WARN")
	assert.Contains(t, f.Message, "expires within")
}

// TestCheckNbTLS_SANMismatchIsFatal covers the SAN-verification branch: a valid,
// far-from-expiry cert whose SAN does not cover the ServerURL hostname must FAIL.
func TestCheckNbTLS_SANMismatchIsFatal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeMinimalNbConfigYAML(t, dir)
	now := time.Now()
	// Cert is for a different host than ServerURL.
	certPath, keyPath := writeSelfSignedCert(t, dir,
		now.Add(-1*time.Hour), now.Add(365*24*time.Hour), []string{"other.example.org"})

	cfg := config.Defaults()
	cfg.Server.NetBird.ConfigPath = cfgPath
	cfg.Server.NetBird.ServerURL = "https://nb.example.com"
	cfg.Server.NetBird.TLSCertFile = certPath
	cfg.Server.NetBird.TLSKeyFile = keyPath

	f := checkNbTLS(context.Background(), cfg)
	assert.Equal(t, DoctorFatal, f.Severity, "SAN mismatch must be FATAL")
	assert.Contains(t, f.Message, "SAN mismatch")
}

// ── checkNbMgmtBind tests ───────────────────────────────────────────────────

// TestCheckNbMgmtBind_WildcardBindIsFatal covers the security-critical branch:
// mgmt_bind_addr containing 0.0.0.0 exposes the management/metrics port publicly
// and must FAIL.
func TestCheckNbMgmtBind_WildcardBindIsFatal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeMinimalNbConfigYAML(t, dir)

	cfg := config.Defaults()
	cfg.Server.NetBird.ConfigPath = cfgPath
	cfg.Server.NetBird.MgmtBindAddr = "0.0.0.0:443"

	f := checkNbMgmtBind(cfg)
	assert.Equal(t, DoctorFatal, f.Severity, "0.0.0.0 bind must be FATAL")
	assert.Contains(t, f.Message, "0.0.0.0")
}

// TestCheckNbMgmtBind_LoopbackBindIsOK covers the safe path: a loopback
// mgmt_bind_addr and no public metrics listen address must PASS.
func TestCheckNbMgmtBind_LoopbackBindIsOK(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeMinimalNbConfigYAML(t, dir)

	cfg := config.Defaults()
	cfg.Server.NetBird.ConfigPath = cfgPath
	cfg.Server.NetBird.MgmtBindAddr = "127.0.0.1:443"

	f := checkNbMgmtBind(cfg)
	assert.Equal(t, DoctorOK, f.Severity, "loopback bind must be OK")
	assert.Contains(t, f.Message, "not exposed")
}

// TestCheckNbMgmtBind_MetricsWildcardFromYAMLIsFatal covers the second wildcard
// source: metricsListenAddress=0.0.0.0:... parsed from config.yaml must FAIL,
// independent of the loopback MgmtBindAddr struct field.
func TestCheckNbMgmtBind_MetricsWildcardFromYAMLIsFatal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	const body = "metricsListenAddress: \"0.0.0.0:9090\"\n" +
		"server:\n  listenAddress: \"127.0.0.1:443\"\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0o600))

	cfg := config.Defaults()
	cfg.Server.NetBird.ConfigPath = cfgPath
	cfg.Server.NetBird.MgmtBindAddr = "127.0.0.1:443" // loopback struct field

	f := checkNbMgmtBind(cfg)
	assert.Equal(t, DoctorFatal, f.Severity, "metricsListenAddress 0.0.0.0 must be FATAL")
	assert.Contains(t, f.Message, "0.0.0.0")
}
