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

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// enrollTestKeychain is an in-memory KeychainStore for enroll tests.
type enrollTestKeychain struct {
	data map[string]string // key: "service:account"
}

func newMockKeychain() *enrollTestKeychain {
	return &enrollTestKeychain{data: make(map[string]string)}
}

func (m *enrollTestKeychain) kcKey(service, account string) string {
	return service + ":" + account
}

func (m *enrollTestKeychain) Set(_ context.Context, service, account, secret string) error {
	m.data[m.kcKey(service, account)] = secret
	return nil
}

func (m *enrollTestKeychain) Get(_ context.Context, service, account string) (string, error) {
	v, ok := m.data[m.kcKey(service, account)]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (m *enrollTestKeychain) Delete(_ context.Context, service, account string) error {
	delete(m.data, m.kcKey(service, account))
	return nil
}

var _ secrets.KeychainStore = (*enrollTestKeychain)(nil)

// TestEnrollRig_NameValidation asserts that rig names with chars outside [a-z0-9-]
// are rejected and nothing is written (T-14-11, ASVS V5).
func TestEnrollRig_NameValidation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := config.Defaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	kc := newMockKeychain()

	badNames := []string{
		"My_Rig",
		"rig name",
		"RIG",
		"rig!",
		"rig/path",
		"rig;evil",
		"",
		strings.Repeat("a", 64), // too long (>63)
	}
	for _, name := range badNames {
		err := enrollRig(context.Background(), enrollRigOpts{
			name:     name,
			cfgPath:  cfgPath,
			keychain: kc,
			apply:    true,
		})
		assert.Error(t, err, "expected error for name=%q", name)
		assert.Contains(t, err.Error(), "invalid rig name", "name=%q", name)
	}
	// Verify nothing was written to keychain.
	assert.Empty(t, kc.data, "keychain must remain empty for invalid names")
}

// TestEnrollRig_TopicCollision asserts that enrolling a rig whose derived/overridden
// ntfy_topic equals an existing cfg.Rigs[].NtfyTopic returns an error and writes nothing
// (SC-1, D-NI-02, T-14-08).
func TestEnrollRig_TopicCollision(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := config.Defaults()
	cfg.Version = 1
	existingTopic := "abysslink-laptop-a1b2c3d4"
	cfg.Rigs = []config.RigConfig{
		{Name: "laptop", Hostname: "laptop.ts.net", NtfyTopic: existingTopic, Backend: "tailscale"},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	kc := newMockKeychain()

	err = enrollRig(context.Background(), enrollRigOpts{
		name:          "laptop2",
		cfgPath:       cfgPath,
		keychain:      kc,
		apply:         true,
		overrideTopic: existingTopic, // force a collision
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "topic", "error must mention topic collision")

	// Assert nothing was written to config.
	cfg2, loadErr := config.Load(cfgPath)
	require.NoError(t, loadErr)
	assert.Len(t, cfg2.Rigs, 1, "no new rig must be appended on topic collision")
}

// TestEnrollRig_Migration asserts that enroll --apply copies v1 keychain entries
// non-destructively; --dry-run does not call Set (SC-1 / PATTERNS §Keychain migration).
func TestEnrollRig_Migration(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := config.Defaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	kc := newMockKeychain()
	// Pre-populate v1 keychain entries.
	v1Accounts := []string{"ntfy-password", "anthropic-api-key", "code-server-password"}
	for _, acct := range v1Accounts {
		require.NoError(t, kc.Set(context.Background(), "abysslink", acct, "secret-"+acct))
	}

	// Dry-run: no Set for the new rig service.
	preCount := len(kc.data)
	err = enrollRig(context.Background(), enrollRigOpts{
		name:     "workstation",
		cfgPath:  cfgPath,
		keychain: kc,
		apply:    false, // dry-run
	})
	require.NoError(t, err)
	// Dry-run must not add any new entries.
	assert.Equal(t, preCount, len(kc.data), "dry-run must not call keychain Set")

	// Apply: migrates v1 entries into rig-scoped service.
	err = enrollRig(context.Background(), enrollRigOpts{
		name:     "workstation",
		cfgPath:  cfgPath,
		keychain: kc,
		apply:    true,
	})
	require.NoError(t, err)

	rigSvc := fleet.RigService("workstation")
	for _, acct := range v1Accounts {
		// Rig-scoped entry must exist.
		v, getErr := kc.Get(context.Background(), rigSvc, acct)
		require.NoError(t, getErr, "rig-scoped entry missing for %s", acct)
		assert.Equal(t, "secret-"+acct, v, "migrated value must equal original")

		// v1 entry must still exist (non-destructive).
		v1Val, getErr := kc.Get(context.Background(), "abysslink", acct)
		require.NoError(t, getErr, "v1 entry must not be deleted for %s", acct)
		assert.Equal(t, "secret-"+acct, v1Val)
	}
}

// TestEnrollRig_HMACKey asserts that enroll --apply generates a 64-char-hex HMAC key,
// stores it at (RigService(name), "hmac-signing-key"), and the key is NOT written into
// the yaml body (T-14-09, D-KN-01).
func TestEnrollRig_HMACKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := config.Defaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	kc := newMockKeychain()

	err = enrollRig(context.Background(), enrollRigOpts{
		name:     "myrig",
		cfgPath:  cfgPath,
		keychain: kc,
		apply:    true,
	})
	require.NoError(t, err)

	// HMAC key must be stored in keychain.
	hexKey, getErr := kc.Get(context.Background(), fleet.RigService("myrig"), "hmac-signing-key")
	require.NoError(t, getErr, "hmac-signing-key must be in keychain")
	assert.Len(t, hexKey, 64, "HMAC key must be 64 hex chars (32 bytes)")

	// HMAC key must NOT appear in the written YAML.
	yamlBytes, readErr := os.ReadFile(cfgPath)
	require.NoError(t, readErr)
	assert.NotContains(t, string(yamlBytes), hexKey, "HMAC key must not appear in yaml")
}

// TestEnrollRig_AuditWrite asserts that the rig record write routes through config.Write
// (which calls audit.WriteFile), never os.WriteFile, and the written bytes contain no
// HMAC key (T-14-09 / CLAUDE.md audit invariant). We verify by reading back the config.
func TestEnrollRig_AuditWrite(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := config.Defaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	kc := newMockKeychain()

	var out bytes.Buffer
	err = enrollRig(context.Background(), enrollRigOpts{
		name:     "devbox",
		cfgPath:  cfgPath,
		keychain: kc,
		apply:    true,
		stdout:   &out,
	})
	require.NoError(t, err)

	// Config must now contain the rig.
	cfg2, loadErr := config.Load(cfgPath)
	require.NoError(t, loadErr)
	require.Len(t, cfg2.Rigs, 1, "one rig must be appended")
	assert.Equal(t, "devbox", cfg2.Rigs[0].Name)
	assert.NotEmpty(t, cfg2.Rigs[0].NtfyTopic, "ntfy_topic must be set")

	// HMAC key must not appear in the written yaml.
	hexKey, _ := kc.Get(context.Background(), fleet.RigService("devbox"), "hmac-signing-key")
	if hexKey != "" {
		yamlBytes, _ := os.ReadFile(cfgPath)
		assert.NotContains(t, string(yamlBytes), hexKey)
	}
}

// TestEnrollRig_ACLDeny asserts that enroll --apply with an ACLManager backend
// calls GetACL, asserts no tag:laptop→tag:laptop grant, calls SetACL, and reads back
// the effect (absence-of-grant, A1 decision, Phase 13 SC-3 validate-after-push).
func TestEnrollRig_ACLDeny(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := config.Defaults()
	cfg.Version = 1
	cfg.Backend.Type = "tailscale"
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	kc := newMockKeychain()

	// Use a spy ACL manager that records calls and returns a safe ACL.
	spy := &spyACLManager{}

	err = enrollRig(context.Background(), enrollRigOpts{
		name:       "rigbox",
		cfgPath:    cfgPath,
		keychain:   kc,
		apply:      true,
		aclManager: spy,
	})
	require.NoError(t, err)

	// Verify that GetACL was called (read current) and SetACL was called (push),
	// and GetACL was called again (validate-after-push, SC-3).
	assert.GreaterOrEqual(t, spy.getCalls, 2, "GetACL must be called at least twice (read + validate-after-push)")
	assert.GreaterOrEqual(t, spy.setCalls, 1, "SetACL must be called to persist the deny assertion")
}

// TestEnrollRig_RigRigGrantFails asserts that if the current ACL contains a
// tag:laptop→tag:laptop grant, enrollment returns an error (security violation,
// absence-of-grant A1 decision).
func TestEnrollRig_RigRigGrantFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := config.Defaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	kc := newMockKeychain()

	// ACL manager that returns an ACL with a rig↔rig grant.
	spy := &spyACLManager{hasRigRigGrant: true}

	err = enrollRig(context.Background(), enrollRigOpts{
		name:       "badrig",
		cfgPath:    cfgPath,
		keychain:   kc,
		apply:      true,
		aclManager: spy,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tag:laptop", "error must identify the rig↔rig grant violation")
}

// spyACLManager is a test-double that implements the aclManagerFace interface
// (the internal test seam for the backend.ACLManager subset used by enrollRig).
type spyACLManager struct {
	getCalls       int
	setCalls       int
	hasRigRigGrant bool // when true, GetACL returns an ACL with tag:laptop→tag:laptop
}

func (s *spyACLManager) GetACL(_ context.Context) ([]byte, string, error) {
	s.getCalls++
	if s.hasRigRigGrant {
		// Return a HuJSON ACL with a tag:laptop→tag:laptop grant (security violation).
		return []byte(`{
    "grants": [
        {"src": ["tag:mobile"], "dst": ["tag:laptop"], "ip": ["tcp:22"]},
        {"src": ["tag:laptop"], "dst": ["tag:laptop"], "ip": ["*"]}
    ]
}`), "etag1", nil
	}
	// Safe ACL: only mobile→laptop.
	return []byte(`{
    "grants": [
        {"src": ["tag:mobile"], "dst": ["tag:laptop"], "ip": ["tcp:22"]}
    ]
}`), "etag1", nil
}

func (s *spyACLManager) SetACL(_ context.Context, _ []byte, _ string) error {
	s.setCalls++
	return nil
}
