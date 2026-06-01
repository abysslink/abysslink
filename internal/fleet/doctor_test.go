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

package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── mock ACLManager ───────────────────────────────────────────────────────────

// mockACLManager implements backend.ACLManager for tests. It returns the ACL
// bytes set in rawACL field. GetACL is counted to verify read-back calls.
type mockACLManager struct {
	rawACL   []byte
	getCalls int
}

func (m *mockACLManager) GetACL(_ context.Context) ([]byte, string, error) {
	m.getCalls++
	return m.rawACL, "etag-1", nil
}

func (m *mockACLManager) SetACL(_ context.Context, _ []byte, _ string) error {
	return nil
}

func (m *mockACLManager) NewACLEditor(raw []byte) (backend.ACLEditor, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockACLManager) DefaultACL(_, _ string) []byte {
	return m.rawACL
}

func (m *mockACLManager) Diff(_, _ []byte) string {
	return ""
}

// aclDocSafe returns an ACL with no tag:laptop→tag:laptop grant (only mobile→laptop).
func aclDocSafe() []byte {
	type grant struct {
		Src []string `json:"src"`
		Dst []string `json:"dst"`
	}
	type doc struct {
		Grants []grant `json:"grants"`
	}
	d := doc{Grants: []grant{
		{Src: []string{"tag:mobile"}, Dst: []string{"tag:laptop"}},
	}}
	b, _ := json.Marshal(d)
	return b
}

// aclDocWithRigRigGrant returns an ACL that HAS a tag:laptop→tag:laptop grant.
func aclDocWithRigRigGrant() []byte {
	type grant struct {
		Src []string `json:"src"`
		Dst []string `json:"dst"`
	}
	type doc struct {
		Grants []grant `json:"grants"`
	}
	d := doc{Grants: []grant{
		{Src: []string{"tag:mobile"}, Dst: []string{"tag:laptop"}},
		{Src: []string{"tag:laptop"}, Dst: []string{"tag:laptop"}}, // rig-to-rig
	}}
	b, _ := json.Marshal(d)
	return b
}

// ── TestDoctor_RigIsolation ───────────────────────────────────────────────────

// TestDoctor_RigIsolation verifies that mr-rig-isolation:
//   - returns DoctorFatal when the ACL contains a tag:laptop→tag:laptop grant
//   - returns DoctorOK when the ACL has no rig-to-rig grant
//   - calls GetACL (read-back-of-effect, Decision A1)
//   - returns DoctorWarning when the ACL backend is nil
func TestDoctor_RigIsolation(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Rigs = []config.RigConfig{
		{Name: "alpha", Hostname: "alpha.ts.net", NtfyTopic: "abysslink-alpha-aabb1122"},
	}

	t.Run("FATAL when rig-to-rig grant present", func(t *testing.T) {
		mgr := &mockACLManager{rawACL: aclDocWithRigRigGrant()}
		findings := DoctorChecks(ctx, cfg, nil, mgr)
		var isolation *backend.DoctorFinding
		for i := range findings {
			if findings[i].Check == "mr-rig-isolation" {
				isolation = &findings[i]
				break
			}
		}
		require.NotNil(t, isolation, "mr-rig-isolation finding must be present")
		assert.Equal(t, backend.DoctorFatal, isolation.Severity,
			"must be FATAL when rig-to-rig grant exists")
		assert.Greater(t, mgr.getCalls, 0, "GetACL must be called (read-back-of-effect)")
	})

	t.Run("OK when no rig-to-rig grant", func(t *testing.T) {
		mgr := &mockACLManager{rawACL: aclDocSafe()}
		findings := DoctorChecks(ctx, cfg, nil, mgr)
		var isolation *backend.DoctorFinding
		for i := range findings {
			if findings[i].Check == "mr-rig-isolation" {
				isolation = &findings[i]
				break
			}
		}
		require.NotNil(t, isolation, "mr-rig-isolation finding must be present")
		assert.Equal(t, backend.DoctorOK, isolation.Severity,
			"must be OK when no rig-to-rig grant")
		assert.Greater(t, mgr.getCalls, 0, "GetACL must be called (read-back-of-effect)")
	})

	t.Run("WARN when ACL backend nil", func(t *testing.T) {
		findings := DoctorChecks(ctx, cfg, nil, nil)
		var isolation *backend.DoctorFinding
		for i := range findings {
			if findings[i].Check == "mr-rig-isolation" {
				isolation = &findings[i]
				break
			}
		}
		require.NotNil(t, isolation, "mr-rig-isolation finding must be present even when backend nil")
		assert.Equal(t, backend.DoctorWarning, isolation.Severity,
			"must be WARN when ACL backend unavailable")
	})
}

// ── TestDoctor_TopicIsolation ─────────────────────────────────────────────────

// TestDoctor_TopicIsolation verifies that mr-topic-isolation:
//   - returns DoctorOK when all rigs have distinct NtfyTopics
//   - returns DoctorFatal when two rigs share an NtfyTopic
func TestDoctor_TopicIsolation(t *testing.T) {
	ctx := context.Background()
	mgr := &mockACLManager{rawACL: aclDocSafe()}

	t.Run("OK with distinct topics", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rigs = []config.RigConfig{
			{Name: "alpha", NtfyTopic: "abysslink-alpha-aabb1122"},
			{Name: "beta", NtfyTopic: "abysslink-beta-33445566"},
		}
		findings := DoctorChecks(ctx, cfg, nil, mgr)
		var topicF *backend.DoctorFinding
		for i := range findings {
			if findings[i].Check == "mr-topic-isolation" {
				topicF = &findings[i]
				break
			}
		}
		require.NotNil(t, topicF)
		assert.Equal(t, backend.DoctorOK, topicF.Severity,
			"must be OK when topics are distinct")
	})

	t.Run("FATAL when two rigs share a topic", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rigs = []config.RigConfig{
			{Name: "alpha", NtfyTopic: "abysslink-shared-aabb1122"},
			{Name: "beta", NtfyTopic: "abysslink-shared-aabb1122"}, // duplicate
		}
		findings := DoctorChecks(ctx, cfg, nil, mgr)
		var topicF *backend.DoctorFinding
		for i := range findings {
			if findings[i].Check == "mr-topic-isolation" {
				topicF = &findings[i]
				break
			}
		}
		require.NotNil(t, topicF)
		assert.Equal(t, backend.DoctorFatal, topicF.Severity,
			"must be FATAL when two rigs share a topic")
	})
}

// ── TestDoctor_KeyUniqueness ──────────────────────────────────────────────────

// TestDoctor_KeyUniqueness verifies that mr-key-uniqueness:
//   - returns DoctorOK when all rig names yield distinct keychain services
//   - returns DoctorFatal when two rigs derive the same keychain service (duplicate names)
//   - returns DoctorWarning when named rigs coexist with legacy v1 service="abysslink" entries (D-KN-02)
func TestDoctor_KeyUniqueness(t *testing.T) {
	ctx := context.Background()
	mgr := &mockACLManager{rawACL: aclDocSafe()}

	t.Run("OK with distinct rig names", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rigs = []config.RigConfig{
			{Name: "alpha", NtfyTopic: "abysslink-alpha-aabb1122"},
			{Name: "beta", NtfyTopic: "abysslink-beta-33445566"},
		}
		kc := secrets.NewMockStore()
		findings := DoctorChecks(ctx, cfg, kc, mgr)
		var keyF *backend.DoctorFinding
		for i := range findings {
			if findings[i].Check == "mr-key-uniqueness" {
				keyF = &findings[i]
				break
			}
		}
		require.NotNil(t, keyF)
		assert.Equal(t, backend.DoctorOK, keyF.Severity,
			"must be OK when rig names are distinct")
	})

	t.Run("FATAL when two rigs produce the same keychain service", func(t *testing.T) {
		// Two rigs with the same name → same RigService → duplicate keychain namespace.
		cfg := config.Defaults()
		cfg.Rigs = []config.RigConfig{
			{Name: "alpha", NtfyTopic: "abysslink-alpha-aabb1122"},
			{Name: "alpha", NtfyTopic: "abysslink-alpha-33445566"}, // same name → same service
		}
		kc := secrets.NewMockStore()
		findings := DoctorChecks(ctx, cfg, kc, mgr)
		var keyF *backend.DoctorFinding
		for i := range findings {
			if findings[i].Check == "mr-key-uniqueness" {
				keyF = &findings[i]
				break
			}
		}
		require.NotNil(t, keyF)
		assert.Equal(t, backend.DoctorFatal, keyF.Severity,
			"must be FATAL when two rigs derive the same keychain service")
	})

	t.Run("WARN when legacy v1 coexists with named rigs (D-KN-02)", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Rigs = []config.RigConfig{
			{Name: "alpha", NtfyTopic: "abysslink-alpha-aabb1122"},
		}
		kc := secrets.NewMockStore()
		// Seed a legacy v1 entry under service="abysslink" to simulate coexistence.
		require.NoError(t, kc.Set(ctx, "abysslink", "ntfy-password", "legacy-pass"))
		findings := DoctorChecks(ctx, cfg, kc, mgr)
		var keyF *backend.DoctorFinding
		for i := range findings {
			if findings[i].Check == "mr-key-uniqueness" {
				keyF = &findings[i]
				break
			}
		}
		require.NotNil(t, keyF)
		assert.Equal(t, backend.DoctorWarning, keyF.Severity,
			"must be WARN when legacy v1 entries coexist with named rigs (D-KN-02)")
	})
}

// ── TestDoctor_FindingMetadata ────────────────────────────────────────────────

// TestDoctor_FindingMetadata verifies that DoctorChecks returns exactly
// three findings with Module="fleet" and the three mr-* check names.
func TestDoctor_FindingMetadata(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Rigs = []config.RigConfig{
		{Name: "alpha", NtfyTopic: "abysslink-alpha-aabb1122"},
	}
	kc := secrets.NewMockStore()
	mgr := &mockACLManager{rawACL: aclDocSafe()}

	findings := DoctorChecks(ctx, cfg, kc, mgr)
	require.Len(t, findings, 3, "DoctorChecks must return exactly 3 findings")

	checks := make(map[string]bool)
	for _, f := range findings {
		assert.Equal(t, "fleet", f.Module, "Module must be 'fleet' for all mr-* findings")
		checks[f.Check] = true
	}
	assert.True(t, checks["mr-rig-isolation"], "mr-rig-isolation must be present")
	assert.True(t, checks["mr-topic-isolation"], "mr-topic-isolation must be present")
	assert.True(t, checks["mr-key-uniqueness"], "mr-key-uniqueness must be present")
}
