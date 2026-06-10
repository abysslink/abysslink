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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findingByCheck returns the first finding with the given Check name, or nil.
func findingByCheck(findings []modules.Finding, check string) *modules.Finding {
	for i := range findings {
		if findings[i].Check == check {
			return &findings[i]
		}
	}
	return nil
}

func TestAuditDoctor_KeychainNil(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	findings := auditDoctorFindings(logPath, nil)
	f := findingByCheck(findings, "audit-keychain")
	require.NotNil(t, f, "audit-keychain finding must be present when kc is nil")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

func TestAuditDoctor_AnchorAgeWarnWhenMissing(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := secrets.NewMockStore()
	findings := auditDoctorFindings(logPath, kc)
	f := findingByCheck(findings, "audit-anchor-age")
	require.NotNil(t, f, "missing anchor should produce an anchor-age WARN")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

func TestAuditDoctor_AnchorAgeWarnWhenStale(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	// Write a stale anchor (Time older than 24h). HMAC need not match for the
	// age check, which only parses Time.
	stale := audit.Anchor{
		EntryCount: 0,
		LastHash:   "",
		Time:       time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(stale)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit.anchor.json"), data, 0o600))

	findings := auditDoctorFindings(logPath, secrets.NewMockStore())
	f := findingByCheck(findings, "audit-anchor-age")
	require.NotNil(t, f)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// TestAuditDoctor_AnchorAgeWarnWhenUnparseable covers WR-05: an anchor whose
// Time does not parse as RFC3339 must emit a WARN finding, not silently pass as
// "age within threshold" (false-clean). A local attacker who can write
// audit.anchor.json could otherwise set Time to garbage to suppress staleness.
func TestAuditDoctor_AnchorAgeWarnWhenUnparseable(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	bad := audit.Anchor{
		EntryCount: 0,
		LastHash:   "",
		Time:       "not-a-timestamp",
	}
	data, err := json.Marshal(bad)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit.anchor.json"), data, 0o600))

	findings := auditDoctorFindings(logPath, secrets.NewMockStore())
	f := findingByCheck(findings, "audit-anchor-age")
	require.NotNil(t, f, "unparseable anchor time must produce an anchor-age finding")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

func TestAuditDoctor_CountVsAnchorFatal(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	// Fresh anchor recording 5 entries, but the log has 0 — truncation. The
	// anchor is unsigned (no valid HMAC), which CR-01 now treats as tamper:
	// either way the audit-count-vs-anchor check fires FATAL.
	anchor := audit.Anchor{
		EntryCount: 5,
		LastHash:   "abc",
		Time:       time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(anchor)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit.anchor.json"), data, 0o600))

	findings := auditDoctorFindings(logPath, secrets.NewMockStore())
	f := findingByCheck(findings, "audit-count-vs-anchor")
	require.NotNil(t, f, "count < anchor.EntryCount must be FATAL")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

// TestAuditDoctor_ForgedAnchorFatal covers CR-01: an anchor whose HMAC does not
// validate (forged or unsigned) must be reported FATAL by audit-count-vs-anchor
// regardless of whether its EntryCount happens to look consistent.
func TestAuditDoctor_ForgedAnchorFatal(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := secrets.NewMockStore()

	// Build a real signed log + anchor first. dryRun must be false: since
	// CORE-08, dry-run writes append nothing and never generate the HMAC key,
	// so a dry-run-only setup leaves no key for WriteAnchor to sign with.
	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, sa.WriteFile(filepath.Join(dir, "f"), []byte{byte(i)}, 0o600, false))
	}
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	// Forge: rewrite the anchor's EntryCount, leaving the stale HMAC.
	anchorFile := filepath.Join(dir, "audit.anchor.json")
	raw, _ := os.ReadFile(anchorFile) //nolint:gosec // G304: test reads a fixture path under the test's own temp dir, not user input
	var a audit.Anchor
	require.NoError(t, json.Unmarshal(raw, &a))
	a.LastHash = "deadbeef" // tamper a signed field; the HMAC is now stale
	bad, _ := json.Marshal(a)
	require.NoError(t, os.WriteFile(anchorFile, bad, 0o600))

	findings := auditDoctorFindings(logPath, kc)
	f := findingByCheck(findings, "audit-count-vs-anchor")
	require.NotNil(t, f, "forged anchor HMAC must be FATAL even when counts match")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

// TestAuditDoctor_ValidAnchorNoFinding covers CR-01's happy path: a properly
// signed anchor whose count matches the log must produce no count-vs-anchor
// finding.
func TestAuditDoctor_ValidAnchorNoFinding(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	kc := secrets.NewMockStore()

	sa, err := audit.NewSigned(logPath, kc)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		// dryRun=false: see TestAuditDoctor_ForgedAnchorFatal (CORE-08).
		require.NoError(t, sa.WriteFile(filepath.Join(dir, "f"), []byte{byte(i)}, 0o600, false))
	}
	require.NoError(t, audit.WriteAnchor(context.Background(), logPath, kc))

	findings := auditDoctorFindings(logPath, kc)
	assert.Nil(t, findingByCheck(findings, "audit-count-vs-anchor"),
		"a valid signed anchor with matching count must not flag truncation")
}
