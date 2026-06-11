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
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// assertNoFileContains walks root and fails if any regular file contains
// needle. Used to prove one-time secrets never land on disk.
func assertNoFileContains(t *testing.T, root, needle, what string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(path) //nolint:gosec // test walks its own temp dir
		if rerr != nil {
			return rerr
		}
		assert.NotContains(t, string(data), needle, "%s must never be written to %s", what, path)
		return nil
	})
	require.NoError(t, err)
}

// TestEnrollPhoneDevice_MintsAndPrintsOnce covers DEVC-01: the bundle is
// printed exactly once, carries every credential, and NO secret ever lands in
// any file the flow writes (devices.json, audit log, backups, runbook).
func TestEnrollPhoneDevice_MintsAndPrintsOnce(t *testing.T) {
	ctx := context.Background()
	st, dir := newTestDeviceStore(t, nil)

	b, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)
	assert.False(t, rotated, "first enrollment is not a rotation")
	require.NotEmpty(t, b.Bearer)
	require.NotEmpty(t, b.PushToken)
	require.Contains(t, b.SSHPrivateKeyPEM, "OPENSSH PRIVATE KEY")

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, io.Discard)
	printDeviceBundle(p, false, b, rotated)
	got := stripANSI(out.String())

	assert.Equal(t, 1, strings.Count(got, b.Bearer), "bearer must be printed exactly once")
	assert.Equal(t, 1, strings.Count(got, b.PushToken), "push token must be printed exactly once")
	assert.Contains(t, got, "Shown ONCE", "the one-time warning must be present")
	assert.Contains(t, got, "BEGIN OPENSSH PRIVATE KEY", "private key PEM must be in the box")
	assert.Contains(t, got, b.SSHCertAuthorizedKey, "certificate line must be in the box")
	assert.Contains(t, got, b.CAPublicKeyAuthorizedKey, "CA public key line must be in the box")
	assert.Contains(t, got, b.CertNotAfter.UTC().Format("2006-01-02"), "cert expiry must be shown")

	// NEVER persisted: no file under the store dir (devices.json, audit.log,
	// backups) may contain the bearer or the private key.
	assertNoFileContains(t, dir, b.Bearer, "bearer")
	assertNoFileContains(t, dir, "OPENSSH PRIVATE KEY", "SSH private key")

	// The runbook references THAT enrollment happened + cert expiry — never a
	// secret (the runbook body is fully determined by runbookMarkdown).
	cc := &cmdContext{cfg: testCfgDefaults()}
	runbook := runbookMarkdown(cc, b.CertNotAfter)
	assert.Contains(t, runbook, "Device credentials", "runbook must reference that enrollment happened")
	assert.Contains(t, runbook, b.CertNotAfter.UTC().Format("2006-01-02"), "runbook must carry the cert expiry")
	assert.NotContains(t, runbook, b.Bearer, "runbook must never contain the bearer")
	assert.NotContains(t, runbook, b.PushToken, "runbook must never contain the push token")
	assert.NotContains(t, runbook, "PRIVATE KEY", "runbook must never contain the private key")
	assert.NotContains(t, runbook, b.SSHCertAuthorizedKey, "runbook must never contain the certificate")
}

// TestEnrollPhoneDevice_ReenrollRotates covers DEVC-02: a second `enroll
// phone` rotates the existing record in place — same record, fresh
// credentials, old bearer invalid.
func TestEnrollPhoneDevice_ReenrollRotates(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)

	b1, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)
	require.False(t, rotated)

	b2, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)
	assert.True(t, rotated, "re-enrolling an active device must rotate, not fail")
	assert.NotEqual(t, b1.Bearer, b2.Bearer, "rotation must mint a fresh bearer")

	_, ok := st.VerifyBearer(b1.Bearer)
	assert.False(t, ok, "the old bearer must be invalid after rotation (DEVC-02)")
	rec, ok := st.VerifyBearer(b2.Bearer)
	require.True(t, ok, "the new bearer must verify")
	assert.Equal(t, "phone", rec.Name)
	assert.Len(t, st.List(), 1, "rotation must reuse the record, not append a second one")

	// A revoked record's name is re-ENROLLED fresh, not rotated.
	require.NoError(t, st.Revoke(ctx, "phone"))
	_, rotated, err = mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)
	assert.False(t, rotated, "a revoked name must be freshly enrolled, not rotated")
	assert.Len(t, st.List(), 2, "the revoked record stays for the audit trail")
}

// TestEnrollPhone_DryRunMintsNothing covers the [plan] gate: without --apply,
// `enroll phone` previews the device mint and creates NO device store file.
func TestEnrollPhone_DryRunMintsNothing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "abysslink.yaml")
	cfg := testCfgDefaults()
	cfg.Version = 1
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, data, 0o600))

	storePath := filepath.Join(t.TempDir(), "devices.json")
	overrideDeviceStorePath(t, storePath)
	t.Setenv("ABYSSLINK_TS_OAUTH_SECRET", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"enroll", "phone", "--config", cfgPath})
	require.NoError(t, root.ExecuteContext(context.Background()))

	got := stripANSI(out.String())
	assert.Contains(t, got, "[plan] would mint device credentials", "dry-run must preview the device mint")
	assert.Contains(t, got, "ONCE", "preview must flag the one-time nature")
	_, statErr := os.Stat(storePath)
	assert.True(t, os.IsNotExist(statErr), "dry-run must not create the device store")
}

// TestPrintDeviceBundle_JSON covers the --json contract: one structured record
// carrying the one-time secrets (documented as the user's choice to persist)
// plus an explicit warning field.
func TestPrintDeviceBundle_JSON(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	b, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)

	var out bytes.Buffer
	p := NewJSONPrinterTo(&out, io.Discard)
	printDeviceBundle(p, true, b, rotated)

	require.Equal(t, 1, strings.Count(strings.TrimSpace(out.String()), "\n")+1,
		"JSON mode must emit exactly one record")
	var rec deviceBundleRecord
	require.NoError(t, json.Unmarshal(out.Bytes(), &rec))
	assert.Equal(t, "phone", rec.Device)
	assert.False(t, rec.Rotated)
	assert.Equal(t, b.Bearer, rec.Bearer)
	assert.Equal(t, b.PushToken, rec.PushToken)
	assert.Equal(t, b.SSHPrivateKeyPEM, rec.SSHPrivateKeyPEM)
	assert.Equal(t, b.SSHCertAuthorizedKey, rec.SSHCertificate)
	assert.Equal(t, b.CAPublicKeyAuthorizedKey, rec.CAPublicKey)
	assert.Contains(t, rec.Warning, "one-time", "the record must document its one-time nature")

	expires, perr := time.Parse(time.RFC3339, rec.CertNotAfter)
	require.NoError(t, perr)
	assert.WithinDuration(t, b.CertNotAfter, expires, time.Second)
}
