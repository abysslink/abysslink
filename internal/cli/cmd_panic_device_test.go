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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPanicRevokeDeviceCredentials_RevokesAllAndCounts covers DEVC-03: the
// panic step revokes every enrolled device credential in one shot, prints the
// count, and records the audit action.
func TestPanicRevokeDeviceCredentials_RevokesAllAndCounts(t *testing.T) {
	ctx := context.Background()
	t.Setenv("XDG_STATE_HOME", t.TempDir()) // sandbox audit.DefaultLogPath

	st, dir := newTestDeviceStore(t, nil)
	b1, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	b2, err := st.Enroll(ctx, "tablet", "phone")
	require.NoError(t, err)
	overrideDeviceStorePath(t, filepath.Join(dir, "devices.json"))

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	var logged []string
	revokeDeviceCredentialsWithStep(ctx, p, func(a string) { logged = append(logged, a) }, false)

	got := stripANSI(out.String())
	assert.Contains(t, got, "revoked 2 device credential(s)", "the success step must carry the count")
	assert.Contains(t, got, iconDone, "success must show the ✓ marker")
	assert.Contains(t, logged, "revoke_device_credentials", "the audit action must be recorded")

	// Both bearers are dead.
	_, ok := st.VerifyBearer(b1.Bearer)
	assert.False(t, ok, "phone bearer must be invalid after panic")
	_, ok = st.VerifyBearer(b2.Bearer)
	assert.False(t, ok, "tablet bearer must be invalid after panic")
	for _, r := range st.List() {
		assert.True(t, r.Revoked, "every record must be revoked: %s", r.Name)
	}
}

// TestPanicRevokeDeviceCredentials_ZeroDevicesIsSuccess covers the empty
// store: zero devices is a ✓ success with count 0, not a failure.
func TestPanicRevokeDeviceCredentials_ZeroDevicesIsSuccess(t *testing.T) {
	ctx := context.Background()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	overrideDeviceStorePath(t, filepath.Join(t.TempDir(), "devices.json"))

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	var logged []string
	revokeDeviceCredentialsWithStep(ctx, p, func(a string) { logged = append(logged, a) }, false)

	got := stripANSI(out.String())
	assert.Contains(t, got, "revoked 0 device credential(s)", "zero devices is a success")
	assert.Contains(t, got, iconDone, "zero devices must show the ✓ marker")
	assert.NotContains(t, got, iconFatal, "zero devices must not show a failure marker")
	assert.Empty(t, logged, "no mutation happened, so no audit action is logged")
}

// TestPanicRevokeDeviceCredentials_FailureContinues covers the best-effort
// contract: a store failure prints the ✕ marker (errPanicStepFailed idiom) and
// RETURNS — it never panics or aborts, so later panic steps still run.
func TestPanicRevokeDeviceCredentials_FailureContinues(t *testing.T) {
	ctx := context.Background()
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	// A corrupt records file makes RevokeAll fail on load.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "devices.json")
	require.NoError(t, os.WriteFile(storePath, []byte("{not json"), 0o600))
	overrideDeviceStorePath(t, storePath)

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	assert.NotPanics(t, func() {
		revokeDeviceCredentialsWithStep(ctx, p, func(string) {}, false)
	}, "a failing step must return, never panic — panic continues with later steps")

	got := stripANSI(out.String())
	assert.Contains(t, got, iconFatal, "failure must show the ✕ marker")
	assert.Contains(t, got, "revoke device credentials", "failure must name the step")
}

// TestPanicRevokeDeviceCredentials_DryRunNoOp covers the explicit --dry-run
// path: a [plan] line and ZERO mutation (the store file is untouched —
// RevokeAll is never called, because the device store's audit writer always
// writes for real).
func TestPanicRevokeDeviceCredentials_DryRunNoOp(t *testing.T) {
	ctx := context.Background()
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	st, dir := newTestDeviceStore(t, nil)
	b, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	storePath := filepath.Join(dir, "devices.json")
	before, err := os.ReadFile(storePath) //nolint:gosec // test reads its own temp file
	require.NoError(t, err)
	overrideDeviceStorePath(t, storePath)

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, &out)
	var logged []string
	revokeDeviceCredentialsWithStep(ctx, p, func(a string) { logged = append(logged, a) }, true)

	got := stripANSI(out.String())
	assert.Contains(t, got, "[plan]", "dry-run must print a plan line")
	assert.NotContains(t, got, "revoked 1", "dry-run must not claim to have revoked anything")
	assert.Empty(t, logged, "dry-run must not record an audit action")

	after, err := os.ReadFile(storePath) //nolint:gosec // test reads its own temp file
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "dry-run must leave the store file byte-identical")
	_, ok := st.VerifyBearer(b.Bearer)
	assert.True(t, ok, "dry-run must not invalidate any bearer")
}

// TestPanicRunE_WiresDeviceCredentialStep asserts (structurally) that the
// panic command documents the device-credential revocation in its action
// banner text, keeping the emergency contract visible to the operator.
func TestPanicRunE_WiresDeviceCredentialStep(t *testing.T) {
	cmd := newPanicCmd()
	assert.Contains(t, strings.ToLower(cmd.Long), "device credential",
		"panic --help must document the device-credential revocation step")
}
