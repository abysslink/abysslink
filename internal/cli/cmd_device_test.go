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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deviceTestBase is the fixed epoch the device-test fake clocks start at.
var deviceTestBase = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// deviceTestClock is a settable clock for deterministic stale-window tests.
type deviceTestClock struct {
	mu sync.Mutex
	t  time.Time
}

func newDeviceTestClock() *deviceTestClock { return &deviceTestClock{t: deviceTestBase} }

func (c *deviceTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *deviceTestClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// newTestDeviceStore builds a real device.Store over a temp records file with
// the real (unsigned) audit writer and a mock keychain. Returns the store and
// the temp dir holding devices.json + audit.log (+ backups).
func newTestDeviceStore(t *testing.T, now func() time.Time) (*device.Store, string) {
	t.Helper()
	dir := t.TempDir()
	aud := audit.New(filepath.Join(dir, "audit.log"))
	return device.New(filepath.Join(dir, "devices.json"), aud, secrets.NewMockStore(), now), dir
}

// overrideDeviceStorePath points the package-level deviceStorePath seam at a
// fixed path for the duration of the test.
func overrideDeviceStorePath(t *testing.T, path string) {
	t.Helper()
	orig := deviceStorePath
	deviceStorePath = func() (string, error) { return path, nil }
	t.Cleanup(func() { deviceStorePath = orig })
}

// TestDeviceLS_Table covers the human table: enrolled + stale + revoked rows,
// "never" for a device that has not checked in, and the column headers.
func TestDeviceLS_Table(t *testing.T) {
	ctx := context.Background()
	clock := newDeviceTestClock()
	st, _ := newTestDeviceStore(t, clock.Now)

	_, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	_, err = st.Enroll(ctx, "tablet", "phone")
	require.NoError(t, err)
	require.NoError(t, st.Revoke(ctx, "tablet"))

	// 10 days later: "phone" (never seen, enrolled >7d ago) is stale (DEVC-04).
	clock.Set(deviceTestBase.Add(10 * 24 * time.Hour))

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, io.Discard)
	require.NoError(t, deviceLS(p, false, st))

	got := stripANSI(out.String())
	for _, col := range []string{"NAME", "KIND", "ENROLLED", "ROTATED", "CERT EXPIRES", "LAST SEEN", "STALE", "REVOKED"} {
		assert.Contains(t, got, col, "table must carry the %s column", col)
	}
	assert.Contains(t, got, "phone")
	assert.Contains(t, got, "tablet")
	assert.Contains(t, got, "never", "a device that never checked in must show LAST SEEN never")
	assert.Contains(t, got, "2026-06-01", "enrollment date must be shown")

	// Row-level flags: phone is stale (not revoked), tablet is revoked (never stale).
	for _, line := range strings.Split(got, "\n") {
		row := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(row, "phone "):
			assert.Contains(t, line, "yes", "phone row must be flagged stale after 10 quiet days")
		case strings.HasPrefix(row, "tablet "):
			assert.Contains(t, line, "yes", "tablet row must be flagged revoked")
		}
	}
}

// TestDeviceLS_JSON covers the --json array shape, including the stable empty
// encoding ([]).
func TestDeviceLS_JSON(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)

	// Empty store: stable [] — never null.
	var out bytes.Buffer
	p := NewJSONPrinterTo(&out, io.Discard)
	require.NoError(t, deviceLS(p, true, st))
	assert.Equal(t, "[]", strings.TrimSpace(out.String()), "empty device list must encode as []")

	_, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)

	out.Reset()
	require.NoError(t, deviceLS(p, true, st))
	var rows []deviceListRow
	require.NoError(t, json.Unmarshal(out.Bytes(), &rows))
	require.Len(t, rows, 1)
	assert.Equal(t, "phone", rows[0].Name)
	assert.Equal(t, "phone", rows[0].Kind)
	assert.NotEmpty(t, rows[0].EnrolledAt)
	assert.NotEmpty(t, rows[0].CertExpires)
	assert.Empty(t, rows[0].LastSeen, "never-seen device must omit last_seen")
	assert.False(t, rows[0].Stale)
	assert.False(t, rows[0].Revoked)
}

// TestDeviceRevoke_DryRunDefault covers the dry-run default: a [plan] preview
// and zero mutation.
func TestDeviceRevoke_DryRunDefault(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	b, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, io.Discard)
	require.NoError(t, deviceRevoke(ctx, p, st, "phone", false, false))

	got := stripANSI(out.String())
	assert.Contains(t, got, "[plan]", "dry-run must print a plan line")
	assert.Contains(t, got, "--apply", "dry-run must point at --apply")

	// No mutation: the bearer still verifies and the record is still active.
	_, ok := st.VerifyBearer(b.Bearer)
	assert.True(t, ok, "dry-run revoke must not invalidate the bearer")
	rec, found := st.Get("phone")
	require.True(t, found)
	assert.False(t, rec.Revoked, "dry-run revoke must not revoke the record")
}

// TestDeviceRevoke_Apply covers --apply: the device is individually revoked
// (DEVC-01) and its bearer stops verifying.
func TestDeviceRevoke_Apply(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	b, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	b2, err := st.Enroll(ctx, "tablet", "phone")
	require.NoError(t, err)

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, io.Discard)
	require.NoError(t, deviceRevoke(ctx, p, st, "phone", true, false))

	assert.Contains(t, stripANSI(out.String()), "Revoked device \"phone\"")
	_, ok := st.VerifyBearer(b.Bearer)
	assert.False(t, ok, "revoked device's bearer must stop verifying")
	_, ok = st.VerifyBearer(b2.Bearer)
	assert.True(t, ok, "revocation is per-device: the other device must keep working")
}

// TestDeviceRevoke_UnknownName covers the clear-error contract: an unknown
// name errors and lists the known device names.
func TestDeviceRevoke_UnknownName(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	_, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)

	var out bytes.Buffer
	p := NewHumanPrinterTo(&out, io.Discard)
	err = deviceRevoke(ctx, p, st, "watch", true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"watch"`, "error must name the unknown device")
	assert.Contains(t, err.Error(), "phone", "error must list the known device names")

	// Empty store variant: still a clear error, pointing at enrollment.
	stEmpty, _ := newTestDeviceStore(t, nil)
	err = deviceRevoke(ctx, p, stEmpty, "watch", true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no devices are enrolled")
}

// TestDeviceCA covers `device ca`: the authorized_keys-format CA line on
// stdout (human) and the structured record under --json.
func TestDeviceCA(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)

	var out, errOut bytes.Buffer
	p := NewHumanPrinterTo(&out, &errOut)
	require.NoError(t, deviceCA(ctx, p, st, false))
	line := strings.TrimSpace(stripANSI(out.String()))
	assert.True(t, strings.HasPrefix(line, "ssh-ed25519 "), "CA line must be authorized_keys format, got %q", line)
	assert.Contains(t, stripANSI(errOut.String()), "TrustedUserCAKeys", "sshd wiring hint goes to stderr")

	// JSON mode: one structured record; the same CA key (stable across calls).
	var jsonOut bytes.Buffer
	jp := NewJSONPrinterTo(&jsonOut, io.Discard)
	require.NoError(t, deviceCA(ctx, jp, st, true))
	var rec map[string]string
	require.NoError(t, json.Unmarshal(jsonOut.Bytes(), &rec))
	assert.Equal(t, line, rec["ca_public_key"], "CA key must be stable across calls")
}

// TestDeviceCommand_RootRegistration covers wiring: `abysslink device ls`
// works end-to-end through the root command (read-only path, temp store).
func TestDeviceCommand_RootRegistration(t *testing.T) {
	dir := t.TempDir()
	overrideDeviceStorePath(t, filepath.Join(dir, "devices.json"))

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"device", "ls", "--json"})
	require.NoError(t, root.ExecuteContext(context.Background()))
	assert.Equal(t, "[]", strings.TrimSpace(out.String()), "no store file = empty JSON array")
}

// TestDeviceRevoke_RootDryRun covers the root-level dry-run default for
// `device revoke <name>`: plan output, no store mutation, exit 0.
func TestDeviceRevoke_RootDryRun(t *testing.T) {
	ctx := context.Background()
	clock := newDeviceTestClock()
	st, dir := newTestDeviceStore(t, clock.Now)
	b, err := st.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	overrideDeviceStorePath(t, filepath.Join(dir, "devices.json"))

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"device", "revoke", "phone"})
	require.NoError(t, root.ExecuteContext(ctx))

	assert.Contains(t, stripANSI(out.String()), "[plan]")
	_, ok := st.VerifyBearer(b.Bearer)
	assert.True(t, ok, "root-level dry-run revoke must not mutate the store")
}
