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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/secrets"
)

// fileShape mirrors the on-disk top-level JSON for white-box file assertions.
type fileShape struct {
	Version        int             `json:"version"`
	NextSerial     uint64          `json:"next_serial"`
	RevokedSerials []uint64        `json:"revoked_serials"`
	Devices        []device.Record `json:"devices"`
}

func readFileShape(t *testing.T, path string) fileShape {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var f fileShape
	require.NoError(t, json.Unmarshal(data, &f))
	return f
}

func TestEnroll_Basic(t *testing.T) {
	s, fa, _, path := testStore(t)
	ctx := context.Background()

	b, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	require.NotNil(t, b)

	// Bundle shape.
	assert.Equal(t, "phone", b.Name)
	assert.True(t, strings.HasPrefix(b.PushToken, "ablk_p_"), "push token prefix, got %q", b.PushToken)
	assert.True(t, strings.HasPrefix(b.Bearer, "ablk_b_"), "bearer prefix, got %q", b.Bearer)
	assert.NotContains(t, b.PushToken, "=", "base64url-nopad")
	assert.NotContains(t, b.Bearer, "=", "base64url-nopad")
	assert.Contains(t, b.SSHPrivateKeyPEM, "OPENSSH PRIVATE KEY")
	assert.Contains(t, b.SSHCertAuthorizedKey, "ssh-ed25519-cert-v01@openssh.com")
	assert.Contains(t, b.CAPublicKeyAuthorizedKey, "ssh-ed25519")
	assert.True(t, b.CertNotAfter.Equal(baseTime.Add(90*24*time.Hour)), "CertNotAfter = %v", b.CertNotAfter)

	// Record shape.
	rec, ok := s.Get("phone")
	require.True(t, ok)
	_, perr := ulid.ParseStrict(rec.ID)
	assert.NoError(t, perr, "ID must be a strict ULID, got %q", rec.ID)
	assert.Equal(t, "phone", rec.Kind)
	assert.Equal(t, b.PushToken, rec.PushToken)
	wantSHA := sha256.Sum256([]byte(b.Bearer))
	assert.Equal(t, hex.EncodeToString(wantSHA[:]), rec.BearerSHA256)
	assert.Equal(t, uint64(1), rec.SSHCertSerial)
	assert.True(t, strings.HasPrefix(rec.SSHPubKeyFP, "SHA256:"), "fingerprint, got %q", rec.SSHPubKeyFP)
	assert.True(t, rec.EnrolledAt.Equal(baseTime))
	assert.True(t, rec.RotatedAt.IsZero())
	assert.False(t, rec.Revoked)
	assert.Empty(t, rec.TLSClientCertFP)

	// One audited write at 0600, and the file really carries that mode.
	assert.Equal(t, 1, fa.writeCount())
	assert.Equal(t, os.FileMode(0o600), fa.perms[0])
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestEnroll_DuplicateNameAndReuseAfterRevoke(t *testing.T) {
	s, _, _, _ := testStore(t)
	ctx := context.Background()

	b1, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	rec1, ok := s.Get("phone")
	require.True(t, ok)

	_, err = s.Enroll(ctx, "phone", "phone")
	require.ErrorIs(t, err, device.ErrExists)

	require.NoError(t, s.Revoke(ctx, "phone"))
	b2, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err, "a revoked name must be re-enrollable")
	rec2, ok := s.Get("phone")
	require.True(t, ok)
	assert.NotEqual(t, rec1.ID, rec2.ID, "re-enrollment mints a fresh identity")
	assert.NotEqual(t, b1.Bearer, b2.Bearer)
	assert.False(t, rec2.Revoked, "Get prefers the active record")

	// Old bearer must stay dead.
	_, ok = s.VerifyBearer(b1.Bearer)
	assert.False(t, ok)
	got, ok := s.VerifyBearer(b2.Bearer)
	require.True(t, ok)
	assert.Equal(t, rec2.ID, got.ID)
}

func TestEnroll_Validation(t *testing.T) {
	s, _, _, _ := testStore(t)
	ctx := context.Background()

	for _, name := range []string{"", "bad name", "-lead", ".lead", "tab\tname", strings.Repeat("x", 65)} {
		_, err := s.Enroll(ctx, name, "phone")
		assert.Error(t, err, "name %q must be rejected", name)
	}
	_, err := s.Enroll(ctx, "phone", "")
	assert.Error(t, err, "empty kind must be rejected")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Enroll(cancelled, "phone", "phone")
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRotate(t *testing.T) {
	s, _, clk, path := testStore(t)
	ctx := context.Background()

	b1, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	rec1, _ := s.Get("phone")

	rotatedAt := baseTime.Add(time.Hour)
	clk.Set(rotatedAt)
	b2, err := s.Rotate(ctx, "phone")
	require.NoError(t, err)

	rec2, ok := s.Get("phone")
	require.True(t, ok)
	assert.Equal(t, rec1.ID, rec2.ID, "ID survives rotation")
	assert.True(t, rec2.EnrolledAt.Equal(rec1.EnrolledAt), "EnrolledAt survives rotation")
	assert.True(t, rec2.RotatedAt.Equal(rotatedAt))
	assert.Equal(t, uint64(2), rec2.SSHCertSerial, "rotation consumes the next serial")
	assert.NotEqual(t, rec1.PushToken, rec2.PushToken)
	assert.NotEqual(t, rec1.BearerSHA256, rec2.BearerSHA256)
	assert.NotEqual(t, rec1.SSHPubKeyFP, rec2.SSHPubKeyFP, "rotation mints a fresh keypair")

	// Old bearer invalidated immediately; new bearer works.
	_, ok = s.VerifyBearer(b1.Bearer)
	assert.False(t, ok, "rotate must invalidate the old bearer")
	got, ok := s.VerifyBearer(b2.Bearer)
	require.True(t, ok)
	assert.Equal(t, rec1.ID, got.ID)

	// Old serial lands in revoked_serials (DEVC-02 auditability).
	assert.Equal(t, []uint64{1}, s.RevokedSerials())
	f := readFileShape(t, path)
	assert.Equal(t, []uint64{1}, f.RevokedSerials)
	assert.Equal(t, uint64(3), f.NextSerial)
	require.Len(t, f.Devices, 1, "rotate updates in place, no second record")

	_, err = s.Rotate(ctx, "ghost")
	assert.ErrorIs(t, err, device.ErrNotFound)
}

func TestRevoke(t *testing.T) {
	s, _, clk, path := testStore(t)
	ctx := context.Background()

	b, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)

	revokedAt := baseTime.Add(30 * time.Minute)
	clk.Set(revokedAt)
	require.NoError(t, s.Revoke(ctx, "phone"))

	rec, ok := s.Get("phone")
	require.True(t, ok, "Get still surfaces revoked records")
	assert.True(t, rec.Revoked)
	assert.True(t, rec.RevokedAt.Equal(revokedAt))
	assert.Empty(t, rec.PushToken, "revocation blanks the push token")
	assert.Empty(t, rec.BearerSHA256, "revocation must not leave a verifiable hash behind")
	assert.Equal(t, []uint64{1}, s.RevokedSerials())

	_, ok = s.VerifyBearer(b.Bearer)
	assert.False(t, ok, "revoked device must fail VerifyBearer")

	// The blanked hash is really gone from disk too.
	f := readFileShape(t, path)
	require.Len(t, f.Devices, 1)
	assert.Empty(t, f.Devices[0].BearerSHA256)
	assert.Empty(t, f.Devices[0].PushToken)

	// Idempotent: revoking again is a counted-as-success no-op.
	require.NoError(t, s.Revoke(ctx, "phone"))
	// Unknown name errors.
	assert.ErrorIs(t, s.Revoke(ctx, "ghost"), device.ErrNotFound)
}

func TestRevokeAll_OneAtomicWrite(t *testing.T) {
	s, fa, _, _ := testStore(t)
	ctx := context.Background()

	bundles := map[string]*device.Bundle{}
	for _, name := range []string{"phone", "tablet", "watch"} {
		b, err := s.Enroll(ctx, name, "phone")
		require.NoError(t, err)
		bundles[name] = b
	}
	require.NoError(t, s.Revoke(ctx, "watch")) // pre-revoked: not re-counted

	before := fa.writeCount()
	n, err := s.RevokeAll(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "only active devices transition")
	assert.Equal(t, before+1, fa.writeCount(), "DEVC-03: RevokeAll is ONE atomic file write")

	for name, b := range bundles {
		_, ok := s.VerifyBearer(b.Bearer)
		assert.False(t, ok, "%s must fail VerifyBearer after RevokeAll", name)
		rec, ok := s.Get(name)
		require.True(t, ok)
		assert.True(t, rec.Revoked)
		assert.Empty(t, rec.BearerSHA256)
	}
	assert.ElementsMatch(t, []uint64{1, 2, 3}, s.RevokedSerials())

	// Nothing active left: no-op, no write.
	before = fa.writeCount()
	n, err = s.RevokeAll(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Equal(t, before, fa.writeCount(), "no mutation means no write")
}

func TestVerifyBearer(t *testing.T) {
	s, _, _, _ := testStore(t)
	ctx := context.Background()

	b, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)

	rec, ok := s.VerifyBearer(b.Bearer)
	require.True(t, ok)
	assert.Equal(t, "phone", rec.Name)

	for _, presented := range []string{
		"",
		"ablk_b_wrong",
		b.Bearer + "x",
		b.Bearer[:len(b.Bearer)-1],
		rec.BearerSHA256, // presenting the stored hash itself must not verify
	} {
		_, ok := s.VerifyBearer(presented)
		assert.False(t, ok, "presented %q must not verify", presented)
	}

	// Returned record is a copy: mutating it must not poison the store.
	rec.Name = "tampered"
	again, ok := s.VerifyBearer(b.Bearer)
	require.True(t, ok)
	assert.Equal(t, "phone", again.Name)
}

func TestVerifyBearer_MtimeReload(t *testing.T) {
	_, fa, clk, path := testStore(t)
	ctx := context.Background()

	// Two independent Store instances over the same file simulate the daemon
	// (reader) and an out-of-process CLI (writer) sharing the registry.
	kc := secrets.NewMockStore()
	writer := device.New(path, fa, kc, clk.Now)
	reader := device.New(path, fa, kc, clk.Now)

	b, err := writer.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	_, ok := reader.VerifyBearer(b.Bearer)
	require.True(t, ok, "reader must lazily load the file")

	// Out-of-process revocation: the reader must observe it on the next call.
	require.NoError(t, writer.Revoke(ctx, "phone"))
	bumpMtime(t, path)
	_, ok = reader.VerifyBearer(b.Bearer)
	assert.False(t, ok, "reader must re-load on mtime change and fail the revoked bearer")

	// And a fully external rewrite (raw bytes, not via a Store) is seen too.
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, bytes.ReplaceAll(data, []byte(`"revoked": true`), []byte(`"revoked": false`)), 0o600))
	bumpMtime(t, path)
	recs := reader.List()
	require.Len(t, recs, 1)
	assert.False(t, recs[0].Revoked, "external rewrite must be re-loaded")
}

func TestTouchLastSeen_RateLimit(t *testing.T) {
	s, fa, _, _ := testStore(t)
	ctx := context.Background()

	_, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	rec, _ := s.Get("phone")

	t0 := baseTime.Add(10 * time.Minute)
	require.NoError(t, s.TouchLastSeen(ctx, rec.ID, t0))
	after := fa.writeCount()
	got, _ := s.Get("phone")
	assert.True(t, got.LastSeen.Equal(t0))

	// Within 60s of the stored LastSeen: skipped entirely.
	require.NoError(t, s.TouchLastSeen(ctx, rec.ID, t0.Add(30*time.Second)))
	require.NoError(t, s.TouchLastSeen(ctx, rec.ID, t0.Add(59*time.Second)))
	assert.Equal(t, after, fa.writeCount(), "touches within 60s must not write")
	got, _ = s.Get("phone")
	assert.True(t, got.LastSeen.Equal(t0))

	// Past the window: persisted.
	t1 := t0.Add(61 * time.Second)
	require.NoError(t, s.TouchLastSeen(ctx, rec.ID, t1))
	assert.Equal(t, after+1, fa.writeCount())
	got, _ = s.Get("phone")
	assert.True(t, got.LastSeen.Equal(t1))

	// Unknown ID errors; revoked ID is a silent no-op.
	assert.ErrorIs(t, s.TouchLastSeen(ctx, "01ZZZZZZZZZZZZZZZZZZZZZZZZ", t1), device.ErrNotFound)
	require.NoError(t, s.Revoke(ctx, "phone"))
	before := fa.writeCount()
	require.NoError(t, s.TouchLastSeen(ctx, rec.ID, t1.Add(time.Hour)))
	assert.Equal(t, before, fa.writeCount(), "touching a revoked device must not write")
}

func TestStale_Matrix(t *testing.T) {
	s, _, clk, _ := testStore(t)
	ctx := context.Background()
	window := 24 * time.Hour

	// Enroll everything 48h before "now".
	clk.Set(baseTime.Add(-48 * time.Hour))
	for _, name := range []string{"never-seen-old", "seen-recently", "seen-long-ago", "revoked-old"} {
		_, err := s.Enroll(ctx, name, "phone")
		require.NoError(t, err)
	}
	id := func(name string) string {
		r, ok := s.Get(name)
		require.True(t, ok)
		return r.ID
	}
	require.NoError(t, s.TouchLastSeen(ctx, id("seen-recently"), baseTime.Add(-time.Hour)))
	require.NoError(t, s.TouchLastSeen(ctx, id("seen-long-ago"), baseTime.Add(-25*time.Hour)))
	require.NoError(t, s.Revoke(ctx, "revoked-old"))

	// A fresh enrollment inside the window.
	clk.Set(baseTime.Add(-time.Hour))
	_, err := s.Enroll(ctx, "never-seen-new", "phone")
	require.NoError(t, err)

	clk.Set(baseTime)
	var names []string
	for _, r := range s.Stale(window) {
		names = append(names, r.Name)
	}
	assert.ElementsMatch(t, []string{"never-seen-old", "seen-long-ago"}, names,
		"stale = active AND (never seen + enrolled > window ago, OR last seen > window ago)")
}

func TestNoSecretsOnDiskOrInLogs(t *testing.T) {
	s, _, _, path := testStore(t)
	ctx := context.Background()

	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	b1, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	b2, err := s.Rotate(ctx, "phone")
	require.NoError(t, err)
	require.NoError(t, s.Revoke(ctx, "phone"))

	fileBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	logs := logBuf.String()

	for label, secret := range map[string]string{
		"enroll bearer":      b1.Bearer,
		"rotate bearer":      b2.Bearer,
		"enroll private key": strings.TrimSpace(b1.SSHPrivateKeyPEM),
		"rotate private key": strings.TrimSpace(b2.SSHPrivateKeyPEM),
	} {
		assert.NotContains(t, string(fileBytes), secret, "%s must never reach the records file", label)
		assert.NotContains(t, logs, secret, "%s must never reach a log line", label)
	}
	// Even the bearer hashes stay out of logs.
	h1 := sha256.Sum256([]byte(b1.Bearer))
	assert.NotContains(t, logs, hex.EncodeToString(h1[:]))
}

func TestTokenUniqueness(t *testing.T) {
	s, _, _, _ := testStore(t)
	ctx := context.Background()

	seen := map[string]bool{}
	for _, name := range []string{"a", "b", "c", "d"} {
		b, err := s.Enroll(ctx, name, "phone")
		require.NoError(t, err)
		for _, v := range []string{b.Bearer, b.PushToken, b.SSHPrivateKeyPEM} {
			assert.False(t, seen[v], "minted values must never repeat")
			seen[v] = true
		}
	}
}

func TestGet_RevokedFallbackAndMissing(t *testing.T) {
	s, _, _, _ := testStore(t)
	ctx := context.Background()

	_, ok := s.Get("ghost")
	assert.False(t, ok)

	_, err := s.Enroll(ctx, "phone", "phone")
	require.NoError(t, err)
	require.NoError(t, s.Revoke(ctx, "phone"))
	rec, ok := s.Get("phone")
	require.True(t, ok, "Get falls back to the revoked record when no active one exists")
	assert.True(t, rec.Revoked)

	assert.Len(t, s.List(), 1)
}
