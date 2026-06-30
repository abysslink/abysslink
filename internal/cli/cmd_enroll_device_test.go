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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/device"
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
	printDeviceBundle(p, io.Discard, false, b, rotated, false, sshConnInfo{})
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

// TestPrintDeviceBundle_QR covers the `enroll --qr` path: with showQR the
// bundle is rendered as scannable QR codes (one per credential) to the QR
// writer, alongside a scan prompt in the human output. CA pub is omitted from
// the QR set (public + available via `device ca`).
func TestPrintDeviceBundle_QR(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	b, _, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)

	var human, qrOut bytes.Buffer
	p := NewHumanPrinterTo(&human, io.Discard)
	printDeviceBundle(p, &qrOut, false, b, false, true /* showQR */, sshConnInfo{})

	got := stripANSI(human.String())
	assert.Contains(t, got, "Scan with your phone", "the QR scan prompt must be shown")
	for _, label := range []string{"SSH private key", "SSH certificate", "Bearer token", "Push token"} {
		assert.Contains(t, got, label, "QR section must label %q", label)
	}
	assert.NotEmpty(t, qrOut.String(), "QR codes must be rendered to the QR writer")

	// showQR=false renders no QR codes (regression: opt-in only).
	var human2, qrOut2 bytes.Buffer
	p2 := NewHumanPrinterTo(&human2, io.Discard)
	printDeviceBundle(p2, &qrOut2, false, b, false, false, sshConnInfo{})
	assert.Empty(t, qrOut2.String(), "no QR output unless --qr is set")
	assert.NotContains(t, stripANSI(human2.String()), "Scan with your phone")
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
	printDeviceBundle(p, io.Discard, true, b, rotated, false, sshConnInfo{})

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

// withEnrollStageFn swaps the enrollStageFn package-var seam for the duration
// of a test and restores it via t.Cleanup, so the pull-default UX is exercised
// without a live daemon.
func withEnrollStageFn(t *testing.T, fn func(ctx context.Context, b *device.Bundle, rotated bool, conn sshConnInfo) (*daemon.EnrollStageResult, error)) {
	t.Helper()
	prev := enrollStageFn
	enrollStageFn = fn
	t.Cleanup(func() { enrollStageFn = prev })
}

// TestEnrollPhone_PullDefault_StagesAndPrintsOneQR covers DEVC-07: on a
// successful stage, offerCredentialPull prints ONE capability-URL QR with a
// single-use prompt mentioning the TTL minutes, AND the one-time secret box
// still prints exactly once. The capability URL appears exactly once.
func TestEnrollPhone_PullDefault_StagesAndPrintsOneQR(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	b, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)

	const wantURL = "https://rig.ts.net:8443/enroll/ablk_e_xxxx"
	withEnrollStageFn(t, func(_ context.Context, _ *device.Bundle, _ bool, _ sshConnInfo) (*daemon.EnrollStageResult, error) {
		return &daemon.EnrollStageResult{URL: wantURL, TTLSeconds: 300}, nil
	})

	var human, qrOut bytes.Buffer
	p := NewHumanPrinterTo(&human, io.Discard)
	offerCredentialPull(ctx, p, &qrOut, false, b, rotated, false /* showQR */, sshConnInfo{})

	got := stripANSI(human.String())
	// The capability URL is rendered as an ANSI QR matrix (not literal text) to
	// the QR writer, AND printed once as text so the operator can open it
	// directly when scanning is inconvenient.
	assert.NotEmpty(t, qrOut.String(), "the capability-URL QR must be rendered")
	assert.NotContains(t, qrOut.String(), wantURL, "the QR encodes the URL into a matrix, not as literal text")
	assert.Equal(t, 1, strings.Count(got, wantURL), "the URL is also printed once as text for direct open")
	assert.Contains(t, got, "do NOT send it via a messaging app", "warn against link-preview consumption")

	// Single-use prompt mentions the minutes.
	assert.Contains(t, got, "single use", "the one-scan prompt must flag single-use")
	assert.Contains(t, got, "5 minutes", "the prompt must show the TTL in minutes")
	assert.Contains(t, got, "Scan with your phone to pull", "the one-scan prompt must be present")

	// The secret box STILL prints (source of truth) — bearer shown exactly once.
	assert.Equal(t, 1, strings.Count(got, b.Bearer), "the one-time secret box must still print the bearer once")
	assert.Contains(t, got, "Shown ONCE", "the one-time secret box must still print")

	// Under --json the URL is a typed record payload exactly once (printQR is
	// --json-safe), and the box record still prints — proving the URL travels
	// only via the QR/record channel.
	var jsonHuman bytes.Buffer
	jp := NewJSONPrinterTo(&jsonHuman, io.Discard)
	offerCredentialPull(ctx, jp, io.Discard, true, b, rotated, false, sshConnInfo{})
	assert.Equal(t, 1, strings.Count(jsonHuman.String(), wantURL), "under --json the capability URL appears exactly once as a typed record")
}

// TestEnrollPhone_DaemonUnreachable_Degrades covers the graceful-degradation
// invariant (T-28.2-13): any stage failure prints the inline notice + the box,
// and the per-credential QRs only when --qr was set — never the capability-URL
// QR, and never an error (offerCredentialPull has no error return).
func TestEnrollPhone_DaemonUnreachable_Degrades(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	b, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)

	withEnrollStageFn(t, func(_ context.Context, _ *device.Bundle, _ bool, _ sshConnInfo) (*daemon.EnrollStageResult, error) {
		return nil, fmt.Errorf("staging: %w", daemon.ErrUnreachable)
	})

	// showQR=false: notice + box, NO per-credential QRs, NO capability-URL QR.
	var human, qrOut bytes.Buffer
	p := NewHumanPrinterTo(&human, io.Discard)
	offerCredentialPull(ctx, p, &qrOut, false, b, rotated, false, sshConnInfo{})
	got := stripANSI(human.String())
	// "Daemon not reachable" survives the 54-col note-box wrap; the full
	// "showing credentials inline" title now spans two lines inside the box.
	assert.Contains(t, got, "Daemon not reachable", "a degraded notice must be printed")
	assert.Contains(t, got, "abysslink daemon enable --apply", "the notice must tell the operator how to enable the one-scan pull")
	assert.Contains(t, got, "Shown ONCE", "the box must still print on degrade")
	assert.Equal(t, 1, strings.Count(got, b.Bearer), "the bearer must still print once on degrade")
	assert.Empty(t, qrOut.String(), "no QR (URL or per-credential) when staging fails and --qr is unset")
	assert.NotContains(t, got, "Scan with your phone to pull", "no one-scan prompt on degrade")

	// showQR=true: notice + box + per-credential QRs, still NO capability-URL QR.
	var human2, qrOut2 bytes.Buffer
	p2 := NewHumanPrinterTo(&human2, io.Discard)
	offerCredentialPull(ctx, p2, &qrOut2, false, b, rotated, true, sshConnInfo{})
	got2 := stripANSI(human2.String())
	assert.Contains(t, got2, "Daemon not reachable", "a degraded notice must be printed")
	assert.Contains(t, got2, "Scan with your phone to import", "per-credential QRs print on degrade with --qr")
	assert.NotEmpty(t, qrOut2.String(), "per-credential QRs must render with --qr on degrade")
	assert.NotContains(t, got2, "Scan with your phone to pull", "no one-scan capability-URL prompt on degrade")
}

// TestEnrollPhone_StageJSONMatchesJSONOutput covers the no-wire-drift invariant
// (T-28.2-14): the json.RawMessage staged via the enrollStageFn default (built
// from newDeviceBundleRecord) decodes to the SAME field set + tag values as the
// `--json` printDeviceBundle output for the same Bundle.
func TestEnrollPhone_StageJSONMatchesJSONOutput(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	b, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)

	// The --json output for this bundle.
	var jsonOut bytes.Buffer
	jp := NewJSONPrinterTo(&jsonOut, io.Discard)
	printDeviceBundle(jp, io.Discard, true, b, rotated, false, sshConnInfo{})
	var fromJSON map[string]any
	require.NoError(t, json.Unmarshal(jsonOut.Bytes(), &fromJSON))

	// The ACTUAL staged bytes — produced by marshalStagedBundle, the same
	// function the default enrollStageFn POSTs to the daemon. Comparing the real
	// staging producer (not a re-call of the constructor) means a regression that
	// wraps/extends only the staged path would fail this test.
	staged, err := marshalStagedBundle(b, rotated, sshConnInfo{})
	require.NoError(t, err)
	var fromStage map[string]any
	require.NoError(t, json.Unmarshal(staged, &fromStage))

	assert.Equal(t, fromJSON, fromStage, "the staged JSON must match the --json output field-for-field (no wire drift)")

	// And every field the phone needs is actually present in the staged bytes.
	for _, k := range []string{
		"device", "bearer", "push_token", "ssh_private_key_pem",
		"ssh_certificate", "ca_public_key", "cert_not_after",
	} {
		assert.Contains(t, fromStage, k, "staged bundle must carry %q for the phone to import", k)
	}
}

// TestNewDeviceBundleRecord_ConnInfo covers the no-typing UX: when the rig's
// host + user are known, the record carries ready-to-paste ssh/mosh commands and
// the connection coordinates; when the host is unknown they are omitted (never a
// half-built command), so the phone JSON/page just drops them.
func TestNewDeviceBundleRecord_ConnInfo(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestDeviceStore(t, nil)
	b, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)

	// Host + user known → commands composed; default port 22 omitted from output.
	rec := newDeviceBundleRecord(b, rotated, sshConnInfo{Host: "rig.tail1.ts.net", User: "moh", Port: 22})
	assert.Equal(t, "rig.tail1.ts.net", rec.SSHHost)
	assert.Equal(t, "moh", rec.SSHUser)
	assert.Equal(t, 0, rec.SSHPort, "standard port 22 is omitted (omitempty keeps the page tidy)")
	assert.Equal(t, "ssh -i abysslink_phone moh@rig.tail1.ts.net", rec.SSHCommand)
	assert.Contains(t, rec.MoshCommand, `mosh --ssh="ssh -i abysslink_phone" moh@rig.tail1.ts.net -- tmux new -A -s main`)

	// Non-standard port → -p flag appears and the port is recorded.
	recP := newDeviceBundleRecord(b, rotated, sshConnInfo{Host: "rig.tail1.ts.net", User: "moh", Port: 2222})
	assert.Equal(t, 2222, recP.SSHPort)
	assert.Contains(t, recP.SSHCommand, "-p 2222")

	// Unknown host → no commands, no coordinates (degrade, never half-built).
	recEmpty := newDeviceBundleRecord(b, rotated, sshConnInfo{})
	assert.Empty(t, recEmpty.SSHCommand)
	assert.Empty(t, recEmpty.MoshCommand)
	assert.Empty(t, recEmpty.SSHHost)
}

// TestEnrollPhone_CapabilityURLNeverOnDisk covers T-28.2-12: on the success
// path the capability URL, the token, the bearer, and the private key never
// land in any file the enroll flow writes.
func TestEnrollPhone_CapabilityURLNeverOnDisk(t *testing.T) {
	ctx := context.Background()
	st, dir := newTestDeviceStore(t, nil)
	b, rotated, err := mintPhoneDeviceBundle(ctx, st)
	require.NoError(t, err)

	const wantURL = "https://rig.ts.net:8443/enroll/ablk_e_secrettoken"
	const wantToken = "ablk_e_secrettoken"
	withEnrollStageFn(t, func(_ context.Context, _ *device.Bundle, _ bool, _ sshConnInfo) (*daemon.EnrollStageResult, error) {
		return &daemon.EnrollStageResult{URL: wantURL, TTLSeconds: 300}, nil
	})

	var human, qrOut bytes.Buffer
	p := NewHumanPrinterTo(&human, io.Discard)
	offerCredentialPull(ctx, p, &qrOut, false, b, rotated, false, sshConnInfo{})

	// No file the device store wrote (devices.json, audit log, backups) carries
	// the capability URL/token, the bearer, or the private key.
	assertNoFileContains(t, dir, wantURL, "capability URL")
	assertNoFileContains(t, dir, wantToken, "capability token")
	assertNoFileContains(t, dir, b.Bearer, "bearer")
	assertNoFileContains(t, dir, "OPENSSH PRIVATE KEY", "SSH private key")

	// The runbook is the one document the full enroll flow writes to disk — it
	// must record only THAT enrollment happened + the cert expiry, never the
	// capability URL/token or any secret. (runbookMarkdown never receives the
	// staged URL, so this is a regression guard against that ever changing.)
	cc := &cmdContext{cfg: testCfgDefaults()}
	runbook := runbookMarkdown(cc, b.CertNotAfter)
	assert.NotContains(t, runbook, wantURL, "the runbook must never carry the capability URL")
	assert.NotContains(t, runbook, wantToken, "the runbook must never carry the capability token")
	assert.NotContains(t, runbook, b.Bearer, "the runbook must never carry the bearer")
	assert.NotContains(t, runbook, "PRIVATE KEY", "the runbook must never carry the private key")
}
