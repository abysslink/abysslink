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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// devSSHKeychain is an in-memory KeychainStore whose Get returns the wrapped
// secrets.ErrNotFound on a miss, so device.Store.CAPublicKey mints the CA on
// first use (the enroll test mock returns a plain error and pre-seeds instead).
type devSSHKeychain struct{ data map[string]string }

func (k *devSSHKeychain) key(s, a string) string { return s + ":" + a }

func (k *devSSHKeychain) Set(_ context.Context, s, a, secret string) error {
	if k.data == nil {
		k.data = map[string]string{}
	}
	k.data[k.key(s, a)] = secret
	return nil
}

func (k *devSSHKeychain) Get(_ context.Context, s, a string) (string, error) {
	if v, ok := k.data[k.key(s, a)]; ok {
		return v, nil
	}
	return "", secrets.ErrNotFound
}

func (k *devSSHKeychain) Delete(_ context.Context, s, a string) error {
	delete(k.data, k.key(s, a))
	return nil
}

var _ secrets.KeychainStore = (*devSSHKeychain)(nil)

// fakeCAView is a test caKRLView. A non-nil caErr makes CAPublicKeyIfPresent
// fail (no enrolled CA / no keychain).
type fakeCAView struct {
	caLine  string
	caErr   error
	serials []uint64
}

func (f fakeCAView) CAPublicKeyIfPresent(context.Context) (string, error) {
	if f.caErr != nil {
		return "", f.caErr
	}
	return f.caLine, nil
}

func (f fakeCAView) RevokedSerials() []uint64 { return f.serials }

// withDevSSHPaths points the drift reads at temp files for the duration of the
// test, restoring the real /etc/ssh destinations afterwards. Pass "" for a path
// to leave that destination at a guaranteed-absent temp path (missing-file case).
func withDevSSHPaths(t *testing.T, caTrust, krl string) {
	t.Helper()
	origCA, origKRL := devSSHCATrustDest, devSSHKRLDest
	t.Cleanup(func() { devSSHCATrustDest, devSSHKRLDest = origCA, origKRL })
	if caTrust == "" {
		caTrust = filepath.Join(t.TempDir(), "absent-ca.pub")
	}
	if krl == "" {
		krl = filepath.Join(t.TempDir(), "absent.krl")
	}
	devSSHCATrustDest, devSSHKRLDest = caTrust, krl
}

// writeTemp writes content to a fresh temp file and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

// findCheck returns the first finding with the given Check name (or a zero
// finding + false).
func findCheck(findings []modules.Finding, check string) (modules.Finding, bool) {
	for _, f := range findings {
		if f.Check == check {
			return f, true
		}
	}
	return modules.Finding{}, false
}

const testCALine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTCAKEYABCDEFGHIJKLMNOPQRSTUV abysslink-device-ssh-ca"

func TestDevSSHDrift_KRLMatch(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// Installed CA trust file matches the store line; KRL lists exactly the
	// store's revoked serials ⇒ both OK.
	caTrust := writeTemp(t, "abysslink_device_ca.pub", testCALine+"\n")
	krl := writeTemp(t, "abysslink.krl", "binary-krl-bytes")
	withDevSSHPaths(t, caTrust, krl)

	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: "# CA key ssh-ed25519 SHA256:abc\nserial: 5\nserial: 7\n", ExitCode: 0},
	})
	ca := fakeCAView{caLine: testCALine, serials: []uint64{7, 5}}

	findings := devSSHDriftFindings(context.Background(), runner, ca)

	caF, ok := findCheck(findings, "ca-trust")
	require.True(t, ok, "expected ca-trust OK finding")
	assert.Equal(t, modules.SeverityOK, caF.Severity)
	krlF, ok := findCheck(findings, "krl")
	require.True(t, ok, "expected krl OK finding")
	assert.Equal(t, modules.SeverityOK, krlF.Severity)
}

func TestDevSSHDrift_KRLMatch_CollapsedRange(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// C1 regression: ssh-keygen COLLAPSES consecutive serials into "serial: N-M"
	// ranges (device serials are monotonic, so this is the common case). The
	// drift check must EXPAND the range and match the store — not false-WARN.
	caTrust := writeTemp(t, "abysslink_device_ca.pub", testCALine+"\n")
	krl := writeTemp(t, "abysslink.krl", "binary-krl-bytes")
	withDevSSHPaths(t, caTrust, krl)

	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: "# CA key ssh-ed25519 SHA256:abc\nserial: 1-3\nserial: 7-8\nserial: 20\n", ExitCode: 0},
	})
	ca := fakeCAView{caLine: testCALine, serials: []uint64{20, 1, 2, 3, 8, 7}}

	findings := devSSHDriftFindings(context.Background(), runner, ca)

	krlF, ok := findCheck(findings, "krl")
	require.True(t, ok, "collapsed-range KRL output must match the store ⇒ krl OK, not false drift")
	assert.Equal(t, modules.SeverityOK, krlF.Severity)
	_, drift := findCheck(findings, "krl-drift")
	assert.False(t, drift, "must not false-WARN on the collapsed-range form")
}

func TestDevSSHDrift_KRLUnparseable(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// A "serial:" line that ssh-keygen would never emit (non-numeric) ⇒ the parse
	// errors and the check degrades to devssh-unknown WARN, never a false-OK.
	caTrust := writeTemp(t, "abysslink_device_ca.pub", testCALine+"\n")
	krl := writeTemp(t, "abysslink.krl", "binary-krl-bytes")
	withDevSSHPaths(t, caTrust, krl)

	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: "# CA key\nserial: not-a-number\n", ExitCode: 0},
	})
	ca := fakeCAView{caLine: testCALine, serials: []uint64{5}}

	findings := devSSHDriftFindings(context.Background(), runner, ca)
	f, ok := findCheck(findings, "devssh-unknown")
	require.True(t, ok, "unparseable serial line ⇒ devssh-unknown WARN")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	_, okOK := findCheck(findings, "krl")
	assert.False(t, okOK, "unparseable output must never render a krl OK (no false-OK)")
}

func TestDevSSHDrift_KRLDrift(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// Live KRL lists a different serial set than the store ⇒ krl-drift WARN.
	caTrust := writeTemp(t, "abysslink_device_ca.pub", testCALine+"\n")
	krl := writeTemp(t, "abysslink.krl", "binary-krl-bytes")
	withDevSSHPaths(t, caTrust, krl)

	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: "# CA key\nserial: 5\n", ExitCode: 0}, // disk has only 5
	})
	ca := fakeCAView{caLine: testCALine, serials: []uint64{5, 9}} // store has 5 and 9

	findings := devSSHDriftFindings(context.Background(), runner, ca)

	f, ok := findCheck(findings, "krl-drift")
	require.True(t, ok, "expected krl-drift WARN finding")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	_, okOK := findCheck(findings, "krl")
	assert.False(t, okOK, "must not also emit a krl OK finding on drift")
}

func TestDevSSHDrift_KRLMissing(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// KRL file absent ⇒ krl-missing WARN (CA trust present so the CA check is OK).
	caTrust := writeTemp(t, "abysslink_device_ca.pub", testCALine+"\n")
	withDevSSHPaths(t, caTrust, "") // krl left at a guaranteed-absent temp path

	// No ssh-keygen call is expected — the stat fails before the probe runs.
	runner := shell.NewMockRunner()
	ca := fakeCAView{caLine: testCALine, serials: []uint64{5}}

	findings := devSSHDriftFindings(context.Background(), runner, ca)

	f, ok := findCheck(findings, "krl-missing")
	require.True(t, ok, "expected krl-missing WARN finding")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	assert.True(t, runner.Done(), "ssh-keygen must not run when the KRL is absent")
}

func TestDevSSHDrift_SshKeygenUnavailable(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// ssh-keygen exec error ⇒ devssh-unknown WARN (NEVER a false-OK).
	caTrust := writeTemp(t, "abysslink_device_ca.pub", testCALine+"\n")
	krl := writeTemp(t, "abysslink.krl", "binary-krl-bytes")
	withDevSSHPaths(t, caTrust, krl)

	runner := shell.NewMockRunner(shell.Call{Err: errors.New("exec: ssh-keygen: not found")})
	ca := fakeCAView{caLine: testCALine, serials: []uint64{5}}

	findings := devSSHDriftFindings(context.Background(), runner, ca)

	f, ok := findCheck(findings, "devssh-unknown")
	require.True(t, ok, "expected devssh-unknown WARN on probe failure")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	_, okOK := findCheck(findings, "krl")
	assert.False(t, okOK, "probe failure must never render a krl OK (no false-OK)")
}

func TestDevSSHDrift_SshKeygenNonZeroExit(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// ssh-keygen runs but exits non-zero (garbage KRL) ⇒ devssh-unknown WARN.
	caTrust := writeTemp(t, "abysslink_device_ca.pub", testCALine+"\n")
	krl := writeTemp(t, "abysslink.krl", "not-a-real-krl")
	withDevSSHPaths(t, caTrust, krl)

	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stderr: "invalid format", ExitCode: 255},
	})
	ca := fakeCAView{caLine: testCALine, serials: []uint64{5}}

	findings := devSSHDriftFindings(context.Background(), runner, ca)
	f, ok := findCheck(findings, "devssh-unknown")
	require.True(t, ok, "expected devssh-unknown WARN on non-zero exit")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

func TestDevSSHDrift_NoCA(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// CAPublicKey errors (no enrolled CA / no keychain) ⇒ zero findings.
	withDevSSHPaths(t, writeTemp(t, "ca.pub", testCALine), writeTemp(t, "k.krl", "x"))
	runner := shell.NewMockRunner()
	ca := fakeCAView{caErr: errors.New("device: no keychain backend")}

	findings := devSSHDriftFindings(context.Background(), runner, ca)
	assert.Empty(t, findings, "no enrolled CA ⇒ drift family is silent (auto-trust not in play)")

	// A nil view is equally silent (fail-safe).
	assert.Empty(t, devSSHDriftFindings(context.Background(), runner, nil))
}

func TestDevSSHDrift_CATrustDrift(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// CA-trust file content differs from the store line ⇒ ca-trust-drift WARN.
	caTrust := writeTemp(t, "abysslink_device_ca.pub", "ssh-ed25519 AAAASTALEKEY old-ca\n")
	krl := writeTemp(t, "abysslink.krl", "binary-krl-bytes")
	withDevSSHPaths(t, caTrust, krl)

	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: "# CA key\nserial: 5\n", ExitCode: 0},
	})
	ca := fakeCAView{caLine: testCALine, serials: []uint64{5}}

	findings := devSSHDriftFindings(context.Background(), runner, ca)
	f, ok := findCheck(findings, "ca-trust-drift")
	require.True(t, ok, "expected ca-trust-drift WARN")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

func TestDevSSHDrift_CATrustMissing(t *testing.T) {
	// Not t.Parallel(): mutates the devSSHCATrustDest/devSSHKRLDest package-var seam.
	// CA enrolled but the CA-trust file is absent ⇒ ca-trust-missing WARN.
	krl := writeTemp(t, "abysslink.krl", "binary-krl-bytes")
	withDevSSHPaths(t, "", krl) // CA trust left at a guaranteed-absent temp path

	runner := shell.NewMockRunner(shell.Call{
		Result: shell.Result{Stdout: "# CA key\nserial: 5\n", ExitCode: 0},
	})
	ca := fakeCAView{caLine: testCALine, serials: []uint64{5}}

	findings := devSSHDriftFindings(context.Background(), runner, ca)
	f, ok := findCheck(findings, "ca-trust-missing")
	require.True(t, ok, "expected ca-trust-missing WARN")
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// --- Task 2: wiring (findingFix + collectDoctorFindings) ---------------------

// TestFindingFix_DevSSH asserts every new drift check ID has a non-empty
// remediation. The CA/KRL drift fixes are all `up --apply` (the operator runs
// it; doctor never auto-fixes); devssh-unknown points at installing ssh-keygen.
func TestFindingFix_DevSSH(t *testing.T) {
	t.Parallel()
	for _, check := range []string{"ca-trust-drift", "krl-drift", "ca-trust-missing", "krl-missing"} {
		fix := findingFix(check)
		assert.NotEmpty(t, fix, "findingFix(%q) must return a non-empty remediation", check)
		assert.Contains(t, fix, "up --apply", "%q remediation must point at up --apply", check)
	}
	unknown := findingFix("devssh-unknown")
	assert.NotEmpty(t, unknown, "devssh-unknown must have a remediation")
	assert.Contains(t, unknown, "ssh-keygen", "devssh-unknown remediation must mention ssh-keygen")
}

// TestDevSSHCAView_KeychainBacked asserts the wiring helper builds a usable
// read-only CA view from a keychain-backed device store. It proves the H2
// guarantee: the read view NEVER mints a CA (no side effect on the doctor path),
// so a machine that never ran `up --apply` stays silent. Once a CA exists
// (minted by the write path, as enroll/up does), the read view sees it and the
// drift family runs end to end. A nil keychain yields a nil view (the fail-safe
// the gate relies on).
func TestDevSSHCAView_KeychainBacked(t *testing.T) {
	// Not t.Parallel(): mutates the deviceStorePath + devSSH path package-var seams.
	tmp := t.TempDir()
	origPath := deviceStorePath
	t.Cleanup(func() { deviceStorePath = origPath })
	storePath := filepath.Join(tmp, "devices.json")
	deviceStorePath = func() (string, error) { return storePath, nil }

	// nil keychain ⇒ nil view (fail-safe; the family stays silent).
	assert.Nil(t, devSSHCAView(modules.Deps{Keychain: nil}))

	kc := &devSSHKeychain{}
	view := devSSHCAView(modules.Deps{Keychain: kc})
	require.NotNil(t, view, "keychain-backed view must be constructed")

	// H2: a fresh store has no CA in the keychain. The read view must NOT mint
	// one — CAPublicKeyIfPresent returns ErrNotFound, the family is silent, and
	// nothing is persisted to the keychain as a side effect of running doctor.
	_, err := view.CAPublicKeyIfPresent(context.Background())
	require.ErrorIs(t, err, secrets.ErrNotFound, "read view must NOT mint a CA on first use")
	assert.Empty(t, devSSHDriftFindings(context.Background(), shell.NewMockRunner(), view),
		"no enrolled CA ⇒ drift family silent (and no CA minted)")
	_, getErr := kc.Get(context.Background(), "abysslink", "device-ssh-ca")
	require.ErrorIs(t, getErr, secrets.ErrNotFound, "doctor read path must not create a CA in the keychain")

	// Enroll a CA via the MINTING write path (what `up --apply`/enroll does),
	// then the read view sees it through the shared keychain.
	writeStore := device.New(storePath, nil, kc, nil)
	caLine, err := writeStore.CAPublicKey(context.Background())
	require.NoError(t, err, "write path mints the CA on first use")
	require.True(t, strings.HasPrefix(caLine, "ssh-"), "CA line must be an authorized_keys line, got %q", caLine)

	gotLine, err := view.CAPublicKeyIfPresent(context.Background())
	require.NoError(t, err, "read view sees the now-enrolled CA")
	require.Equal(t, caLine, gotLine)
	assert.Empty(t, view.RevokedSerials(), "fresh store has no revoked serials")

	// Drive the full family with this production-shaped view: install a matching
	// CA-trust file + an empty KRL, script ssh-keygen listing no serials ⇒ both OK.
	caTrust := writeTemp(t, "abysslink_device_ca.pub", caLine+"\n")
	krl := writeTemp(t, "abysslink.krl", "binary")
	withDevSSHPaths(t, caTrust, krl)
	runner := shell.NewMockRunner(shell.Call{Result: shell.Result{Stdout: "# CA key\n", ExitCode: 0}})

	findings := devSSHDriftFindings(context.Background(), runner, view)
	require.Len(t, findings, 2, "drift family emits exactly the ca-trust + krl findings")
	caF, ok := findCheck(findings, "ca-trust")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, caF.Severity)
	krlF, ok := findCheck(findings, "krl")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityOK, krlF.Severity)
}

var _ caKRLView = (*device.Store)(nil) // *device.Store must satisfy the drift view.
