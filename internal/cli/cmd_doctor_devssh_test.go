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
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCAView is a test caKRLView. A non-nil caErr makes CAPublicKey fail
// (no enrolled CA / no keychain).
type fakeCAView struct {
	caLine  string
	caErr   error
	serials []uint64
}

func (f fakeCAView) CAPublicKey(context.Context) (string, error) {
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

func TestParseKRLSerials(t *testing.T) {
	t.Parallel()

	// Real-shaped ssh-keygen -Q -l -f output: a CA-key header line then serials,
	// out of order and with surrounding whitespace, plus a noise line.
	stdout := "# CA key ssh-ed25519 SHA256:abc123\n" +
		"  serial: 7 \n" +
		"serial: 5\n" +
		"some unrelated line\n" +
		"serial: 12\n"
	got := parseKRLSerials(stdout)
	assert.Equal(t, []uint64{5, 7, 12}, got, "serials sorted ascending; header + noise ignored")

	// Empty / header-only output ⇒ empty serial set (a valid empty KRL).
	assert.Empty(t, parseKRLSerials("# CA key ssh-ed25519 SHA256:abc123\n"))
	assert.Empty(t, parseKRLSerials(""))
}

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
