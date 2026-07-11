//go:build darwin

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

package hwkey

// enclave_darwin_test.go — the Secure Enclave fail-closed battery. Every
// sc_auth / ssh-keygen interaction is a scripted MockRunner Call; the dylib
// probe points at a fixture file. No live enclave, keychain, or Touch ID.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestEnclave builds a SecureEnclaveProvider with deterministic seams: a
// fixture dylib, same-dir toolchain, a live TTY, and a caller-controlled
// temp dir standing in for the `ssh-keygen -K` CWD.
func newTestEnclave(t *testing.T, r shell.Runner, tmp string) *SecureEnclaveProvider {
	t.Helper()
	dylib := filepath.Join(t.TempDir(), "ssh-keychain.dylib")
	require.NoError(t, os.WriteFile(dylib, []byte("sk-api"), 0o644))
	p := newSecureEnclaveProvider(r)
	p.dylibPath = dylib
	p.resolvePath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	p.isTTY = func() bool { return true }
	p.mkTempDir = func() (string, error) { return tmp, nil }
	return p
}

// enclaveHappyCalls scripts the four external interactions of a successful
// enrollment: ssh -V, sc_auth create (interactive), sc_auth list (one row
// containing the label), ssh-keygen -K (interactive, in-dir).
func enclaveHappyCalls(label string) []shell.Call {
	return []shell.Call{
		sshVOKCall(),
		{Result: shell.Result{ExitCode: 0}}, // sc_auth create-ctk-identity (silent success — ASSUMED, post-verified)
		{Result: shell.Result{Stdout: "hash                                         label     type\nABC123                                       " + label + "  p-256-ne\n", ExitCode: 0}},
		{Result: shell.Result{ExitCode: 0}}, // ssh-keygen -K
	}
}

// plantEnclaveFixture simulates the handle files `ssh-keygen -K` downloads.
func plantEnclaveFixture(t *testing.T, dir, pubLine string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "id_ecdsa_sk_rk"), []byte("handle"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "id_ecdsa_sk_rk.pub"), []byte(pubLine+"\n"), 0o644))
}

func TestEnclaveEnroll_KeytypeLiteralLocked(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	tmp := t.TempDir()
	plantEnclaveFixture(t, tmp, "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr enclave")
	r := shell.NewMockRunner(enclaveHappyCalls("abysslink-rig")...)
	p := newTestEnclave(t, r, tmp)
	dst := t.TempDir()

	enrolled, err := p.Enroll(context.Background(), EnrollRequest{Dir: dst, Label: "abysslink-rig"})
	require.NoError(t, err)
	require.True(t, r.Done())

	ic := r.RunInteractiveCalls()
	require.Len(t, ic, 2)
	assert.Equal(t, []string{"sc_auth", "create-ctk-identity", "-l", "abysslink-rig", "-k", "p-256-ne", "-t", "bio"}, ic[0],
		"ONLY p-256-ne (non-exportable) may ever appear on a sc_auth argv, and -t is always bio")
	assert.Equal(t, []string{"ssh-keygen", "-K", "-w", p.dylibPath, "-N", ""}, ic[1])

	// The -K call must have run in the FRESH temp dir (Overwrite blocker + fail-closed file count).
	var kCall shell.Call
	for _, c := range r.RecordedCalls() {
		if c.Name == "ssh-keygen" {
			kCall = c
		}
	}
	assert.Equal(t, tmp, kCall.Dir, "ssh-keygen -K must run in the provider-controlled temp dir")

	assert.Equal(t, KindSecureEnclave, enrolled.Kind)
	assert.Equal(t, filepath.Join(dst, "id_ecdsa_sk_rk"), enrolled.PrivateHandle)
	assert.FileExists(t, enrolled.PrivateHandle)
	assert.FileExists(t, enrolled.PublicKeyPath)

	// The -k allowlist is a SINGLE literal: any other configured value is
	// refused pre-exec (exportable p-256 / silent-fail p-384-ne unreachable).
	r2 := shell.NewMockRunner()
	p2 := newTestEnclave(t, r2, t.TempDir())
	p2.ctkKeyType = "p-256" // exportable — must never reach an argv
	_, err = p2.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "x"})
	require.ErrorIs(t, err, ErrSoftwareKey)
	assert.Empty(t, r2.RecordedCalls())
}

func TestEnclaveEnroll_Ed25519Refused(t *testing.T) {
	r := shell.NewMockRunner()
	p := newTestEnclave(t, r, t.TempDir())
	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "x", KeyType: "ed25519-sk"})
	require.ErrorIs(t, err, ErrSoftwareKey, "the enclave is P-256 only; the request must never degrade to a different key")
	assert.Empty(t, r.RecordedCalls())
}

// TestEnclaveEnroll_NoIdentityRefuses: sc_auth list exits 0 with ONLY the
// header line — the exit code lies; zero identities means ErrEnrollFailed.
func TestEnclaveEnroll_NoIdentityRefuses(t *testing.T) {
	r := shell.NewMockRunner(
		sshVOKCall(),
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "hash    label    type\n", ExitCode: 0}}, // header only
	)
	p := newTestEnclave(t, r, t.TempDir())
	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "abysslink-rig"})
	require.ErrorIs(t, err, ErrEnrollFailed)
	assert.Len(t, r.RunInteractiveCalls(), 1, "ssh-keygen -K must never run when zero identities exist")
	assert.True(t, r.Done())
}

// TestEnclaveEnroll_LabelMissingRefuses: rows exist but none carries our label.
func TestEnclaveEnroll_LabelMissingRefuses(t *testing.T) {
	r := shell.NewMockRunner(
		sshVOKCall(),
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "hash  label  type\nXYZ   other-identity  p-256-ne\n", ExitCode: 0}},
	)
	p := newTestEnclave(t, r, t.TempDir())
	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "abysslink-rig"})
	require.ErrorIs(t, err, ErrEnrollFailed)
}

// TestEnclaveEnroll_KZeroFilesRefuses: `ssh-keygen -K` exits 0 ("No keys to
// download" lie) but produced zero handle files — ErrEnrollFailed.
func TestEnclaveEnroll_KZeroFilesRefuses(t *testing.T) {
	tmp := t.TempDir() // deliberately left empty
	r := shell.NewMockRunner(enclaveHappyCalls("abysslink-rig")...)
	p := newTestEnclave(t, r, tmp)
	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "abysslink-rig"})
	require.ErrorIs(t, err, ErrEnrollFailed)
	assert.True(t, r.Done())
}

// TestEnclaveEnroll_PubTokenMismatchDeletes: the downloaded pub is not the
// exact sk-ecdsa token — files deleted, ErrSoftwareKey.
func TestEnclaveEnroll_PubTokenMismatchDeletes(t *testing.T) {
	tmp := t.TempDir()
	plantEnclaveFixture(t, tmp, "ecdsa-sha2-nistp256 AAAA plain-software-ecdsa")
	r := shell.NewMockRunner(enclaveHappyCalls("abysslink-rig")...)
	p := newTestEnclave(t, r, tmp)
	dst := t.TempDir()

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: dst, Label: "abysslink-rig"})
	require.ErrorIs(t, err, ErrSoftwareKey)
	assert.NoFileExists(t, filepath.Join(tmp, "id_ecdsa_sk_rk"))
	assert.NoFileExists(t, filepath.Join(tmp, "id_ecdsa_sk_rk.pub"))
	assert.NoFileExists(t, filepath.Join(dst, "id_ecdsa_sk_rk"))
}

// writeEnclaveHandle plants one named handle + .pub pair, simulating one of
// several resident keys `ssh-keygen -K` downloads.
func writeEnclaveHandle(t *testing.T, dir, base, pubLine string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, base), []byte("handle-"+base), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, base+".pub"), []byte(pubLine+"\n"), 0o644))
}

// TestEnclaveEnroll_MultipleHandlesSelectsLabeled is the P37-04 regression:
// `ssh-keygen -K` downloads a handle for EVERY resident key the sk-api
// provider reports, not just the identity created in step 1. On a Mac with a
// pre-existing enclave SSH identity the lexically FIRST glob match is the OLD
// key — installing it records the wrong credential. The provider must select
// the handle whose .pub carries the just-created label.
func TestEnclaveEnroll_MultipleHandlesSelectsLabeled(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	tmp := t.TempDir()
	// OLD foreign identity — lexically first, the buggy pick.
	writeEnclaveHandle(t, tmp, "id_ecdsa_sk_rk", "sk-ecdsa-sha2-nistp256@openssh.com AAAAOld some-other-tool")
	// NEW abysslink identity created by this enrollment.
	writeEnclaveHandle(t, tmp, "id_ecdsa_sk_rk1", "sk-ecdsa-sha2-nistp256@openssh.com AAAANew abysslink-rig")

	r := shell.NewMockRunner(enclaveHappyCalls("abysslink-rig")...)
	p := newTestEnclave(t, r, tmp)
	dst := t.TempDir()

	enrolled, err := p.Enroll(context.Background(), EnrollRequest{Dir: dst, Label: "abysslink-rig"})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dst, "id_ecdsa_sk_rk1"), enrolled.PrivateHandle,
		"the labeled (just-created) handle must be installed, not the lexically first one")

	data, rErr := os.ReadFile(enrolled.PublicKeyPath)
	require.NoError(t, rErr)
	assert.Contains(t, string(data), "abysslink-rig", "the installed pub must be the just-created identity's")
	assert.NotContains(t, string(data), "some-other-tool", "the foreign identity must never be installed")
}

// TestEnclaveEnroll_MultipleHandlesAmbiguousRefuses: when several handles are
// downloaded and the label matches zero (comment format drifted — ASSUMED
// literal miss) or several of them, the enrollment refuses with
// ErrEnrollFailed and installs NOTHING — abysslink never guesses which
// credential it just minted.
func TestEnclaveEnroll_MultipleHandlesAmbiguousRefuses(t *testing.T) {
	cases := []struct {
		name string
		pubs [2]string
	}{
		{"zero_label_matches", [2]string{
			"sk-ecdsa-sha2-nistp256@openssh.com AAAAOld tool-a",
			"sk-ecdsa-sha2-nistp256@openssh.com AAAANew tool-b",
		}},
		{"multiple_label_matches", [2]string{
			"sk-ecdsa-sha2-nistp256@openssh.com AAAAOld abysslink-rig",
			"sk-ecdsa-sha2-nistp256@openssh.com AAAANew abysslink-rig",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			writeEnclaveHandle(t, tmp, "id_ecdsa_sk_rk", tc.pubs[0])
			writeEnclaveHandle(t, tmp, "id_ecdsa_sk_rk1", tc.pubs[1])

			r := shell.NewMockRunner(enclaveHappyCalls("abysslink-rig")...)
			p := newTestEnclave(t, r, tmp)
			dst := t.TempDir()

			_, err := p.Enroll(context.Background(), EnrollRequest{Dir: dst, Label: "abysslink-rig"})
			require.ErrorIs(t, err, ErrEnrollFailed)

			entries, dErr := os.ReadDir(dst)
			require.NoError(t, dErr)
			assert.Empty(t, entries, "an ambiguous download must install NOTHING")
		})
	}
}

func TestEnclaveEnroll_NonTTYRefused(t *testing.T) {
	r := shell.NewMockRunner()
	p := newTestEnclave(t, r, t.TempDir())
	p.isTTY = func() bool { return false }
	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "x"})
	require.ErrorIs(t, err, ErrNoTTY)
	assert.Empty(t, r.RecordedCalls())
}

func TestEnclaveEnroll_DylibMissingNotAvailable(t *testing.T) {
	r := shell.NewMockRunner()
	p := newTestEnclave(t, r, t.TempDir())
	p.dylibPath = filepath.Join(t.TempDir(), "absent.dylib")

	probe := p.Available(context.Background())
	assert.False(t, probe.OK)
	assert.Contains(t, probe.Reason, "too old")

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "x"})
	require.ErrorIs(t, err, ErrNotAvailable, "no fallback to Secretive or a software key")
	assert.Empty(t, r.RecordedCalls())
}

// noDirRunner wraps a Runner and deliberately hides the DirRunner capability.
type noDirRunner struct{ shell.Runner }

// TestEnclaveEnroll_NoDirRunnerRefused: a runner without working-directory
// support is refused rather than running `ssh-keygen -K` in an uncontrolled CWD.
func TestEnclaveEnroll_NoDirRunnerRefused(t *testing.T) {
	inner := shell.NewMockRunner(
		sshVOKCall(),
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{Stdout: "h l t\nA abysslink-rig p\n", ExitCode: 0}},
	)
	p := newTestEnclave(t, noDirRunner{inner}, t.TempDir())
	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "abysslink-rig"})
	require.ErrorIs(t, err, ErrNotAvailable)
}

func TestEnclaveEnroll_ScAuthFailureRefuses(t *testing.T) {
	r := shell.NewMockRunner(
		sshVOKCall(),
		shell.Call{Result: shell.Result{ExitCode: 1}}, // sc_auth create fails
	)
	p := newTestEnclave(t, r, t.TempDir())
	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "x"})
	require.ErrorIs(t, err, ErrEnrollFailed)
	assert.True(t, r.Done())
}

func TestEnclaveAvailable_ScAuthMissing(t *testing.T) {
	r := shell.NewMockRunner(sshVOKCall())
	p := newTestEnclave(t, r, t.TempDir())
	p.resolvePath = func(name string) (string, error) {
		if name == "sc_auth" {
			return "", errToolMissing
		}
		return "/usr/bin/" + name, nil
	}
	probe := p.Available(context.Background())
	assert.False(t, probe.OK)
}

// TestFactoryDarwin pins the factory: both kinds construct on darwin.
func TestFactoryDarwin(t *testing.T) {
	r := shell.NewMockRunner()
	enclave, err := NewProvider(KindSecureEnclave, r, Options{})
	require.NoError(t, err)
	assert.Equal(t, KindSecureEnclave, enclave.Kind())

	fido, err := NewProvider(KindFIDO2, r, Options{FIDO2ProviderPath: "/tmp/x.dylib"})
	require.NoError(t, err)
	assert.Equal(t, KindFIDO2, fido.Kind())
}
