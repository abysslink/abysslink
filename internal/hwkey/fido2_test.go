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

// fido2_test.go — the FIDO2 enrollment battery. Every external interaction is
// a scripted shell.MockRunner Call: no test here (or anywhere) touches a live
// authenticator, keychain, or ssh-keygen -w.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sshVOKCall is the scripted `ssh -V` toolchain probe reply (>= 10.0 floor).
func sshVOKCall() shell.Call {
	return shell.Call{Result: shell.Result{Stderr: "OpenSSH_10.2p1, LibreSSL 3.3.6\n", ExitCode: 0}}
}

// newTestFIDO2 builds a FIDO2Provider with deterministic seams: same-dir
// toolchain paths, a live TTY, and a caller-controlled temp dir (so fixtures
// can be pre-planted where the mocked ssh-keygen "wrote" them).
func newTestFIDO2(r shell.Runner, opts Options, needsPath bool, tmp string) *FIDO2Provider {
	p := newFIDO2Provider(r, opts, needsPath)
	p.resolvePath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	p.isTTY = func() bool { return true }
	p.mkTempDir = func() (string, error) { return tmp, nil }
	return p
}

// plantKeyFixture simulates the files ssh-keygen would have produced.
func plantKeyFixture(t *testing.T, dir, pubLine string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, HandleBaseName), []byte("handle-bytes"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, HandleBaseName+".pub"), []byte(pubLine+"\n"), 0o644))
}

func TestFIDO2Enroll_TypeAllowlistRefusesSoftware(t *testing.T) {
	r := shell.NewMockRunner() // ZERO scripted calls: any Runner call fails the test
	p := newTestFIDO2(r, Options{}, false, t.TempDir())

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l", KeyType: "ed25519"})
	require.ErrorIs(t, err, ErrSoftwareKey, "a software key type must be refused pre-exec")
	assert.Empty(t, r.RecordedCalls(), "refusal must happen with ZERO Runner calls")
	assert.True(t, r.Done())

	_, err = p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l", KeyType: "rsa"})
	require.ErrorIs(t, err, ErrSoftwareKey)
	assert.Empty(t, r.RecordedCalls())
}

func TestFIDO2Enroll_ArgvExact(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir()) // audit log for the audited move

	t.Run("base_linux_no_provider", func(t *testing.T) {
		tmp := t.TempDir()
		plantKeyFixture(t, tmp, "sk-ssh-ed25519@openssh.com AAAAGnNr lbl")
		r := shell.NewMockRunner(
			sshVOKCall(),
			shell.Call{Result: shell.Result{ExitCode: 0}}, // interactive ssh-keygen
		)
		p := newTestFIDO2(r, Options{}, false, tmp)
		dst := t.TempDir()

		enrolled, err := p.Enroll(context.Background(), EnrollRequest{
			Dir: dst, Label: "lbl", KeyType: "ed25519-sk", Application: "ssh:abysslink",
		})
		require.NoError(t, err)
		require.True(t, r.Done(), "every scripted call must be consumed")

		ic := r.RunInteractiveCalls()
		require.Len(t, ic, 1)
		assert.Equal(t, []string{
			"ssh-keygen",
			"-t", "ed25519-sk",
			"-O", "verify-required",
			"-O", "application=ssh:abysslink",
			"-f", filepath.Join(tmp, HandleBaseName),
			"-N", "",
			"-C", "lbl",
		}, ic[0], "each -O is its own pair; -N is the empty string; no -w without a provider path")

		assert.Equal(t, filepath.Join(dst, HandleBaseName), enrolled.PrivateHandle)
		assert.FileExists(t, enrolled.PrivateHandle)
		assert.FileExists(t, enrolled.PublicKeyPath)
		assert.True(t, enrolled.Info.Hardware)
		assert.Equal(t, KindFIDO2, enrolled.Kind)
	})

	t.Run("resident_plus_darwin_provider_path", func(t *testing.T) {
		tmp := t.TempDir()
		plantKeyFixture(t, tmp, "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr lbl")
		providerDylib := filepath.Join(t.TempDir(), "libsk-libfido2.dylib")
		require.NoError(t, os.WriteFile(providerDylib, []byte("dylib"), 0o644))
		r := shell.NewMockRunner(
			sshVOKCall(),
			shell.Call{Result: shell.Result{ExitCode: 0}},
		)
		p := newTestFIDO2(r, Options{FIDO2ProviderPath: providerDylib}, true, tmp)

		_, err := p.Enroll(context.Background(), EnrollRequest{
			Dir: t.TempDir(), Label: "lbl", KeyType: "ecdsa-sk",
			Application: "ssh:abysslink", User: "alice", Resident: true,
		})
		require.NoError(t, err)
		ic := r.RunInteractiveCalls()
		require.Len(t, ic, 1)
		assert.Equal(t, []string{
			"ssh-keygen",
			"-t", "ecdsa-sk",
			"-O", "verify-required",
			"-O", "application=ssh:abysslink",
			"-f", filepath.Join(tmp, HandleBaseName),
			"-N", "",
			"-C", "lbl",
			"-O", "resident",
			"-O", "user=alice",
			"-w", providerDylib,
		}, ic[0])
	})
}

// TestFIDO2Enroll_RefusesSoftwareKeyOutput is the load-bearing gate: keygen
// "succeeds" (exit 0) but the produced pub is a SOFTWARE key — the files must
// be deleted and ErrSoftwareKey returned. Never a silent software key.
func TestFIDO2Enroll_RefusesSoftwareKeyOutput(t *testing.T) {
	tmp := t.TempDir()
	plantKeyFixture(t, tmp, "ssh-ed25519 AAAAC3Nza lbl") // NOT sk-backed
	r := shell.NewMockRunner(
		sshVOKCall(),
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	p := newTestFIDO2(r, Options{}, false, tmp)
	dst := t.TempDir()

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: dst, Label: "lbl"})
	require.ErrorIs(t, err, ErrSoftwareKey)
	assert.NoFileExists(t, filepath.Join(tmp, HandleBaseName), "produced handle must be deleted")
	assert.NoFileExists(t, filepath.Join(tmp, HandleBaseName+".pub"), "produced pub must be deleted")
	assert.NoFileExists(t, filepath.Join(dst, HandleBaseName), "nothing may be installed")
}

// TestFIDO2Enroll_WrongTokenForKeyType: exit 0 and an sk pub, but not the
// token the requested key type must produce — still refused (consistency).
func TestFIDO2Enroll_WrongTokenForKeyType(t *testing.T) {
	tmp := t.TempDir()
	plantKeyFixture(t, tmp, "sk-ecdsa-sha2-nistp256@openssh.com AAAA lbl") // ecdsa, but ed25519-sk requested
	r := shell.NewMockRunner(sshVOKCall(), shell.Call{Result: shell.Result{ExitCode: 0}})
	p := newTestFIDO2(r, Options{}, false, tmp)

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "lbl", KeyType: "ed25519-sk"})
	require.ErrorIs(t, err, ErrSoftwareKey)
}

// TestFIDO2Enroll_MissingPubRefuses: exit 0 but zero files produced.
func TestFIDO2Enroll_MissingPubRefuses(t *testing.T) {
	tmp := t.TempDir() // deliberately empty — keygen "succeeded" but wrote nothing
	r := shell.NewMockRunner(sshVOKCall(), shell.Call{Result: shell.Result{ExitCode: 0}})
	p := newTestFIDO2(r, Options{}, false, tmp)

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "lbl"})
	require.ErrorIs(t, err, ErrSoftwareKey)
}

func TestFIDO2Enroll_ApplicationPrefixEnforced(t *testing.T) {
	r := shell.NewMockRunner() // zero calls: refusal is pre-exec
	p := newTestFIDO2(r, Options{}, false, t.TempDir())

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l", Application: "web:evil"})
	require.ErrorIs(t, err, ErrEnrollFailed)
	assert.Empty(t, r.RecordedCalls())
}

func TestFIDO2Enroll_NonTTYRefused(t *testing.T) {
	r := shell.NewMockRunner()
	p := newTestFIDO2(r, Options{}, false, t.TempDir())
	p.isTTY = func() bool { return false }

	_, err := p.Enroll(context.Background(), EnrollRequest{Dir: t.TempDir(), Label: "l"})
	require.ErrorIs(t, err, ErrNoTTY, "interactive flows never run unattended")
	assert.Empty(t, r.RecordedCalls())
}

func TestFIDO2Verify_FailClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("verified_sk", func(t *testing.T) {
		dir := t.TempDir()
		pub := filepath.Join(dir, "k.pub")
		require.NoError(t, os.WriteFile(pub, []byte("sk-ssh-ed25519@openssh.com AAAA me@rig\n"), 0o644))
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{
			Stdout: "256 SHA256:abcdefg me@rig (ED25519-SK)\n", ExitCode: 0,
		}})
		p := newTestFIDO2(r, Options{}, false, dir)
		info, err := p.Verify(ctx, pub)
		require.NoError(t, err)
		assert.True(t, info.Hardware)
		assert.Equal(t, "SHA256:abcdefg", info.Fingerprint)
	})

	t.Run("software_pub_is_error", func(t *testing.T) {
		dir := t.TempDir()
		pub := filepath.Join(dir, "k.pub")
		require.NoError(t, os.WriteFile(pub, []byte("ssh-ed25519 AAAA me@rig\n"), 0o644))
		p := newTestFIDO2(shell.NewMockRunner(), Options{}, false, dir)
		_, err := p.Verify(ctx, pub)
		require.ErrorIs(t, err, ErrSoftwareKey)
	})

	t.Run("keygen_l_disagrees_is_error", func(t *testing.T) {
		dir := t.TempDir()
		pub := filepath.Join(dir, "k.pub")
		require.NoError(t, os.WriteFile(pub, []byte("sk-ssh-ed25519@openssh.com AAAA me@rig\n"), 0o644))
		r := shell.NewMockRunner(shell.Call{Result: shell.Result{
			Stdout: "256 SHA256:abcdefg me@rig (ED25519)\n", ExitCode: 0, // NOT -SK
		}})
		p := newTestFIDO2(r, Options{}, false, dir)
		_, err := p.Verify(ctx, pub)
		require.Error(t, err, "pub says sk but -l says software: refuse, never Hardware=true")
	})

	t.Run("garbage_pub_is_error_never_hardware", func(t *testing.T) {
		dir := t.TempDir()
		pub := filepath.Join(dir, "k.pub")
		require.NoError(t, os.WriteFile(pub, []byte("total garbage\n"), 0o644))
		p := newTestFIDO2(shell.NewMockRunner(), Options{}, false, dir)
		info, err := p.Verify(ctx, pub)
		require.ErrorIs(t, err, ErrParse)
		assert.False(t, info.Hardware)
	})

	t.Run("missing_pub_is_error", func(t *testing.T) {
		p := newTestFIDO2(shell.NewMockRunner(), Options{}, false, t.TempDir())
		_, err := p.Verify(ctx, filepath.Join(t.TempDir(), "absent.pub"))
		require.Error(t, err)
	})
}
