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

import (
	"context"
	"errors"
)

// Kind names a hardware key provider class.
type Kind string

// Provider kinds. These strings double as the config-level
// hardware_keys.provider enum values (internal/config ValidateHardwareKeys).
const (
	// KindSecureEnclave is the macOS SEP path: sc_auth create-ctk-identity +
	// ssh-keygen -K -w /usr/lib/ssh-keychain.dylib handle download.
	KindSecureEnclave Kind = "secure-enclave"
	// KindFIDO2 is the external-authenticator path: ssh-keygen -t ed25519-sk
	// (or ecdsa-sk for old firmware) with -O verify-required.
	KindFIDO2 Kind = "fido2"
)

// Sentinel errors, matched with errors.Is (mirrors secrets.ErrNotFound).
var (
	// ErrNotAvailable means the provider cannot run on this system (tool
	// missing, mixed toolchain, dylib absent, no provider middleware, runner
	// without DirRunner). Never worked around with an alternate tool.
	ErrNotAvailable = errors.New("hwkey: provider not available on this system")
	// ErrNoTTY means enrollment was attempted without an interactive terminal.
	// Interactive touch/PIN flows never run unattended (no hang, no
	// stdin-consumption chaos).
	ErrNoTTY = errors.New("hwkey: enrollment requires an interactive terminal")
	// ErrSoftwareKey means the requested or produced key is not verifiably
	// hardware-backed (sk-*). The produced files, if any, have been deleted.
	// This is the load-bearing fail-closed gate: abysslink never silently
	// mints or accepts a software key where a hardware key was requested.
	ErrSoftwareKey = errors.New("hwkey: produced key is not hardware-backed (sk-*); refusing")
	// ErrEnrollFailed means the enrollment tooling failed (device not found,
	// wrong PIN, sc_auth non-zero, zero files downloaded). NEVER mapped to a
	// software-key retry.
	ErrEnrollFailed = errors.New("hwkey: enrollment failed")
	// ErrUnsupportedOS is returned by the stub factory on unsupported GOOS.
	ErrUnsupportedOS = errors.New("hwkey: hardware keys unsupported on this OS")
	// ErrVersionFloor means the installed OpenSSH is below the 10.0 floor
	// (HWK-02). Refused before any keygen exec.
	ErrVersionFloor = errors.New("hwkey: OpenSSH below required 10.0 floor")
	// ErrParse means tool output could not be recognized. Failing closed:
	// an unparseable `ssh -V` is never assumed modern, and an unparseable
	// public key is never classified hardware OR software.
	ErrParse = errors.New("hwkey: unrecognized tool output (failing closed)")
)

// Probe is a NON-INTERACTIVE availability report, safe to run from status and
// doctor (LookPath, `ssh -V`, stat — never a touch/PIN prompt).
type Probe struct {
	OK         bool
	Reason     string // remediation hint when !OK
	SSHVersion string // parsed "major.minor" for diagnostics (may be empty)
}

// EnrollRequest describes one enrollment. It carries NO secrets: PINs and
// passphrases are typed by the operator on the inherited TTY and read by
// OpenSSH itself — abysslink never sees, stores, or passes them.
type EnrollRequest struct {
	Dir         string // destination directory for handle files
	Label       string // sc_auth -l label / ssh-keygen -C comment
	KeyType     string // "ed25519-sk" (default) | "ecdsa-sk"; allowlist-enforced
	Application string // FIDO2 -O application=...; must begin "ssh:"
	User        string // FIDO2 -O user=... (resident keys)
	Resident    bool   // FIDO2 -O resident
}

// KeyInfo is the fail-closed classification of an on-disk public key.
type KeyInfo struct {
	TypeToken   string // e.g. "sk-ssh-ed25519@openssh.com" or "-l" shortname
	Hardware    bool   // true ONLY on a verified sk-* prefix / "-SK" -l shortname
	Fingerprint string // "SHA256:..." from ssh-keygen -l (empty on pub-only parse)
	Comment     string
}

// EnrolledKey describes a successful enrollment.
type EnrolledKey struct {
	Kind          Kind
	PrivateHandle string // path to the handle file (NOT secret material for sk keys)
	PublicKeyPath string
	Info          KeyInfo
}

// Provider creates and verifies hardware-backed SSH keys. It sits beside
// secrets.KeychainStore: same interface + per-OS factory + mock shape.
type Provider interface {
	Kind() Kind
	// Available probes binaries/dylibs/version floor. Never interactive.
	Available(ctx context.Context) Probe
	// Enroll is INTERACTIVE (touch/PIN via inherited TTY). Fail-closed: it
	// post-verifies the produced public key is sk-backed; on any miss it
	// deletes the produced files and returns ErrSoftwareKey. It NEVER falls
	// back to generating a software key.
	Enroll(ctx context.Context, req EnrollRequest) (*EnrolledKey, error)
	// Verify classifies pubPath. Parse miss => error, never Hardware=true.
	Verify(ctx context.Context, pubPath string) (KeyInfo, error)
}

// Options carries provider construction options.
type Options struct {
	// FIDO2ProviderPath is the sk-api middleware dylib for external tokens on
	// macOS (stock Apple ssh-keygen has no USB HID middleware — REAL-CONFIRMED
	// "No FIDO SecurityKeyProvider specified"). Empty on Linux, where the
	// distro OpenSSH ships an internal provider.
	FIDO2ProviderPath string
}

// EnclaveDylibPath is Apple's OpenSSH sk-api keychain module. Every ssh
// connection that uses an enclave key needs -o SecurityKeyProvider pointing
// here — the explicit flag, never the SSH_SK_PROVIDER env var (ASSUMED:
// Homebrew ssh ignores the env var).
const EnclaveDylibPath = enclaveDylibPath

// EnclaveEnrollArgvs returns the exact command argvs the Secure Enclave
// enrollment runs, in order. It is the single argv source shared by the darwin
// provider and the CLI dry-run preview, so the preview can never drift from
// what --apply executes. Untagged so the preview renders on every GOOS.
// dylibPath is Apple's sk-api module (EnclaveDylibPath in production; the
// provider's seam value in tests).
func EnclaveEnrollArgvs(label, dylibPath string) [][]string {
	return [][]string{
		{"sc_auth", "create-ctk-identity", "-l", label, "-k", scAuthKeyTypeP256NE, "-t", scAuthProtectionBio},
		{"sc_auth", "list-ctk-identities", "-t", "ssh"},
		{"ssh-keygen", "-K", "-w", dylibPath, "-N", ""},
	}
}

// FIDO2EnrollArgv returns the exact ssh-keygen argv the FIDO2 enrollment runs.
// Single argv source shared by Enroll and the CLI dry-run preview (each -O is
// its own flag pair; the argv is exec'd directly — never sh -c). providerPath
// appends -w when non-empty (macOS external-token middleware).
func FIDO2EnrollArgv(req EnrollRequest, keyPath, providerPath string) []string {
	argv := []string{
		"ssh-keygen",
		"-t", req.KeyType,
		"-O", "verify-required",
		"-O", "application=" + req.Application,
		"-f", keyPath,
		"-N", "",
		"-C", req.Label,
	}
	if req.Resident {
		argv = append(argv, "-O", "resident", "-O", "user="+req.User)
	}
	if providerPath != "" {
		argv = append(argv, "-w", providerPath)
	}
	return argv
}
