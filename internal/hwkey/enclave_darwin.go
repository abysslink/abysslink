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

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/shell"
)

// SecureEnclaveProvider enrolls macOS Secure Enclave SSH keys (HWK-01).
//
// Model: Apple's /usr/lib/ssh-keychain.dylib is an OpenSSH sk-api provider
// (REAL-CONFIRMED exports). The SK interface is ECDSA P-256 only — enclave
// keys surface as sk-ecdsa-sha2-nistp256@openssh.com; ed25519-sk is
// impossible on the enclave. Creation happens via `sc_auth
// create-ctk-identity` (NOT `ssh-keygen -t ecdsa-sk -w`: Apple's module lacks
// sk_enroll key generation — ASSUMED, and this flow never attempts it), then
// `ssh-keygen -K` downloads a HANDLE into a fresh temp dir; the private key
// never leaves the enclave.
type SecureEnclaveProvider struct {
	runner shell.Runner
	// dylibPath is Apple's sk-api module (default enclaveDylibPath); a seam so
	// tests can point it at a fixture without touching /usr/lib.
	dylibPath string
	// ctkKeyType is the sc_auth -k value. Locked to the single-value allowlist
	// {"p-256-ne"}: Enroll refuses any other value pre-exec, making the
	// exportable "p-256" and the silently-failing "p-384-ne" unreachable.
	ctkKeyType string

	// Test seams (defaults set by newSecureEnclaveProvider; never nil).
	resolvePath func(string) (string, error)
	isTTY       func() bool
	mkTempDir   func() (string, error)
}

// newSecureEnclaveProvider constructs a SecureEnclaveProvider with production
// seam defaults.
func newSecureEnclaveProvider(runner shell.Runner) *SecureEnclaveProvider {
	return &SecureEnclaveProvider{
		runner:      runner,
		dylibPath:   enclaveDylibPath,
		ctkKeyType:  scAuthKeyTypeP256NE,
		resolvePath: shell.ResolvePath,
		isTTY:       stdinIsTTY,
		mkTempDir:   func() (string, error) { return os.MkdirTemp("", "abysslink-hwkey-*") },
	}
}

// Kind returns KindSecureEnclave.
func (p *SecureEnclaveProvider) Kind() Kind { return KindSecureEnclave }

// Available probes the enclave toolchain non-interactively: the sk-api dylib
// present, ssh/ssh-keygen same-directory and >= 10.0, and sc_auth resolvable.
// No `nm` pre-probe ships (needs CLT); the runtime "is not an OpenSSH FIDO
// library" stderr is the macOS-too-old signal at enroll time.
func (p *SecureEnclaveProvider) Available(ctx context.Context) Probe {
	probe, _ := p.checkAvailable(ctx)
	return probe
}

// checkAvailable is the shared availability logic, returning the Probe and
// the matching sentinel error for Enroll's pre-exec refusals.
func (p *SecureEnclaveProvider) checkAvailable(ctx context.Context) (Probe, error) {
	if _, err := os.Stat(p.dylibPath); err != nil {
		wErr := fmt.Errorf("%w: %s is absent — this macOS is too old for native enclave SSH keys (needs the OpenSSH sk-api keychain module)", ErrNotAvailable, p.dylibPath)
		return Probe{OK: false, Reason: wErr.Error()}, wErr
	}
	version, err := checkToolchain(ctx, p.runner, p.resolvePath)
	if err != nil {
		return Probe{OK: false, Reason: err.Error(), SSHVersion: version}, err
	}
	if _, err := p.resolvePath("sc_auth"); err != nil {
		wErr := fmt.Errorf("%w: sc_auth not found on PATH: %v", ErrNotAvailable, err)
		return Probe{OK: false, Reason: wErr.Error(), SSHVersion: version}, wErr
	}
	return Probe{OK: true, SSHVersion: version}, nil
}

// Enroll creates one Secure Enclave identity and downloads its SSH handle.
// INTERACTIVE (Touch ID GUI + `ssh-keygen -K` PIN/touch on the inherited
// TTY). Fail-closed refusal points, each covered by a test: non-TTY; key type
// not p-256-ne; unsupported key-type request; dylib missing; mixed toolchain;
// version floor; runner without shell.DirRunner; sc_auth non-zero; zero
// identities after create (exit-code lie); `-K` exit 0 with zero handle files
// ("No keys to download" lie); multiple downloaded handles that cannot be
// uniquely tied to the just-created label (pre-existing enclave identities —
// never install a foreign credential); produced pub token not sk-ecdsa (files
// deleted + ErrSoftwareKey). There is NO branch that generates a software key.
func (p *SecureEnclaveProvider) Enroll(ctx context.Context, req EnrollRequest) (*EnrolledKey, error) {
	if !p.isTTY() {
		return nil, fmt.Errorf("%w: enclave enrollment needs a live terminal for the Touch ID / PIN prompts", ErrNoTTY)
	}
	// -k single-value allowlist: only the non-exportable P-256 type may ever
	// reach a sc_auth argv (fail-closed hazard: "p-256" is EXPORTABLE).
	if p.ctkKeyType != scAuthKeyTypeP256NE {
		return nil, fmt.Errorf("%w: refusing sc_auth key type %q — only %q (non-exportable) is permitted", ErrSoftwareKey, p.ctkKeyType, scAuthKeyTypeP256NE)
	}
	// The enclave is P-256 only; an explicit ed25519-sk (or any other) request
	// cannot be honoured and must never degrade to a different key.
	if req.KeyType != "" && req.KeyType != keyTypeECDSASK {
		return nil, fmt.Errorf("%w: the Secure Enclave only mints ecdsa-sk (P-256); requested %q", ErrSoftwareKey, req.KeyType)
	}
	if _, err := p.checkAvailable(ctx); err != nil {
		return nil, err
	}
	dr, ok := p.runner.(shell.DirRunner)
	if !ok {
		// `ssh-keygen -K` writes handles to CWD only; refuse rather than run
		// it in an uncontrolled working directory.
		return nil, fmt.Errorf("%w: runner lacks working-directory support (shell.DirRunner) required for ssh-keygen -K", ErrNotAvailable)
	}

	argvs := EnclaveEnrollArgvs(req.Label, p.dylibPath)
	// (1) Create the enclave identity (Touch ID GUI may fire; success is
	// silent + exit 0 — ASSUMED, so step 2 post-verifies it).
	if err := p.runner.RunInteractive(ctx, argvs[0][0], argvs[0][1:]...); err != nil {
		return nil, fmt.Errorf("%w: sc_auth create-ctk-identity failed: %v", ErrEnrollFailed, err)
	}
	// (2) Post-verify the identity exists — exit 0 with a header-only listing
	// means ZERO identities (REAL-CONFIRMED exit-code lie).
	if err := p.verifyIdentityListed(ctx, req.Label); err != nil {
		return nil, err
	}
	// (3) Download the handle in a FRESH temp dir (kills the "Overwrite
	// (y/n)?" blocker); PIN + touch handled by OpenSSH on the inherited TTY.
	tmpDir, err := p.mkTempDir()
	if err != nil {
		return nil, fmt.Errorf("hwkey: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	kArgv := argvs[2]
	if err := dr.RunInteractiveDir(ctx, tmpDir, kArgv[0], kArgv[1:]...); err != nil {
		return nil, fmt.Errorf("%w: ssh-keygen -K failed: %v", ErrEnrollFailed, err)
	}
	// (4) Exit 0 is NOT success: `-K` exits 0 with "No keys to download" when
	// zero resident keys exist. Require >= 1 handle file actually produced —
	// and when the download contains handles for MORE THAN ONE resident key
	// (a Mac with pre-existing enclave identities), select the just-created
	// one by label or refuse: never install a foreign credential.
	handle, err := findEnclaveHandle(tmpDir, req.Label)
	if err != nil {
		return nil, err
	}
	// (5)+(6) Shared post-verify (pub token must be exactly sk-ecdsa, else
	// delete + ErrSoftwareKey) and audited move into req.Dir.
	return finishEnroll(KindSecureEnclave, handle, tokenSKECDSA, req.Dir)
}

// Verify classifies the public key at pubPath fail-closed (shared rule).
func (p *SecureEnclaveProvider) Verify(ctx context.Context, pubPath string) (KeyInfo, error) {
	return verifyPubKey(ctx, p.runner, pubPath)
}

// verifyIdentityListed asserts `sc_auth list-ctk-identities -t ssh` reports at
// least one non-header row containing label. The row shape is ASSUMED, so the
// parse is defensive: line 1 is treated as the header; zero remaining rows, or
// none containing the label, is ErrEnrollFailed — create is never assumed.
func (p *SecureEnclaveProvider) verifyIdentityListed(ctx context.Context, label string) error {
	res, err := p.runner.Run(ctx, "sc_auth", "list-ctk-identities", "-t", "ssh")
	if err != nil || !res.Ok() {
		return fmt.Errorf("%w: sc_auth list-ctk-identities failed", ErrEnrollFailed)
	}
	lines := make([]string, 0, 4)
	for _, ln := range strings.Split(res.Stdout, "\n") {
		if strings.TrimSpace(ln) != "" {
			lines = append(lines, ln)
		}
	}
	if len(lines) <= 1 {
		// Header-only (or empty) with exit 0: ZERO identities exist.
		return fmt.Errorf("%w: sc_auth reports no CTK identities after create (exit code 0 lies here)", ErrEnrollFailed)
	}
	for _, row := range lines[1:] {
		if strings.Contains(row, label) {
			return nil
		}
	}
	return fmt.Errorf("%w: created identity %q not present in sc_auth list-ctk-identities output", ErrEnrollFailed, label)
}

// findEnclaveHandle returns the id_ecdsa_sk_rk* HANDLE file (not .pub) that
// `ssh-keygen -K` produced in dir for the identity just created under label.
// Fail-closed on every miss:
//
//   - ZERO handles: ErrEnrollFailed — neutralizes the exit-0 "No keys to
//     download" lie.
//   - EXACTLY ONE handle: that handle (the fresh temp dir guarantees it was
//     produced by this run).
//   - MULTIPLE handles: `-K` downloads a handle for EVERY resident key the
//     sk-api provider reports, not just the identity created in step 1, so a
//     Mac with pre-existing enclave SSH identities yields several files and
//     lexical glob order would pick an arbitrary — possibly foreign — key.
//     Disambiguate by the label in each handle's .pub line (ASSUMED to carry
//     it — an ASSUMED miss can only refuse, never mis-select): exactly one
//     match wins; zero or several matches is ErrEnrollFailed. abysslink never
//     guesses which credential it just minted.
func findEnclaveHandle(dir, label string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, enclaveHandlePrefix+"*"))
	if err != nil {
		return "", fmt.Errorf("%w: scanning for downloaded handles: %v", ErrEnrollFailed, err)
	}
	handles := make([]string, 0, len(matches))
	for _, m := range matches {
		if !strings.HasSuffix(m, ".pub") {
			handles = append(handles, m)
		}
	}
	switch len(handles) {
	case 0:
		return "", fmt.Errorf("%w: ssh-keygen -K exited 0 but downloaded zero resident-key handles (no enclave key exists)", ErrEnrollFailed)
	case 1:
		return handles[0], nil
	}
	var labelled []string
	for _, h := range handles {
		data, rErr := os.ReadFile(h + ".pub") //nolint:gosec // G304: path is inside the temp dir this package just created
		if rErr != nil {
			continue // unreadable .pub cannot corroborate the label — skip, never select
		}
		if label != "" && strings.Contains(FirstNonEmptyLine(string(data)), label) {
			labelled = append(labelled, h)
		}
	}
	if len(labelled) == 1 {
		return labelled[0], nil
	}
	return "", fmt.Errorf("%w: ssh-keygen -K downloaded %d resident-key handles but the just-created identity %q could not be uniquely identified (%d label matches) — pre-existing enclave keys present; refusing to install a credential that may not be the one just enrolled", ErrEnrollFailed, len(handles), label, len(labelled))
}
