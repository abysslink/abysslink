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

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/shell"
)

// HandleBaseName is the on-disk base name for FIDO2 key handle files created
// by this package (matches the config resolver default ~/.ssh/abysslink_id_sk).
const HandleBaseName = "abysslink_id_sk"

// DefaultApplication is the default FIDO2 -O application value. It must begin
// "ssh:" (OpenSSH fatals otherwise; the config layer enforces the same prefix).
const DefaultApplication = "ssh:abysslink"

// FIDO2Provider enrolls external FIDO2 authenticator keys via
// `ssh-keygen -t ed25519-sk` (HWK-02). Untagged: the factories construct it on
// darwin (with a mandatory provider middleware path) and linux (internal
// provider). All external commands go through shell.Runner.
type FIDO2Provider struct {
	runner shell.Runner
	opts   Options
	// needsProviderPath is true on darwin: stock Apple ssh-keygen has no USB
	// HID middleware (REAL-CONFIRMED "No FIDO SecurityKeyProvider specified"),
	// so Options.FIDO2ProviderPath is mandatory there.
	needsProviderPath bool

	// Test seams (defaults set by newFIDO2Provider; never nil).
	resolvePath func(string) (string, error)
	isTTY       func() bool
	mkTempDir   func() (string, error)
}

// newFIDO2Provider constructs a FIDO2Provider with production seam defaults.
func newFIDO2Provider(runner shell.Runner, opts Options, needsProviderPath bool) *FIDO2Provider {
	return &FIDO2Provider{
		runner:            runner,
		opts:              opts,
		needsProviderPath: needsProviderPath,
		resolvePath:       shell.ResolvePath,
		isTTY:             stdinIsTTY,
		mkTempDir:         func() (string, error) { return os.MkdirTemp("", "abysslink-hwkey-*") },
	}
}

// Kind returns KindFIDO2.
func (p *FIDO2Provider) Kind() Kind { return KindFIDO2 }

// Available probes the FIDO2 toolchain non-interactively: ssh/ssh-keygen
// present and from the SAME directory, `ssh -V` >= 10.0 (numeric tuple), and —
// on darwin — a stat-able sk-api provider middleware path.
func (p *FIDO2Provider) Available(ctx context.Context) Probe {
	probe, _ := p.checkAvailable(ctx)
	return probe
}

// checkAvailable is the shared availability logic. It returns both the Probe
// (for Available) and the matching sentinel error (for Enroll's pre-exec
// refusals): ErrNotAvailable / ErrVersionFloor / ErrParse.
func (p *FIDO2Provider) checkAvailable(ctx context.Context) (Probe, error) {
	version, err := checkToolchain(ctx, p.runner, p.resolvePath)
	if err != nil {
		return Probe{OK: false, Reason: err.Error(), SSHVersion: version}, err
	}
	if p.needsProviderPath {
		if p.opts.FIDO2ProviderPath == "" {
			err := fmt.Errorf("%w: no FIDO2 provider middleware configured — set hardware_keys.fido2_provider_path (Homebrew openssh or a built libsk-libfido2.dylib); stock Apple ssh-keygen has no USB HID middleware", ErrNotAvailable)
			return Probe{OK: false, Reason: err.Error(), SSHVersion: version}, err
		}
		if _, sErr := os.Stat(p.opts.FIDO2ProviderPath); sErr != nil {
			err := fmt.Errorf("%w: FIDO2 provider middleware %q not found: %v", ErrNotAvailable, p.opts.FIDO2ProviderPath, sErr)
			return Probe{OK: false, Reason: err.Error(), SSHVersion: version}, err
		}
	}
	return Probe{OK: true, SSHVersion: version}, nil
}

// Enroll creates one FIDO2 sk key. INTERACTIVE: the authenticator touch and
// any PIN prompt go straight to the operator's TTY via RunInteractive —
// abysslink never reads the PIN. Fail-closed refusal points, in order:
// non-TTY; key type outside the {ed25519-sk, ecdsa-sk} allowlist (ZERO Runner
// calls — a config typo must never silently mint a software key); application
// not "ssh:"-prefixed; toolchain unavailable/below-floor. A keygen failure is
// ErrEnrollFailed and is NEVER retried with a different -t or without -w. An
// exit-0 run whose produced .pub is not the expected sk token has its files
// DELETED and returns ErrSoftwareKey.
func (p *FIDO2Provider) Enroll(ctx context.Context, req EnrollRequest) (*EnrolledKey, error) {
	if !p.isTTY() {
		return nil, fmt.Errorf("%w: FIDO2 enrollment needs a live terminal for the touch/PIN prompts", ErrNoTTY)
	}
	if req.KeyType == "" {
		req.KeyType = keyTypeEd25519SK
	}
	if req.KeyType != keyTypeEd25519SK && req.KeyType != keyTypeECDSASK {
		return nil, fmt.Errorf("%w: key type %q is not a hardware (sk) type; allowed: %s, %s",
			ErrSoftwareKey, req.KeyType, keyTypeEd25519SK, keyTypeECDSASK)
	}
	if req.Application == "" {
		req.Application = DefaultApplication
	}
	if !strings.HasPrefix(req.Application, "ssh:") {
		return nil, fmt.Errorf("%w: application %q must begin with \"ssh:\"", ErrEnrollFailed, req.Application)
	}
	if _, err := p.checkAvailable(ctx); err != nil {
		return nil, err
	}

	tmpDir, err := p.mkTempDir()
	if err != nil {
		return nil, fmt.Errorf("hwkey: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	keyPath := filepath.Join(tmpDir, HandleBaseName)
	argv := FIDO2EnrollArgv(req, keyPath, p.opts.FIDO2ProviderPath)
	if runErr := p.runner.RunInteractive(ctx, argv[0], argv[1:]...); runErr != nil {
		// Exit 255 covers every ssh-keygen enrollment failure (device not
		// found, PIN x3, "Key enrollment failed: ..."). The operator saw the
		// reason on their own terminal; we refuse and never retry.
		return nil, fmt.Errorf("%w: ssh-keygen reported an enrollment failure (see its output above): %v", ErrEnrollFailed, runErr)
	}

	return finishEnroll(KindFIDO2, keyPath, expectedTokenFor(req.KeyType), req.Dir)
}

// Verify classifies the public key at pubPath fail-closed (shared rule: pub
// first-token sk- AND ssh-keygen -l shortname ending -SK; either miss is an
// error, never Hardware=true).
func (p *FIDO2Provider) Verify(ctx context.Context, pubPath string) (KeyInfo, error) {
	return verifyPubKey(ctx, p.runner, pubPath)
}

// expectedTokenFor maps an allowlisted sk key type to the exact .pub type
// token a successful enrollment must have produced.
func expectedTokenFor(keyType string) string {
	if keyType == keyTypeECDSASK {
		return tokenSKECDSA
	}
	return tokenSKEd25519
}

// ---------------------------------------------------------------------------
// Shared helpers (used by both FIDO2Provider and SecureEnclaveProvider)
// ---------------------------------------------------------------------------

// stdinIsTTY reports whether stdin is a character device. Defense-in-depth
// re-check behind the CLI's interactive() gate; stdlib-only on purpose.
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// checkToolchain performs the shared non-interactive toolchain probe:
// ssh + ssh-keygen resolvable AND from the same directory (a mixed
// Apple/Homebrew toolchain is refused — no "probably fine" path), and
// `ssh -V` parsed to a numeric tuple meeting the >= 10.0 floor. It returns
// the parsed "major.minor" (when available) and the sentinel-wrapped error.
func checkToolchain(ctx context.Context, runner shell.Runner, resolvePath func(string) (string, error)) (string, error) {
	sshPath, err := resolvePath("ssh")
	if err != nil {
		return "", fmt.Errorf("%w: ssh not found on PATH: %v", ErrNotAvailable, err)
	}
	keygenPath, err := resolvePath("ssh-keygen")
	if err != nil {
		return "", fmt.Errorf("%w: ssh-keygen not found on PATH: %v", ErrNotAvailable, err)
	}
	if filepath.Dir(sshPath) != filepath.Dir(keygenPath) {
		return "", fmt.Errorf("%w: mixed ssh toolchain: ssh is %s but ssh-keygen is %s — install one complete OpenSSH and put it first on PATH",
			ErrNotAvailable, sshPath, keygenPath)
	}

	res, runErr := runner.Run(ctx, "ssh", "-V")
	if runErr != nil {
		return "", fmt.Errorf("%w: cannot run ssh -V: %v", ErrNotAvailable, runErr)
	}
	if !res.Ok() {
		return "", fmt.Errorf("%w: ssh -V exited %d", ErrParse, res.ExitCode)
	}
	// `ssh -V` prints the version to STDERR (stdout is empty — REAL-CONFIRMED).
	major, minor, pErr := ParseSSHVersion(firstLine(res.Stderr))
	if pErr != nil {
		return "", pErr
	}
	version := fmt.Sprintf("%d.%d", major, minor)
	if !MeetsFloor(major, minor) {
		return version, fmt.Errorf("%w: OpenSSH %s < %d.%d", ErrVersionFloor, version, FloorMajor, FloorMinor)
	}
	return version, nil
}

// firstLine returns the first line of s (without the trailing newline).
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimRight(s[:i], "\r")
	}
	return s
}

// FirstNonEmptyLine returns the first non-blank line of s, or "". Exported so
// every consumer that classifies a .pub file (the providers' verifyPubKey AND
// the CLI's hwkeyKindFor) parses the SAME line: classifying the literal first
// line instead would let a leading blank line dodge the software-key FATAL
// (HWK-03 silent-downgrade detector) by degrading it to an "unverifiable"
// WARN (adversarial finding P37-03).
func FirstNonEmptyLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			return strings.TrimRight(ln, "\r")
		}
	}
	return ""
}

// finishEnroll is the shared fail-closed post-verify + move step. keyPath is
// the just-produced handle in the fresh temp dir; expectedToken is the exact
// sk type token the .pub MUST carry. Any miss (missing .pub, parse error,
// wrong or non-sk token) deletes the produced files and returns
// ErrSoftwareKey — exit 0 alone is never success. On success the handle and
// .pub are moved into dstDir through internal/audit (backup + audit entry;
// the file-mutation hard rule), handle mode 0600.
func finishEnroll(kind Kind, keyPath, expectedToken, dstDir string) (*EnrolledKey, error) {
	pubPath := keyPath + ".pub"
	data, err := os.ReadFile(pubPath) //nolint:gosec // G304: path is inside the temp dir this package just created
	if err != nil {
		removeProduced(keyPath, pubPath)
		return nil, fmt.Errorf("%w: enrollment produced no public key at %s: %v", ErrSoftwareKey, pubPath, err)
	}
	info, cErr := ClassifyPublicKeyLine(FirstNonEmptyLine(string(data)))
	if cErr != nil || !info.Hardware || info.TypeToken != expectedToken {
		removeProduced(keyPath, pubPath)
		got := "unparseable"
		if cErr == nil {
			got = info.TypeToken
		}
		return nil, fmt.Errorf("%w: produced public key type is %q, require exactly %q — files deleted", ErrSoftwareKey, got, expectedToken)
	}

	dstPriv := filepath.Join(dstDir, filepath.Base(keyPath))
	dstPub := dstPriv + ".pub"
	if err := moveViaAudit(keyPath, dstPriv, 0o600); err != nil {
		return nil, err
	}
	if err := moveViaAudit(pubPath, dstPub, 0o644); err != nil {
		return nil, err
	}
	return &EnrolledKey{Kind: kind, PrivateHandle: dstPriv, PublicKeyPath: dstPub, Info: info}, nil
}

// removeProduced best-effort deletes enrollment output files (the fail-closed
// delete on a non-sk post-verify).
func removeProduced(paths ...string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

// moveViaAudit moves src to dst through internal/audit (every file mutation is
// backed up and audit-logged — CLAUDE.md hard rule). The audit entry records
// path + content hash only; for sk keys the "private" file is a handle, not
// secret material, but the hash-only rule is kept anyway.
func moveViaAudit(src, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src) //nolint:gosec // G304: src is inside the temp dir this package just created
	if err != nil {
		return fmt.Errorf("hwkey: read produced key file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("hwkey: create destination dir: %w", err)
	}
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("hwkey: audit log path: %w", err)
	}
	if err := audit.New(logPath).WriteFile(dst, data, perm, false); err != nil {
		return fmt.Errorf("hwkey: install key file: %w", err)
	}
	return os.Remove(src)
}

// verifyPubKey is the shared fail-closed Verify: the pub file's first token
// must be an allowlisted sk-* token AND `ssh-keygen -l` must report an
// -SK-suffixed shortname. Either miss is an error — never Hardware=true.
func verifyPubKey(ctx context.Context, runner shell.Runner, pubPath string) (KeyInfo, error) {
	data, err := os.ReadFile(pubPath) //nolint:gosec // G304: pubPath is the operator-configured key path, an audited local file
	if err != nil {
		return KeyInfo{}, fmt.Errorf("hwkey: read public key %s: %w", pubPath, err)
	}
	pubInfo, cErr := ClassifyPublicKeyLine(FirstNonEmptyLine(string(data)))
	if cErr != nil {
		return KeyInfo{}, cErr
	}
	if !pubInfo.Hardware {
		return KeyInfo{}, fmt.Errorf("%w: public key type %q is not sk-backed", ErrSoftwareKey, pubInfo.TypeToken)
	}

	res, rErr := runner.Run(ctx, "ssh-keygen", "-l", "-f", pubPath)
	if rErr != nil || !res.Ok() {
		return KeyInfo{}, fmt.Errorf("%w: ssh-keygen -l could not read %s", ErrParse, pubPath)
	}
	listInfo, lErr := ParseKeygenListLine(FirstNonEmptyLine(res.Stdout))
	if lErr != nil {
		return KeyInfo{}, lErr
	}
	if !listInfo.Hardware {
		return KeyInfo{}, fmt.Errorf("%w: ssh-keygen -l reports non-SK type %q", ErrSoftwareKey, listInfo.TypeToken)
	}
	return KeyInfo{
		TypeToken:   pubInfo.TypeToken,
		Hardware:    true,
		Fingerprint: listInfo.Fingerprint,
		Comment:     listInfo.Comment,
	}, nil
}
