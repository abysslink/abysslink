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

package ssh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// CAProvider is the minimal read-only view of the device store the ssh module
// needs to wire TrustedUserCAKeys + RevokedKeys. *device.Store satisfies it;
// tests inject a fake. Defined locally so the ssh module has no hard device
// import coupling — mirroring the AuditWriter minimal-interface pattern.
type CAProvider interface {
	// CAPublicKey returns the device CA public key as a single
	// authorized_keys-format line (no trailing newline).
	CAPublicKey(ctx context.Context) (string, error)
	// RevokedSerials returns the revoked SSH certificate serials.
	RevokedSerials() []uint64
}

// Destination paths for the installed CA-trust file and the KRL. These hold key
// material, not config, so they live directly under /etc/ssh (NOT in
// sshd_config.d/, which is for config drop-ins). The CA pub is public and the
// KRL must be root-readable or sshd fails pubkey auth closed — both 0644.
const (
	// caTrustDest is where the device CA public key is installed; referenced by
	// the TrustedUserCAKeys directive (DEVC-05).
	caTrustDest = "/etc/ssh/abysslink_device_ca.pub"
	// krlDest is where the OpenSSH KRL is installed; referenced by the
	// RevokedKeys directive (DEVC-06).
	krlDest = "/etc/ssh/abysslink.krl"
)

// Staged filenames under ~/.config/abysslink/generated/. Each is audit-written
// before being installed into /etc/ssh via sudo install.
const (
	// stagedCAName is the staged CA public key filename.
	stagedCAName = "abysslink_device_ca.pub"
	// stagedKRLName is the staged KRL binary filename.
	stagedKRLName = "abysslink.krl"
	// stagedSpecName is the staged, deterministic KRL serial-spec filename. It
	// is the idempotency anchor (the KRL binary is NOT deterministic).
	stagedSpecName = "abysslink.krl.spec"
)

// krlSpecHeader is the managed-by comment line that prefixes every rendered KRL
// serial spec. An empty serial set renders this header alone — a valid empty
// spec that yields a valid empty KRL revoking nothing (never fail-open/closed).
const krlSpecHeader = "# Managed by abysslink — device SSH cert revocation (by serial). Do not edit.\n"

// renderKRLSpec renders the OpenSSH KRL serial spec for serials. The output is
// deterministic — serials are copied and sorted ascending so two calls with the
// same (possibly unsorted) input are byte-identical. This determinism is the
// idempotency anchor: the KRL binary embeds a generation timestamp and is NOT
// byte-deterministic, so dedup must compare the spec, never the KRL bytes.
//
// An empty (nil or zero-length) serial set renders the header comment alone —
// a valid empty spec that ssh-keygen -k turns into a valid empty KRL revoking
// nothing (never an absent/garbage RevokedKeys target that would fail closed
// for all users).
func renderKRLSpec(serials []uint64) string {
	s := sortedDedupe(serials)
	var b strings.Builder
	b.WriteString(krlSpecHeader)
	for _, n := range s {
		// Decimal "serial: N" lines; "N-M" ranges are also valid KRL syntax but
		// are not needed for an explicit revoked-serial list.
		b.WriteString("serial: ")
		b.WriteString(formatUint(n))
		b.WriteString("\n")
	}
	return b.String()
}

// sortedDedupe returns serials sorted ascending with duplicates removed. The
// rendered spec and every serial-set comparison run through this so a duplicate
// serial in RevokedSerials() can never change the spec bytes (idempotency) or
// skew a set-equality check.
func sortedDedupe(serials []uint64) []uint64 {
	if len(serials) == 0 {
		return nil
	}
	seen := make(map[uint64]struct{}, len(serials))
	out := make([]uint64, 0, len(serials))
	for _, n := range serials {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// uint64SlicesEqual reports whether two ALREADY-sorted-and-deduped slices are
// element-wise identical. Callers pass sortedDedupe output on both sides.
func uint64SlicesEqual(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// maxKRLRangeSpan caps how many serials a single "serial: N-M" range may expand
// to. abysslink revokes only a handful of device serials and ssh-keygen
// collapses just the consecutive runs we actually revoked, so a legitimate span
// is tiny; a span past this cap signals a malformed or foreign KRL and is
// reported as an error rather than allocating unboundedly.
const maxKRLRangeSpan = 1 << 20

// ParseKRLSerials extracts every revoked serial from `ssh-keygen -Q -l -f`
// stdout into a sorted, deduplicated []uint64. ssh-keygen COLLAPSES consecutive
// serials into "serial: N-M" ranges — even two adjacent values — so BOTH the
// single "serial: N" and the inclusive "serial: N-M" range forms are handled
// (device serials are allocated monotonically, so adjacency is the common case;
// parsing only the single form would silently drop ranged serials). Non-serial
// lines (the "# CA key ..." header, blanks) are ignored. A "serial:" line whose
// remainder is neither a decimal nor a valid N-M range is an error: ssh-keygen
// never emits that, so it means the KRL or the decode is not what we expect and
// the caller must not trust a partial parse.
func ParseKRLSerials(stdout string) ([]uint64, error) {
	var collected []uint64
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "serial:")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if lo, hi, isRange := strings.Cut(rest, "-"); isRange {
			a, aerr := strconv.ParseUint(strings.TrimSpace(lo), 10, 64)
			b, berr := strconv.ParseUint(strings.TrimSpace(hi), 10, 64)
			if aerr != nil || berr != nil {
				return nil, fmt.Errorf("ssh: malformed KRL serial range %q", rest)
			}
			if b < a {
				return nil, fmt.Errorf("ssh: inverted KRL serial range %q", rest)
			}
			if b-a+1 > maxKRLRangeSpan {
				return nil, fmt.Errorf("ssh: KRL serial range %q spans more than %d serials", rest, maxKRLRangeSpan)
			}
			for n := a; ; n++ {
				collected = append(collected, n)
				if n == b {
					break
				}
			}
			continue
		}
		n, nerr := strconv.ParseUint(rest, 10, 64)
		if nerr != nil {
			return nil, fmt.Errorf("ssh: malformed KRL serial %q", rest)
		}
		collected = append(collected, n)
	}
	return sortedDedupe(collected), nil
}

// formatUint renders a uint64 as decimal without pulling in fmt, keeping
// renderKRLSpec allocation-light and free of format-string parsing.
func formatUint(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte // max digits in a uint64
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// generatedDir resolves ~/.config/abysslink/generated/, creating it 0700 if
// absent. It is the single staging location for every artifact (the drop-in,
// the CA pub, the spec, and the KRL) — mirroring installHardenedSSHD.
func generatedDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("ssh apply: home dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "abysslink", "generated")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("ssh apply: mkdir generated: %w", err)
	}
	return dir, nil
}

// buildAndStageKRL stages the CA public key line and the deterministic KRL
// serial spec via audit.WriteFile, then builds the OpenSSH KRL by invoking
// ssh-keygen -k -s <ca.pub> <spec> through the shell.Runner, and finally
// re-stages the produced KRL binary through audit so the mutation is recorded.
//
// Idempotency is anchored on the deterministic spec, NOT on the KRL bytes (the
// KRL embeds a generation timestamp and is non-deterministic — comparing its
// bytes would churn the audit log on every Apply). When the freshly rendered
// spec is byte-identical to the previously-staged spec AND the staged KRL still
// exists, the build is skipped and changed=false is returned.
//
// The -s <ca.pub> flag is REQUIRED for by-serial revocation (without it
// ssh-keygen exits 255). It is therefore never omitted.
func (m *Module) buildAndStageKRL(ctx context.Context, caLine string, serials []uint64) (changed bool, err error) {
	dir, err := generatedDir()
	if err != nil {
		return false, err
	}
	stagedCA := filepath.Join(dir, stagedCAName)
	stagedSpec := filepath.Join(dir, stagedSpecName)
	stagedKRL := filepath.Join(dir, stagedKRLName)

	// Stage the CA public key (0644 — public material). Every file mutation goes
	// through internal/audit (CLAUDE.md hard rule): backup + hash-only audit +
	// atomic write.
	if werr := m.audit.WriteFile(stagedCA, []byte(caLine+"\n"), 0o644, false); werr != nil {
		return false, fmt.Errorf("ssh apply: stage CA pub: %w", werr)
	}

	desiredSpec := renderKRLSpec(serials)
	desiredSet := sortedDedupe(serials)

	// Idempotency: skip the (non-deterministic) KRL rebuild when the spec is
	// unchanged AND the prior KRL is still staged. Compare the deterministic
	// spec, never the KRL bytes (RESEARCH Pitfall 1).
	if prior, rerr := os.ReadFile(stagedSpec); rerr == nil && string(prior) == desiredSpec {
		if _, serr := os.Stat(stagedKRL); serr == nil {
			return false, nil
		}
	} else if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return false, fmt.Errorf("ssh apply: read staged spec: %w", rerr)
	}

	// Write the spec to a SEPARATE input file for ssh-keygen. The idempotency
	// anchor (stagedSpec) is advanced only at the END of this function — after the
	// KRL is built, verified to revoke exactly the desired serials, and durably
	// staged. Writing the anchor up front (as the original code did) let a
	// mid-build failure leave the anchor ahead of its KRL: the next run would
	// dedup-skip and install the STALE KRL, silently failing open against a
	// just-revoked device.
	specInput := stagedKRL + ".spec.in"
	if werr := m.audit.WriteFile(specInput, []byte(desiredSpec), 0o600, false); werr != nil {
		return false, fmt.Errorf("ssh apply: stage KRL spec input: %w", werr)
	}

	// Build the KRL via ssh-keygen through the Runner (never os/exec). -s is
	// required for by-serial revocation; the spec input path is the final operand.
	res, rerr := m.runner.Run(ctx, "ssh-keygen", "-k", "-f", stagedKRL, "-s", stagedCA, specInput)
	if rerr != nil {
		return false, fmt.Errorf("ssh apply: build KRL: %w", rerr)
	}
	if !res.Ok() {
		return false, fmt.Errorf("ssh apply: ssh-keygen -k exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	// ssh-keygen -k writes the KRL binary itself; re-stage it through audit so
	// the mutation is recorded (CLAUDE.md: every file mutation goes through
	// internal/audit). The audit re-write produces an atomic, backed-up,
	// hash-recorded copy at the same path (0644 — must be root-readable once
	// installed or sshd fails pubkey auth closed).
	krlBytes, rderr := os.ReadFile(stagedKRL)
	if rderr != nil {
		return false, fmt.Errorf("ssh apply: read built KRL: %w", rderr)
	}
	if werr := m.audit.WriteFile(stagedKRL, krlBytes, 0o644, false); werr != nil {
		return false, fmt.Errorf("ssh apply: stage KRL: %w", werr)
	}

	// Verify the built KRL revokes EXACTLY the desired serial set — not merely
	// that it is well-formed. This catches a stale/wrong KRL before the anchor is
	// advanced, so a well-formed-but-wrong KRL can never install silently.
	if verr := m.assertKRLSerials(ctx, stagedKRL, desiredSet); verr != nil {
		return false, verr
	}

	// Advance the idempotency anchor LAST: only now that the matching KRL is
	// durably staged and verified is it safe to record this spec as the
	// dedup baseline for the next run.
	if werr := m.audit.WriteFile(stagedSpec, []byte(desiredSpec), 0o600, false); werr != nil {
		return false, fmt.Errorf("ssh apply: stage KRL spec anchor: %w", werr)
	}
	return true, nil
}

// assertKRLSerials decodes the staged KRL via ssh-keygen -Q -l -f and verifies
// its revoked-serial set equals want (already sorted+deduped). It errors on a
// decode failure, a malformed serial line, or any set mismatch — so the caller
// never advances the idempotency anchor or installs a KRL that does not revoke
// exactly the intended serials. ssh-keygen collapses consecutive serials into
// ranges, which ParseKRLSerials expands, so the comparison is exact.
func (m *Module) assertKRLSerials(ctx context.Context, krlPath string, want []uint64) error {
	res, rerr := m.runner.Run(ctx, "ssh-keygen", "-Q", "-l", "-f", krlPath)
	if rerr != nil {
		return fmt.Errorf("ssh apply: decode KRL for serial check: %w", rerr)
	}
	if !res.Ok() {
		return fmt.Errorf("ssh apply: ssh-keygen -Q -l exited %d decoding KRL: %s",
			res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	got, perr := ParseKRLSerials(res.Stdout)
	if perr != nil {
		return fmt.Errorf("ssh apply: parse staged KRL serials: %w", perr)
	}
	if !uint64SlicesEqual(got, want) {
		return fmt.Errorf("ssh apply: staged KRL revokes serials %v but the device store revokes %v — refusing to install", got, want)
	}
	return nil
}

// installCAAndKRL orchestrates the device-CA wiring for installHardenedSSHD:
// resolve the CA pub + revoked serials, stage and build the KRL, run the
// pre-install validation chain, and install the CA pub + KRL into /etc/ssh —
// all BEFORE the referencing drop-in is installed.
//
// It returns caWired=true only when both key files are validated and installed.
// It is fail-safe: a nil CAProvider, or a CAPublicKey error (no keychain
// backend / no enrolled CA yet), returns (false, nil) so the caller renders the
// legacy hardened drop-in with neither directive — `up` is never blocked. A
// non-nil error is returned ONLY for a real validation or install failure once a
// CA is genuinely present (so a broken KRL never silently disables revocation).
func (m *Module) installCAAndKRL(ctx context.Context) (caWired bool, err error) {
	if m.ca == nil {
		return false, nil // no CA wiring — legacy drop-in (fail-safe)
	}

	caLine, cerr := m.ca.CAPublicKey(ctx)
	if cerr != nil {
		// No keychain backend or no enrolled CA: fall back to the legacy
		// hardened drop-in rather than blocking `up`. WARN, never error.
		slog.WarnContext(ctx, "ssh apply: device CA unavailable — installing legacy hardened sshd config without TrustedUserCAKeys/RevokedKeys",
			"err", cerr)
		return false, nil
	}

	serials := m.ca.RevokedSerials()
	if _, berr := m.buildAndStageKRL(ctx, caLine, serials); berr != nil {
		return false, berr
	}

	dir, derr := generatedDir()
	if derr != nil {
		return false, derr
	}
	stagedCA := filepath.Join(dir, stagedCAName)
	stagedKRL := filepath.Join(dir, stagedKRLName)

	// Pre-install validation chain. sshd -t does NOT validate these key-file
	// targets (it stops at host-key checks), so validate them explicitly before
	// any live mutation: the CA pub must parse and the KRL must be well-formed.
	if res, rerr := m.runner.Run(ctx, "ssh-keygen", "-l", "-f", stagedCA); rerr != nil {
		return false, fmt.Errorf("ssh apply: validate CA pub: %w", rerr)
	} else if !res.Ok() {
		return false, fmt.Errorf("ssh apply: CA pub invalid (ssh-keygen -l exited %d): %s",
			res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	if res, rerr := m.runner.Run(ctx, "ssh-keygen", "-Q", "-l", "-f", stagedKRL); rerr != nil {
		return false, fmt.Errorf("ssh apply: validate KRL: %w", rerr)
	} else if !res.Ok() {
		return false, fmt.Errorf("ssh apply: KRL malformed (ssh-keygen -Q -l exited %d): %s",
			res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	// Install the key material into /etc/ssh BEFORE the drop-in. Both are 0644
	// (the CA pub is public; the KRL MUST be root-readable or sshd refuses all
	// pubkey auth — RESEARCH Pitfall 2).
	slog.InfoContext(ctx, "ssh apply: installing device CA trust + KRL", "ca", caTrustDest, "krl", krlDest)
	if res, rerr := m.runner.Run(ctx, "sudo", "install", "-m", "644", stagedCA, caTrustDest); rerr != nil {
		return false, fmt.Errorf("ssh apply: install CA pub: %w", rerr)
	} else if !res.Ok() {
		return false, fmt.Errorf("ssh apply: install CA pub exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	if res, rerr := m.runner.Run(ctx, "sudo", "install", "-m", "644", stagedKRL, krlDest); rerr != nil {
		return false, fmt.Errorf("ssh apply: install KRL: %w", rerr)
	} else if !res.Ok() {
		return false, fmt.Errorf("ssh apply: install KRL exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	return true, nil
}
