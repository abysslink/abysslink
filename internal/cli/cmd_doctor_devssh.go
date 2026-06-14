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
	"os"
	"sort"
	"strings"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/modules/ssh"
	"github.com/abysslink/abysslink/internal/shell"
)

// devSSHModule is the Module string for every drift finding so the doctor
// render groups them under one heading, distinct from the core "ssh" module's
// own Detect findings.
const devSSHModule = "device-ssh"

// Destination paths for the installed CA-trust file and the KRL. These MUST
// mirror caTrustDest/krlDest in internal/modules/ssh/krl.go — the source of
// truth for where `up --apply` installs the key material. They are stable
// /etc/ssh destination paths, not config, so mirroring the two literals here
// (rather than importing the ssh module, which would pull its lifecycle into
// the doctor package) is deliberate. They are package vars, not consts, so
// tests can point the drift reads at a t.TempDir file (the deviceStorePath
// seam pattern).
var (
	// devSSHCATrustDest mirrors internal/modules/ssh.caTrustDest.
	devSSHCATrustDest = "/etc/ssh/abysslink_device_ca.pub" //nolint:gochecknoglobals // test seam; source of truth is internal/modules/ssh/krl.go
	// devSSHKRLDest mirrors internal/modules/ssh.krlDest.
	devSSHKRLDest = "/etc/ssh/abysslink.krl" //nolint:gochecknoglobals // test seam; source of truth is internal/modules/ssh/krl.go
)

// caKRLView is the minimal read-only view of the device store the drift check
// needs: the enrolled CA public key line and the revoked-serial set. *device.Store
// satisfies it; tests inject a fake. Defined locally so the doctor wiring has no
// hard coupling to the device store lifecycle (mirrors the ssh module's
// CAProvider seam from 28.1-01).
type caKRLView interface {
	// CAPublicKeyIfPresent returns the device CA public key as a single
	// authorized_keys-format line (no trailing newline) WITHOUT minting a CA on
	// first use. An error (secrets.ErrNotFound) means no CA is enrolled (no
	// keychain backend / never minted) — the drift check treats that as
	// "auto-trust not in play" and emits nothing. The read-only path MUST NOT use
	// the minting CAPublicKey: doctor would otherwise create+persist a CA as a
	// side effect and defeat its own silence gate.
	CAPublicKeyIfPresent(ctx context.Context) (string, error)
	// RevokedSerials returns the revoked SSH certificate serials.
	RevokedSerials() []uint64
}

// devSSHOK builds a SeverityOK device-ssh finding (the control ran and passed).
func devSSHOK(check, msg string) modules.Finding {
	return modules.Finding{Module: devSSHModule, Check: check, Severity: modules.SeverityOK, Message: msg}
}

// devSSHWarn builds a SeverityWarning device-ssh finding (drift / missing /
// unverifiable — never a false-green).
func devSSHWarn(check, msg string) modules.Finding {
	return modules.Finding{Module: devSSHModule, Check: check, Severity: modules.SeverityWarning, Message: msg}
}

// devSSHDriftFindings is the read-only CA/KRL drift finding family (success
// criterion 5). It compares the installed /etc/ssh CA-trust file and KRL against
// the current device store state and reports drift — it NEVER auto-fixes (the
// remediation is an explicit `abysslink up --apply` the operator runs).
//
// It emits NOTHING when auto-trust is not in play: a nil view, or a CAPublicKey
// error (no keychain backend / no enrolled CA), means there is no managed CA to
// reconcile, so the drift check is silent rather than warning about absent files
// on a machine that never wires the CA. The caller additionally gates this on
// sshd mode == "openssh-fallback" (a tailscale-SSH machine never installs the
// CA-trust file or KRL).
//
// Honesty rule (T-28.1-08, Phase 23.1/23.2 precedent): a control the check could
// not actually verify NEVER renders SeverityOK. When ssh-keygen is unavailable
// or the -Q -l probe fails to execute, the KRL check degrades to a distinct
// devssh-unknown WARN, not a false-OK and not a false drift error.
func devSSHDriftFindings(ctx context.Context, runner shell.Runner, ca caKRLView) []modules.Finding {
	if ca == nil {
		return nil // no managed CA view — auto-trust not in play (fail-safe).
	}
	caLine, err := ca.CAPublicKeyIfPresent(ctx)
	if err != nil {
		// No keychain backend or no enrolled CA: auto-trust is simply not in
		// play. Emit nothing rather than warning about absent files (fail-safe).
		// CAPublicKeyIfPresent never mints, so this read path has no side effect.
		return nil
	}
	caLine = strings.TrimSpace(caLine)

	var findings []modules.Finding
	findings = append(findings, caTrustDriftFinding(caLine))
	findings = append(findings, krlDriftFindings(ctx, runner, ca.RevokedSerials())...)
	return findings
}

// caTrustDriftFinding compares the installed CA-trust file against the store's
// CA public key line.
func caTrustDriftFinding(caLine string) modules.Finding {
	const (
		checkOK      = "ca-trust"
		checkDrift   = "ca-trust-drift"
		checkMissing = "ca-trust-missing"
	)
	// #nosec G304 -- devSSHCATrustDest is a fixed /etc/ssh destination path (or a
	// test-injected temp path), never attacker-controlled; the file is read-only
	// and only its content is compared (no execution, no secret).
	raw, rerr := os.ReadFile(devSSHCATrustDest)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return devSSHWarn(checkMissing,
				"device CA is enrolled but "+devSSHCATrustDest+" is absent — the CA trust file is not installed; "+
					"run: abysslink up --apply  to wire TrustedUserCAKeys")
		}
		// Unreadable for another reason (perms, IO): cannot verify — WARN, never
		// a false-OK and never a false drift error.
		return devSSHWarn("devssh-unknown",
			"could not read "+devSSHCATrustDest+" to verify CA-trust drift: "+rerr.Error())
	}
	if strings.TrimSpace(string(raw)) == caLine {
		return devSSHOK(checkOK, "installed CA trust file matches the enrolled device CA public key")
	}
	return devSSHWarn(checkDrift,
		"installed "+devSSHCATrustDest+" does not match the enrolled device CA public key (stale after re-enrollment) — "+
			"run: abysslink up --apply  to reinstall the current CA trust file")
}

// krlDriftFindings compares the live KRL's revoked-serial set (decoded via
// ssh-keygen -Q -l -f) against the store's RevokedSerials().
func krlDriftFindings(ctx context.Context, runner shell.Runner, want []uint64) []modules.Finding {
	const (
		checkOK      = "krl"
		checkDrift   = "krl-drift"
		checkMissing = "krl-missing"
		checkUnknown = "devssh-unknown"
	)
	if _, serr := os.Stat(devSSHKRLDest); serr != nil {
		if os.IsNotExist(serr) {
			return []modules.Finding{devSSHWarn(checkMissing,
				"device CA is enrolled but the KRL "+devSSHKRLDest+" is absent — revocation is not enforced on disk; "+
					"run: abysslink up --apply  to install the RevokedKeys KRL")}
		}
		return []modules.Finding{devSSHWarn(checkUnknown,
			"could not stat the KRL "+devSSHKRLDest+" to verify drift: "+serr.Error())}
	}

	res, rerr := runner.Run(ctx, "ssh-keygen", "-Q", "-l", "-f", devSSHKRLDest)
	if rerr != nil {
		// ssh-keygen unavailable / exec failure: cannot verify the live KRL.
		// Probe-failure honesty — WARN, NEVER SeverityOK (T-28.1-08).
		return []modules.Finding{devSSHWarn(checkUnknown,
			"could not run ssh-keygen -Q -l to decode the live KRL (cannot verify revocation drift): "+rerr.Error())}
	}
	if !res.Ok() {
		return []modules.Finding{devSSHWarn(checkUnknown,
			"ssh-keygen -Q -l -f exited non-zero decoding the live KRL (cannot verify revocation drift): "+
				strings.TrimSpace(res.Stderr))}
	}

	got, perr := ssh.ParseKRLSerials(res.Stdout)
	if perr != nil {
		// The KRL decoded but a serial line was not the expected decimal/range
		// form — cannot trust a partial parse. Probe-failure honesty: WARN, never
		// a false-OK and never a false drift error (T-28.1-08).
		return []modules.Finding{devSSHWarn(checkUnknown,
			"could not parse the live KRL's revoked-serial set (cannot verify revocation drift): "+perr.Error())}
	}
	if uint64SetsEqual(got, want) {
		return []modules.Finding{devSSHOK(checkOK,
			"installed KRL revoked-serial set matches the device store (revocation enforced on disk)")}
	}
	return []modules.Finding{devSSHWarn(checkDrift,
		"installed KRL revoked-serial set differs from the device store — a revocation is not yet enforced on disk; "+
			"run: abysslink up --apply  to rebuild the KRL from the current revoked serials")}
}

// uint64SetsEqual reports whether a and b contain the same uint64 values as
// sets. Both inputs are copied and sorted so callers need not pre-sort; this
// makes the comparison order-independent and tolerant of duplicates being
// absent (the producers — parseKRLSerials and RevokedSerials — never duplicate).
func uint64SetsEqual(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]uint64(nil), a...)
	sb := append([]uint64(nil), b...)
	sort.Slice(sa, func(i, j int) bool { return sa[i] < sa[j] })
	sort.Slice(sb, func(i, j int) bool { return sb[i] < sb[j] })
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}
