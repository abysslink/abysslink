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
	"sort"
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
	s := append([]uint64(nil), serials...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
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
