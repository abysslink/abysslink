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

// classify.go holds the pure, GOOS-independent parsers: public-key line
// classification, `ssh-keygen -l` line parsing, and `ssh -V` version parsing.
// Every parser fails CLOSED: an unrecognized input is an error — never
// Hardware=true, never an assumed-modern version.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// hardwarePubTokens is the allowlist of public-key type tokens that classify
// as HARDWARE (sk-backed). Anything not in hardwarePubTokens or
// softwarePubTokens is a parse error, never a guess.
var hardwarePubTokens = map[string]bool{
	tokenSKEd25519:   true,
	tokenSKECDSA:     true,
	tokenWebauthnSK:  true,
	tokenSKEd25519Ct: true,
	tokenSKECDSACt:   true,
}

// softwarePubTokens is the allowlist of public-key type tokens that classify
// as SOFTWARE. Deliberately exhaustive so an unknown/future token fails closed
// (error) instead of being silently binned.
var softwarePubTokens = map[string]bool{
	"ssh-ed25519":         true,
	"ssh-rsa":             true,
	"rsa-sha2-256":        true,
	"rsa-sha2-512":        true,
	"ssh-dss":             true,
	"ecdsa-sha2-nistp256": true,
	"ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true,

	"ssh-ed25519-cert-v01@openssh.com":         true,
	"ssh-rsa-cert-v01@openssh.com":             true,
	"rsa-sha2-256-cert-v01@openssh.com":        true,
	"rsa-sha2-512-cert-v01@openssh.com":        true,
	"ssh-dss-cert-v01@openssh.com":             true,
	"ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
	"ecdsa-sha2-nistp384-cert-v01@openssh.com": true,
	"ecdsa-sha2-nistp521-cert-v01@openssh.com": true,
}

// ClassifyPublicKeyLine classifies one authorized_keys-format public-key line
// by its first whitespace-delimited token. Hardware=true ONLY for the
// allowlisted sk-* / webauthn-sk-* tokens (including their -cert-v01 forms).
// A line with an unknown token, no key material, or no token at all returns
// ErrParse — a parse miss is never "software", it is "refuse".
func ClassifyPublicKeyLine(line string) (KeyInfo, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return KeyInfo{}, fmt.Errorf("%w: public key line has %d fields, want >= 2 (type + key material)", ErrParse, len(fields))
	}
	token := fields[0]
	info := KeyInfo{TypeToken: token}
	if len(fields) > 2 {
		info.Comment = strings.Join(fields[2:], " ")
	}
	switch {
	case hardwarePubTokens[token]:
		info.Hardware = true
		return info, nil
	case softwarePubTokens[token]:
		info.Hardware = false
		return info, nil
	default:
		return KeyInfo{}, fmt.Errorf("%w: unknown public key type token %q", ErrParse, token)
	}
}

// keygenListRe matches one `ssh-keygen -l` output line, parsed FROM THE RIGHT:
// the comment (group 3) can contain spaces or the literal "no comment", so the
// final parenthesized shortname (group 4) is the classification anchor.
// CONFIRMED format string: "%u %s %s (%s)\n" in sshkey.c fingerprint output.
var keygenListRe = regexp.MustCompile(`^(\d+) ((?:SHA256|MD5):\S+) (.*) \(([A-Z0-9-]+)\)$`)

// keygenListSoftwareShortnames is the allowlist of NON-hardware -l shortnames.
// An unknown shortname is an error (fail closed), never Hardware=true and
// never silently "software".
var keygenListSoftwareShortnames = map[string]bool{
	"RSA": true, "DSA": true, "ECDSA": true, "ED25519": true, "XMSS": true,
	// ASSUMED cert shortname renderings (never observed; -SK-CERT handled by
	// the hardware suffix rule below).
	"RSA-CERT": true, "DSA-CERT": true, "ECDSA-CERT": true, "ED25519-CERT": true, "XMSS-CERT": true,
}

// ParseKeygenListLine parses one `ssh-keygen -l -f <pub>` line into KeyInfo.
// The FINAL parenthesized token decides: a "-SK" suffix (or the ASSUMED
// "-SK-CERT") is hardware; an allowlisted plain shortname is software; any
// other token — or a line the regexp cannot shape-match — is ErrParse.
func ParseKeygenListLine(line string) (KeyInfo, error) {
	m := keygenListRe.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return KeyInfo{}, fmt.Errorf("%w: unrecognized ssh-keygen -l line", ErrParse)
	}
	shortname := m[4]
	info := KeyInfo{
		TypeToken:   shortname,
		Fingerprint: m[2],
		Comment:     m[3],
	}
	switch {
	case strings.HasSuffix(shortname, "-SK") || strings.HasSuffix(shortname, "-SK-CERT"):
		info.Hardware = true
		return info, nil
	case keygenListSoftwareShortnames[shortname]:
		info.Hardware = false
		return info, nil
	default:
		return KeyInfo{}, fmt.Errorf("%w: unknown ssh-keygen -l key type %q", ErrParse, shortname)
	}
}

// sshVersionRe matches the OpenSSH version at OFFSET 0 of the FIRST stderr
// line of `ssh -V` (stdout is empty — REAL-CONFIRMED). The optional pN patch
// suffix and everything after (", LibreSSL ...", vendor suffixes) is ignored.
var sshVersionRe = regexp.MustCompile(`^OpenSSH_(\d+)\.(\d+)(?:p(\d+))?`)

// ParseSSHVersion parses "OpenSSH_<major>.<minor>[p<patch>]..." from the first
// stderr line of `ssh -V` into a NUMERIC (major, minor) tuple. A regexp miss,
// an empty line, or an Atoi failure returns ErrParse — the caller must never
// assume-modern on a parse miss.
func ParseSSHVersion(firstStderrLine string) (major, minor int, err error) {
	m := sshVersionRe.FindStringSubmatch(firstStderrLine)
	if m == nil {
		return 0, 0, fmt.Errorf("%w: cannot parse ssh version from %q", ErrParse, firstStderrLine)
	}
	major, err = strconv.Atoi(m[1])
	if err != nil {
		return 0, 0, fmt.Errorf("%w: ssh major version %q: %v", ErrParse, m[1], err)
	}
	minor, err = strconv.Atoi(m[2])
	if err != nil {
		return 0, 0, fmt.Errorf("%w: ssh minor version %q: %v", ErrParse, m[2], err)
	}
	return major, minor, nil
}

// MeetsFloor reports whether the NUMERIC version tuple satisfies the OpenSSH
// >= (FloorMajor, FloorMinor) floor. Numeric tuple compare — (10,0) > (9,9);
// the "10" < "9" lexical-compare bug is a named regression test.
func MeetsFloor(major, minor int) bool {
	if major != FloorMajor {
		return major > FloorMajor
	}
	return minor >= FloorMinor
}
