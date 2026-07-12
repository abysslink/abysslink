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

package sentinel

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// legKind is the classification of a single exec.
type legKind int

const (
	legNone legKind = iota
	legRead
	legEgress
)

// SENSITIVE-READ COMMAND SET (the binary must be a reader). DELIBERATELY
// EXCLUDED: ssh, git, ssh-keygen, ssh-add — they touch ~/.ssh every normal
// session; treating them as reads would nuke precision.
var readCommands = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true,
	"cp": true, "dd": true, "base64": true, "xxd": true, "od": true,
	"tar": true, "zip": true, "gpg": true, "openssl": true, "sqlite3": true,
}

// EGRESS COMMAND SET (opens an outbound connection).
var egressCommands = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"scp": true, "sftp": true, "rsync": true, "ssh": true, "socat": true,
	"openssl": true,
}

// vocabulary holds the compiled path/host matchers for one engine instance.
type vocabulary struct {
	home string

	// Sensitive-path matchers, all resolved to absolute prefixes/paths at build.
	sensitiveDirs  []categorized // prefix match (reading anything inside counts)
	sensitiveFiles map[string]string

	// Basename-only matchers (robust to path form).
	sensitiveBasenames map[string]string

	// Extra ADD-ONLY sensitive tokens from config: absolute prefixes and bare
	// basenames the operator adds.
	extraPrefixes  []string
	extraBasenames map[string]bool

	// Benign egress allowlist.
	allowExact  map[string]bool
	allowSuffix []string
	allowPrefix []string
	allowCIDR   []*net.IPNet
}

type categorized struct {
	prefix   string
	category string
}

// newVocabulary compiles the compiled defaults plus the ADD-ONLY config unions.
func newVocabulary(extraPaths, extraAllowlist []string) *vocabulary {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	v := &vocabulary{
		home:               home,
		sensitiveFiles:     map[string]string{},
		sensitiveBasenames: map[string]string{},
		extraBasenames:     map[string]bool{},
		allowExact:         map[string]bool{},
	}

	join := func(parts ...string) string { return filepath.Join(append([]string{home}, parts...)...) }

	if home != "" {
		// Directory prefixes (reading anything inside counts).
		v.sensitiveDirs = []categorized{
			{join(".ssh"), "ssh-key-store"},
			{join(".gnupg"), "gpg-keyring"},
			{join(".config", "gcloud"), "gcloud-credentials"},
			{join(".aws"), "aws-credentials"},
		}
		// Single-file secrets.
		for path, cat := range map[string]string{
			join(".kube", "config"):        "kube-config",
			join(".netrc"):                 "netrc",
			join(".docker", "config.json"): "docker-config",
			join(".git-credentials"):       "git-credentials",
		} {
			v.sensitiveFiles[path] = cat
		}
		// abysslink secret/state dirs.
		v.sensitiveDirs = append(v.sensitiveDirs,
			categorized{stateDir(home), "abysslink-state"},
		)
	}

	// Basename-only sensitive files (browser/OS credential stores + netrc).
	for base, cat := range map[string]string{
		".netrc":            "netrc",
		".git-credentials":  "git-credentials",
		"login.keychain-db": "os-keychain",
		"Login Data":        "browser-credentials",
		"cookies.sqlite":    "browser-cookies",
		"key4.db":           "browser-key-db",
	} {
		v.sensitiveBasenames[base] = cat
	}

	// ADD-ONLY extra sensitive tokens: an absolute-ish token becomes a prefix,
	// a bare basename becomes a basename matcher.
	for _, p := range extraPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.ContainsRune(p, filepath.Separator) || strings.HasPrefix(p, "~") {
			v.extraPrefixes = append(v.extraPrefixes, v.normalize(p))
		} else {
			v.extraBasenames[p] = true
		}
	}

	v.buildAllowlist(extraAllowlist)
	return v
}

// stateDir returns the abysslink XDG state dir (audit log dir, tailscale state).
func stateDir(home string) string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "abysslink")
	}
	return filepath.Join(home, ".local", "state", "abysslink")
}

// buildAllowlist compiles the compiled-default benign egress allowlist plus the
// ADD-ONLY config union. Loopback and the tailnet CIDR keep FP ~0 for the
// common `go build` / registry-pull / scp-to-tailnet case.
func (v *vocabulary) buildAllowlist(extra []string) {
	for _, h := range []string{
		"proxy.golang.org", "sum.golang.org",
		"registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
		"crates.io", "static.crates.io", "index.crates.io",
		"github.com", "api.github.com", "codeload.github.com", "gitlab.com",
		"ghcr.io",
	} {
		v.allowExact[h] = true
	}
	// Suffix wildcards: base itself and any sub.base.
	v.allowSuffix = []string{"npmjs.org", "docker.io", "ts.net", "pythonhosted.org"}
	// Prefix wildcards: goproxy.* mirrors GOPROXY custom hosts.
	v.allowPrefix = []string{"goproxy."}
	// Tailnet + loopback CIDRs.
	for _, c := range []string{"100.64.0.0/10", "127.0.0.0/8", "::1/128"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			v.allowCIDR = append(v.allowCIDR, n)
		}
	}
	// ADD-ONLY extra allowlist entries.
	for _, h := range extra {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		switch {
		case strings.HasPrefix(h, "*."):
			v.allowSuffix = append(v.allowSuffix, strings.TrimPrefix(h, "*."))
		case strings.Contains(h, "/"):
			if _, n, err := net.ParseCIDR(h); err == nil {
				v.allowCIDR = append(v.allowCIDR, n)
			}
		default:
			v.allowExact[h] = true
		}
	}
}

// classify returns the leg kind and a generic label for one exec. Egress is
// checked first so a dual-use binary (openssl) is classified by its actual
// invocation. Precision over recall: an ambiguous case returns legNone.
func (v *vocabulary) classify(name string, args []string) (legKind, string) {
	bin := baseName(name)

	if egressCommands[bin] {
		if host, ok := parseEgressHost(bin, args); ok {
			if !v.isAllowlisted(host) {
				return legEgress, "non-allowlisted-host"
			}
			return legNone, "" // allowlisted egress is benign
		}
		// egress command with no parseable target: unparseable → treated as
		// benign (never a hit). Fall through only for dual-use readers.
	}

	if readCommands[bin] {
		// openssl s_client is an egress form, not a file read — never a read leg.
		if bin == "openssl" && hasToken(args, "s_client") {
			return legNone, ""
		}
		if cat, ok := v.matchSensitive(args); ok {
			return legRead, cat
		}
	}

	return legNone, ""
}

// matchSensitive returns the category of the first argv token that resolves
// into the sensitive-path set. Flags are skipped. Matching is on normalized
// absolute-path prefix or an exact basename — NOT substring — so a repo file
// literally named "ssh_config" or "ssh" never matches.
func (v *vocabulary) matchSensitive(args []string) (string, bool) {
	skipNext := false
	for _, a := range args {
		if skipNext {
			// This token is the VALUE of a TLS-client-cert flag (see below): a
			// cert/key used to ESTABLISH the connection, not a secret being sent.
			skipNext = false
			continue
		}
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			// A cert/key passed to SET UP TLS (`--cert client.key`, `--cacert
			// ca.pem`, `-E cert.pem`) is normal mTLS, NOT exfil — do not let its
			// value count as a sensitive read. Both `--flag val` and `--flag=val`
			// forms are neutralised. Upload flags (-T/--upload-file/-d/--data) are
			// deliberately NOT here: uploading a secret path IS the exfil signal.
			if isTLSCertFlag(a) {
				skipNext = true // `--cert val` (separate value form)
			}
			continue
		}
		if cat, ok := v.matchSensitiveToken(a); ok {
			return cat, true
		}
	}
	return "", false
}

// matchSensitiveToken classifies a single non-flag argv token. Matching is on
// normalized absolute-path prefix or an exact basename — NOT substring — so a
// repo file literally named "ssh_config" or "ssh" never matches.
func (v *vocabulary) matchSensitiveToken(a string) (string, bool) {
	if a == "" {
		return "", false
	}
	abs := v.normalize(a)
	base := filepath.Base(abs)

	// Directory-prefix matches.
	for _, d := range v.sensitiveDirs {
		if pathHasPrefix(abs, d.prefix) {
			return d.category, true
		}
	}
	// Single-file matches.
	if cat, ok := v.sensitiveFiles[abs]; ok {
		return cat, true
	}
	// Extra ADD-ONLY prefixes.
	for _, p := range v.extraPrefixes {
		if pathHasPrefix(abs, p) {
			return "config-extra-path", true
		}
	}
	// Basename matches (credential stores, netrc).
	if cat, ok := v.sensitiveBasenames[base]; ok {
		return cat, true
	}
	if v.extraBasenames[base] {
		return "config-extra-path", true
	}
	// Private-key basename globs (id_* / *.key / *key*.pem, never *.pub).
	if cat, ok := privateKeyCategory(base); ok {
		return cat, true
	}
	// .env / .env.* local dev secrets.
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return "dotenv", true
	}
	return "", false
}

// privateKeyCategory reports the private-key category for a basename, if any.
//
// Precision over recall: a bare `*.pem` is NOT treated as sensitive, because
// `.pem` is the standard extension for PUBLIC material too — CA bundles
// (ca.pem), server/leaf certs (cert.pem, fullchain.pem, chain.pem). Treating
// every `.pem` as a private key made routine mTLS / custom-CA calls
// (`curl --cacert ca.pem https://internal`) false-fire. We match a `.pem` only
// when the basename positively indicates a PRIVATE key. `id_*` (SSH, not
// `id_*.pub`) and `*.key` stay sensitive.
func privateKeyCategory(base string) (string, bool) {
	if strings.HasSuffix(base, ".pub") {
		return "", false
	}
	if strings.HasPrefix(base, "id_") {
		return "ssh-private-key", true
	}
	if strings.HasSuffix(base, ".key") {
		return "pem-private-key", true
	}
	if strings.HasSuffix(base, ".pem") && looksLikePrivateKeyName(base) {
		return "pem-private-key", true
	}
	return "", false
}

// isTLSCertFlag reports whether a is EXACTLY a curl/wget-style flag whose
// following token is a client cert/key/CA used to establish TLS (not exfil).
// Only the separate-value form (`--cert file`) needs the caller to skip the
// next token; the `--cert=file` form is a single token already skipped as a
// flag, so it is intentionally not matched here.
func isTLSCertFlag(a string) bool {
	switch a {
	case "--cert", "--key", "--cacert", "--capath", "--cert-type", "--key-type",
		"--pinnedpubkey", "--engine", "-E", "--ca-directory", "--certificate",
		"--private-key", "--ca-certificate":
		return true
	}
	return false
}

// looksLikePrivateKeyName reports whether a *.pem basename positively indicates
// a PRIVATE key (vs a cert or CA bundle). Kept tight on purpose.
func looksLikePrivateKeyName(base string) bool {
	lower := strings.ToLower(base)
	for _, hint := range []string{"key", "priv", "identity"} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// normalize resolves a token to a cleaned absolute path: leading ~ expands to
// HOME; a relative path resolves against the cwd; then filepath.Clean.
func (v *vocabulary) normalize(tok string) string {
	p := tok
	switch {
	case p == "~":
		p = v.home
	case strings.HasPrefix(p, "~/"):
		p = filepath.Join(v.home, p[2:])
	case !filepath.IsAbs(p):
		if cwd, err := os.Getwd(); err == nil {
			p = filepath.Join(cwd, p)
		}
	}
	return filepath.Clean(p)
}

// isAllowlisted reports whether an egress host is on the benign allowlist.
func (v *vocabulary) isAllowlisted(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" || h == "localhost" {
		return true
	}
	// Bracketed IPv6.
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsLoopback() {
			return true
		}
		for _, n := range v.allowCIDR {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	if v.allowExact[h] {
		return true
	}
	for _, s := range v.allowSuffix {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	for _, p := range v.allowPrefix {
		if strings.HasPrefix(h, p) {
			return true
		}
	}
	return false
}

// baseName returns the final path element of a binary name (/usr/bin/cat → cat).
func baseName(name string) string {
	return filepath.Base(name)
}

// hasToken reports whether tok appears verbatim among args.
func hasToken(args []string, tok string) bool {
	for _, a := range args {
		if a == tok {
			return true
		}
	}
	return false
}

// pathHasPrefix reports whether abs is within the directory prefix (equal to it
// or a child), using path-segment boundaries so /home/x/.sshother is NOT a
// child of /home/x/.ssh.
func pathHasPrefix(abs, prefix string) bool {
	if prefix == "" {
		return false
	}
	if abs == prefix {
		return true
	}
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(abs, prefix)
}

// parseEgressHost extracts the outbound host from an egress command's argv, if
// one is parseable. Precision over recall: when no host can be parsed the
// egress leg does not fire.
func parseEgressHost(bin string, args []string) (string, bool) {
	switch bin {
	case "curl", "wget":
		return parseURLHost(args)
	case "scp", "sftp":
		return parseRemoteSpec(args)
	case "rsync":
		if h, ok := parseURLHost(args); ok {
			return h, true
		}
		return parseRemoteSpec(args)
	case "ssh":
		return parseSSHTarget(args)
	case "nc", "ncat", "netcat":
		return parseNCHost(args)
	case "socat":
		return parseSocatHost(args)
	case "openssl":
		return parseOpensslConnect(args)
	}
	return "", false
}

// parseURLHost extracts the host from an explicit scheme URL (http://, https://,
// ftp://, ...). A scheme is REQUIRED for curl/wget: a scheme-less token is
// indistinguishable from a filename, so treating it as a host would risk false
// positives — precision over recall.
func parseURLHost(args []string) (string, bool) {
	for _, a := range args {
		if strings.Contains(a, "://") {
			if u, err := url.Parse(a); err == nil && u.Hostname() != "" {
				return u.Hostname(), true
			}
		}
	}
	return "", false
}

// parseRemoteSpec extracts the host from a scp/sftp `[user@]host:path` token.
func parseRemoteSpec(args []string) (string, bool) {
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		// A remote spec has a ':' whose left side is a host (no path separator).
		i := strings.IndexByte(a, ':')
		if i <= 0 {
			continue
		}
		left := a[:i]
		if strings.ContainsRune(left, filepath.Separator) {
			continue // looks like a local path a:b under a dir
		}
		if h := hostFromAuthority(left); h != "" {
			return h, true
		}
	}
	return "", false
}

// parseSSHTarget extracts the host from `ssh [flags] [user@]host command...`.
// It fires ONLY when a remote command follows the host (a bare interactive
// `ssh host` is not egress) — the tight rule that keeps normal interactive SSH
// out of the egress vocabulary.
func parseSSHTarget(args []string) (string, bool) {
	target := ""
	remoteCmd := false
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			if sshFlagTakesArg(a) {
				skipNext = true
			}
			continue
		}
		if target == "" {
			target = a
			continue
		}
		// A non-flag token after the target is a remote command.
		remoteCmd = true
		break
	}
	if target == "" || !remoteCmd {
		return "", false
	}
	if h := hostFromAuthority(target); h != "" {
		return h, true
	}
	return "", false
}

// parseNCHost extracts the host from `nc [flags] host port`. A listener (-l) is
// not egress.
func parseNCHost(args []string) (string, bool) {
	var positional []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			// Listen mode is not egress. Match it precisely: the long flag is
			// exactly `--listen`; a short-flag cluster (`-l`, `-lvp`) contains an
			// 'l'. A LONG flag that merely contains 'l' (`--ssl`, `--tls`) is NOT
			// listen — the old substring test mis-skipped `ncat --ssl host port`
			// as a listener and fail-opened the egress signal.
			if a == "--listen" || (!strings.HasPrefix(a, "--") && strings.ContainsRune(a, 'l')) {
				return "", false
			}
			continue
		}
		positional = append(positional, a)
	}
	if len(positional) >= 2 {
		if h := hostFromAuthority(positional[0]); h != "" {
			return h, true
		}
	}
	return "", false
}

// parseSocatHost extracts the host from a socat TCP/OPENSSL address spec, e.g.
// `TCP:host:port` or `OPENSSL:host:port`.
func parseSocatHost(args []string) (string, bool) {
	for _, a := range args {
		up := strings.ToUpper(a)
		for _, pfx := range []string{"TCP:", "TCP4:", "TCP6:", "OPENSSL:", "SSL:", "TCP-CONNECT:", "OPENSSL-CONNECT:"} {
			if strings.HasPrefix(up, pfx) {
				rest := a[len(pfx):]
				host := rest
				if j := strings.IndexByte(rest, ':'); j > 0 {
					host = rest[:j]
				}
				if h := hostFromAuthority(host); h != "" {
					return h, true
				}
			}
		}
	}
	return "", false
}

// parseOpensslConnect extracts the host from `openssl s_client -connect host:port`.
func parseOpensslConnect(args []string) (string, bool) {
	for i, a := range args {
		if a == "-connect" && i+1 < len(args) {
			hp := args[i+1]
			host := hp
			if j := strings.LastIndexByte(hp, ':'); j > 0 {
				host = hp[:j]
			}
			if h := hostFromAuthority(host); h != "" {
				return h, true
			}
		}
	}
	return "", false
}

// hostFromAuthority strips an optional `user@` prefix and a `:port` suffix,
// returning the bare host, or "" when the token does not look like a host.
func hostFromAuthority(tok string) string {
	if at := strings.LastIndexByte(tok, '@'); at >= 0 {
		tok = tok[at+1:]
	}
	// Strip a trailing :port (but keep bare IPv6 which has multiple colons and
	// is normally bracketed; leave bracketed forms to isAllowlisted).
	if strings.Count(tok, ":") == 1 {
		tok = tok[:strings.IndexByte(tok, ':')]
	}
	tok = strings.TrimSpace(tok)
	if tok == "" || strings.ContainsRune(tok, filepath.Separator) {
		return ""
	}
	return tok
}

// sshFlagTakesArg reports whether an ssh flag consumes the following token.
func sshFlagTakesArg(flag string) bool {
	// Long forms and clustered short flags rarely take a separate arg here; the
	// common value-taking short flags for a remote-exec invocation are these.
	if len(flag) != 2 || flag[0] != '-' {
		return false
	}
	switch flag[1] {
	case 'p', 'i', 'o', 'l', 'F', 'L', 'R', 'D', 'W', 'b', 'c', 'm', 'J', 'e':
		return true
	}
	return false
}
