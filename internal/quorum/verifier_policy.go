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

package quorum

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/audit"
)

// verifierPolicyName is V2's canonical name.
const verifierPolicyName = "V2 policy"

// V2 rule codes.
const (
	codeProtectedPathWrite = "protected-path-write"
	codeAmbiguousScope     = "ambiguous-scope"
	codeNonASCIIPath       = "non-ascii-path"
	codeParseGap           = "parse-gap"
)

// v2WriteVerbs is V2's compiled set of binaries whose invocation constitutes
// a write/mutation of its path targets.
var v2WriteVerbs = map[string]bool{
	"rm": true, "rmdir": true, "mv": true, "cp": true, "dd": true,
	"tee": true, "truncate": true, "chmod": true, "chown": true,
	"ln": true, "shred": true, "rsync": true, "install": true,
	"unlink": true, "srm": true,
}

// v2ProtectedBranches is the compiled protected-branch set; config
// protected_branches are UNION-merged (add-only).
var v2ProtectedBranches = []string{"main", "master"}

// protectedPath is one protected filesystem scope. Reason strings name the
// LABEL, never the raw argument (hygiene: argv can carry secrets-by-accident).
type protectedPath struct {
	label  string
	prefix string // expanded absolute prefix
}

// buildProtectedPaths returns the compiled protected-path set unioned with
// the ADD-ONLY config entries, and whether the user's home directory was
// resolvable. Compiled defaults: ~/.ssh, /etc, the audit-log directory, the
// abysslink config directory, keychain/secret-store paths, and the tailscale
// state directories.
//
// FAIL-CLOSED: when the home directory cannot be resolved, the home-based
// scopes (~/.ssh, keychain, keyring, ~/.config/abysslink) are OMITTED — so
// callers MUST consult the returned homeGrounded flag and escalate/abstain
// rather than treat the shrunken set as authoritative. Silently returning the
// smaller set would let a write into ~/.ssh pass as ALLOW when HOME is unset.
func buildProtectedPaths(extra []string) (paths []protectedPath, homeGrounded bool) {
	var out []protectedPath
	home, homeErr := os.UserHomeDir()
	homeGrounded = homeErr == nil
	if homeGrounded {
		out = append(out,
			protectedPath{"~/.ssh", filepath.Join(home, ".ssh")},
			protectedPath{"keychain", filepath.Join(home, "Library", "Keychains")},
			protectedPath{"keyring", filepath.Join(home, ".local", "share", "keyrings")},
		)
	}
	out = append(out,
		protectedPath{"/etc", "/etc"},
		protectedPath{"keychain", "/Library/Keychains"},
		protectedPath{"tailscale-state", "/var/lib/tailscale"},
		protectedPath{"tailscale-state", "/Library/Tailscale"},
	)
	if logPath, err := audit.DefaultLogPath(); err == nil {
		out = append(out, protectedPath{"audit-log", filepath.Dir(logPath)})
	}
	out = append(out, protectedPath{"abysslink-config", abysslinkConfigDir(home, homeGrounded)})
	for _, e := range extra {
		if e == "" {
			continue
		}
		out = append(out, protectedPath{e, expandTilde(e)})
	}
	return out, homeGrounded
}

// userHomeDir returns the resolved home directory, or "" when unresolvable.
func userHomeDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return ""
}

// abysslinkConfigDir resolves the abysslink config directory
// (XDG_CONFIG_HOME/abysslink, default ~/.config/abysslink).
func abysslinkConfigDir(home string, haveHome bool) string {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "abysslink")
	}
	if haveHome {
		return filepath.Join(home, ".config", "abysslink")
	}
	return "/.config/abysslink"
}

// expandTilde expands a leading ~/ against the user's home directory.
func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
		}
	}
	return p
}

// intent is V2's normalized action model.
type intent struct {
	binary     string
	subcommand string
	flags      []string
	targets    []string
}

// parseIntent builds the normalized {binary, subcommand, flags, targets}
// model from argv. It is deliberately V2's OWN parser — its gaps are the
// failure mode that V1's token scan and V4's stat sweep do not share.
func parseIntent(act action) intent {
	in := intent{binary: act.binary}
	rest := act.args
	// Multi-command binaries: the first non-flag arg is the subcommand.
	multi := map[string]bool{
		"git": true, "kubectl": true, "terraform": true, "tailscale": true,
		"docker": true, "systemctl": true, "brew": true, "apt": true,
	}
	for i, a := range rest {
		if strings.HasPrefix(a, "-") {
			in.flags = append(in.flags, a)
			continue
		}
		if in.subcommand == "" && multi[act.binary] {
			in.subcommand = a
			continue
		}
		// dd-style key=value targets.
		if act.binary == "dd" && (strings.HasPrefix(a, "of=") || strings.HasPrefix(a, "if=")) {
			if strings.HasPrefix(a, "of=") {
				in.targets = append(in.targets, strings.TrimPrefix(a, "of="))
			}
			continue
		}
		_ = i
		in.targets = append(in.targets, a)
	}
	return in
}

// policyVerifier is V2: a semantic policy engine over parsed intent plus the
// quorum policy config. INDEPENDENCE from V1: a different representation —
// V1 fails on string tricks, V2 fails on parser gaps, and a policy-relevant
// parse failure degrades to ALLOW@Low (which the lattice escalates), never
// to a confident ALLOW.
type policyVerifier struct {
	protectedPaths    []protectedPath
	protectedBranches []string
	// homeGrounded is false when os.UserHomeDir failed at construction: the
	// home-based protected scopes are then MISSING, so a write that produces no
	// grounded protected hit fails closed (ABSTAIN) instead of ALLOW.
	homeGrounded bool
}

// newPolicyVerifier builds V2 from the ADD-ONLY config lists.
func newPolicyVerifier(extraPaths, extraBranches []string) *policyVerifier {
	branches := append([]string{}, v2ProtectedBranches...)
	for _, b := range extraBranches {
		if b != "" {
			branches = append(branches, b)
		}
	}
	paths, homeGrounded := buildProtectedPaths(extraPaths)
	return &policyVerifier{
		protectedPaths:    paths,
		protectedBranches: branches,
		homeGrounded:      homeGrounded,
	}
}

func (v *policyVerifier) name() string { return verifierPolicyName }

// checkForcePushProtected is V2's parsed model of the protected-branch force-
// push threat V1 scans tokens for — a distinct representation, correlated only
// at the threat level. A leading-'+' push refspec forces the ref update just
// like --force, so it counts as forced too (QG force-push-refspec).
func (v *policyVerifier) checkForcePushProtected(in intent) (Vote, bool) {
	if in.binary != "git" || in.subcommand != "push" {
		return Vote{}, false
	}
	forced := gitForceFlags(in.flags)
	for _, t := range in.targets {
		if isForcedRefspec(t) {
			forced = true
			break
		}
	}
	if !forced {
		return Vote{}, false
	}
	for _, t := range in.targets {
		for _, br := range v.protectedBranches {
			if t == br || strings.HasSuffix(t, ":"+br) || strings.HasSuffix(t, "/"+br) {
				return Vote{
					Verifier:   verifierPolicyName,
					Verdict:    VerdictEscalate,
					Confidence: ConfidenceHigh,
					Tier:       approve.TierCritical,
					Code:       codeForcePushProtected,
					Reason:     "force-push to protected branch (" + br + ")",
				}, true
			}
		}
	}
	return Vote{}, false
}

func (v *policyVerifier) check(_ context.Context, act action) Vote {
	in := parseIntent(act)

	if vote, hit := v.checkForcePushProtected(in); hit {
		return vote
	}

	if !v2WriteVerbs[in.binary] {
		return Vote{Verifier: verifierPolicyName, Verdict: VerdictAllow, Confidence: ConfidenceHigh}
	}

	// Write verb with no parseable target: a policy-relevant parse gap can
	// never yield a confident ALLOW.
	if len(in.targets) == 0 {
		return Vote{
			Verifier:   verifierPolicyName,
			Verdict:    VerdictAllow,
			Confidence: ConfidenceLow,
			Tier:       approve.TierSensitive,
			Code:       codeParseGap,
			Reason:     "write verb with no parseable target",
		}
	}

	worst := Vote{Verifier: verifierPolicyName, Verdict: VerdictAllow, Confidence: ConfidenceHigh}
	for _, t := range in.targets {
		vote, relevant := v.checkTarget(t)
		if relevant && voteMoreRestrictive(vote, worst) {
			worst = vote
		}
	}
	// FAIL-CLOSED: if the home directory was unresolvable at construction, the
	// home-based protected scopes (~/.ssh, keychain, keyring, config) were
	// never in the set — a write that produced no grounded protected hit might
	// still be landing in one of them, so ABSTAIN (⇒ lattice escalates) instead
	// of returning a confident ALLOW.
	if !v.homeGrounded && effectiveOutcome(worst) == OutcomeAllow {
		return Vote{
			Verifier: verifierPolicyName,
			Verdict:  VerdictAbstain,
			Tier:     approve.TierSensitive,
			Reason:   "home directory unresolved — protected-path check ungrounded",
		}
	}
	return worst
}

// checkTarget classifies one parsed write target against the policy.
func (v *policyVerifier) checkTarget(t string) (Vote, bool) {
	// Ambiguity rules fire BEFORE resolution: `..` traversal and globs make
	// the true target unknowable to a parser (ALLOW@Low ⇒ lattice escalates).
	if strings.Contains(t, "..") {
		return Vote{
			Verifier:   verifierPolicyName,
			Verdict:    VerdictAllow,
			Confidence: ConfidenceLow,
			Tier:       approve.TierSensitive,
			Code:       codeAmbiguousScope,
			Reason:     "parent-traversal path reference",
		}, true
	}
	if hasNonASCII(t) {
		return Vote{
			Verifier:   verifierPolicyName,
			Verdict:    VerdictAllow,
			Confidence: ConfidenceLow,
			Tier:       approve.TierSensitive,
			Code:       codeNonASCIIPath,
			Reason:     "non-ASCII path reference (possible homoglyph)",
		}, true
	}

	expanded := expandTilde(t)
	glob := strings.ContainsAny(t, "*?[")
	abs, err := filepath.Abs(globLiteralPrefix(expanded))
	if err != nil {
		return Vote{
			Verifier:   verifierPolicyName,
			Verdict:    VerdictAllow,
			Confidence: ConfidenceLow,
			Tier:       approve.TierSensitive,
			Code:       codeParseGap,
			Reason:     "unresolvable target path",
		}, true
	}

	for _, pp := range v.protectedPaths {
		if pathUnder(abs, pp.prefix) || pathUnder(pp.prefix, abs) {
			if glob {
				return Vote{
					Verifier:   verifierPolicyName,
					Verdict:    VerdictAllow,
					Confidence: ConfidenceLow,
					Tier:       approve.TierSensitive,
					Code:       codeAmbiguousScope,
					Reason:     "glob into protected scope (" + pp.label + ")",
				}, true
			}
			return Vote{
				Verifier:   verifierPolicyName,
				Verdict:    VerdictEscalate,
				Confidence: ConfidenceHigh,
				Tier:       approve.TierCritical,
				Code:       codeProtectedPathWrite,
				Reason:     "write to protected path (" + pp.label + ")",
			}, true
		}
	}
	return Vote{}, false
}

// voteMoreRestrictive reports whether a should replace b as the verifier's
// single reported vote (higher effective outcome, then higher tier).
func voteMoreRestrictive(a, b Vote) bool {
	ea, eb := effectiveOutcome(a), effectiveOutcome(b)
	if ea != eb {
		return ea > eb
	}
	return a.Tier > b.Tier
}

// pathUnder reports whether p equals prefix or lies underneath it.
func pathUnder(p, prefix string) bool {
	if prefix == "" || p == "" {
		return false
	}
	return p == prefix || strings.HasPrefix(p, prefix+string(filepath.Separator))
}

// globLiteralPrefix returns the literal prefix of a glob pattern (everything
// before the first metacharacter), so "…/.ssh/*" still resolves into ~/.ssh.
func globLiteralPrefix(p string) string {
	i := strings.IndexAny(p, "*?[")
	if i < 0 {
		return p
	}
	// Trim back to the last separator so the prefix is a real directory.
	cut := p[:i]
	if j := strings.LastIndex(cut, string(filepath.Separator)); j >= 0 {
		return cut[:j+1]
	}
	return cut
}

// hasNonASCII reports whether s contains any rune outside printable ASCII.
func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}
