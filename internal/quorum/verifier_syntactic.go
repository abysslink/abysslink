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
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/approve"
)

// verifierSyntacticName is V1's canonical name.
const verifierSyntacticName = "V1 syntactic"

// V1 rule codes (see ShippedRuleTiers for the override registry).
const (
	codeRmRoot               = "rm-root"
	codeForkBomb             = "fork-bomb"
	codeMkfs                 = "mkfs"
	codeDDBlockDevice        = "dd-block-device"
	codeDiskutilErase        = "diskutil-erase"
	codeForcePushProtected   = "force-push-protected"
	codeForcePush            = "force-push"
	codeDropTable            = "drop-table"
	codeShred                = "shred"
	codeRecursiveChmodSystem = "recursive-chmod-system"
	codeRmRecursiveForce     = "rm-recursive-force"
	codeGitResetHard         = "git-reset-hard"
	codeGitCleanForce        = "git-clean-force"
	codeGitCheckoutDot       = "git-checkout-dot"
	codeRsyncDelete          = "rsync-delete"
	codeFindDelete           = "find-delete"
	codeKubectlDelete        = "kubectl-delete"
	codeTerraformDestroy     = "terraform-destroy"
	codePipeToShell          = "pipe-to-shell"
	codeDecodeAndExec        = "decode-and-exec"
	codeExtraPattern         = "extra-pattern"
	// codeOpaqueCommand is the escalate-by-default net for an interpreter/
	// wrapper payload V1 cannot verify statically (python -c "…", a wrapper we
	// could not fully decompose). It only ever UPGRADES an otherwise-confident
	// ALLOW to ESCALATE — a stronger rule (DENY or a more specific escalate)
	// always wins.
	codeOpaqueCommand = "opaque-command"
)

// v1ProtectedBranchTokens is V1's COMPILED protected-branch token set. V1
// consumes only the literal token stream; config protected_branches feed V2's
// policy model, keeping the two input signals independent.
var v1ProtectedBranchTokens = []string{"main", "master"}

// systemPrefixes are the system paths a recursive chmod/chown escalates on.
var systemPrefixes = []string{
	"/etc", "/usr", "/bin", "/sbin", "/var", "/lib", "/boot",
	"/System", "/Library",
}

// synRule is one V1 pattern-table entry: a deterministic predicate over the
// raw argv token stream plus resolved binary basename — nothing else.
type synRule struct {
	code    string
	verdict Verdict
	tier    approve.TierLevel
	reason  string
	match   func(bin string, args []string) bool
}

// synRules is the shipped pattern table, ordered most-severe-first: the first
// match wins, so a DENY shape is never reported as its milder cousin.
var synRules = []synRule{
	// ---- DENY: un-askable catastrophes ----------------------------------
	{codeRmRoot, VerdictDeny, approve.TierCritical, "recursive force remove of filesystem root or home", matchRmRoot},
	{codeForkBomb, VerdictDeny, approve.TierCritical, "fork bomb", matchForkBomb},
	{codeMkfs, VerdictDeny, approve.TierCritical, "filesystem format (mkfs)", func(bin string, _ []string) bool {
		return strings.HasPrefix(bin, "mkfs")
	}},
	{codeDDBlockDevice, VerdictDeny, approve.TierCritical, "dd write to a block device", func(bin string, args []string) bool {
		if bin != "dd" {
			return false
		}
		for _, a := range args {
			if strings.HasPrefix(a, "of=/dev/") {
				return true
			}
		}
		return false
	}},
	{codeDiskutilErase, VerdictDeny, approve.TierCritical, "disk erase (diskutil)", func(bin string, args []string) bool {
		return bin == "diskutil" && (containsToken(args, "eraseDisk") || containsToken(args, "eraseVolume") || containsToken(args, "zeroDisk"))
	}},

	// ---- ESCALATE @ Critical --------------------------------------------
	{codeForcePushProtected, VerdictEscalate, approve.TierCritical, "force-push to protected branch", matchForcePushProtected},
	{codeDropTable, VerdictEscalate, approve.TierCritical, "SQL DROP/TRUNCATE statement", matchDropTable},
	{codeShred, VerdictEscalate, approve.TierCritical, "shred (unrecoverable overwrite)", func(bin string, _ []string) bool {
		return bin == "shred"
	}},
	{codeRecursiveChmodSystem, VerdictEscalate, approve.TierCritical, "recursive chmod/chown on a system prefix", matchRecursiveChmodSystem},

	// ---- ESCALATE @ Sensitive -------------------------------------------
	{codeForcePush, VerdictEscalate, approve.TierSensitive, "force-push", matchForcePush},
	{codeRmRecursiveForce, VerdictEscalate, approve.TierSensitive, "recursive force remove", func(bin string, args []string) bool {
		return bin == "rm" && hasRecursive(args) && hasForce(args)
	}},
	{codeGitResetHard, VerdictEscalate, approve.TierSensitive, "git reset --hard", func(bin string, args []string) bool {
		return bin == "git" && containsToken(args, "reset") && containsToken(args, "--hard")
	}},
	{codeGitCleanForce, VerdictEscalate, approve.TierSensitive, "git clean (force)", func(bin string, args []string) bool {
		return bin == "git" && containsToken(args, "clean") && hasForce(args)
	}},
	{codeGitCheckoutDot, VerdictEscalate, approve.TierSensitive, "git checkout -- . (discard work tree)", func(bin string, args []string) bool {
		return bin == "git" && containsToken(args, "checkout") && containsToken(args, ".")
	}},
	{codeRsyncDelete, VerdictEscalate, approve.TierSensitive, "rsync --delete", func(bin string, args []string) bool {
		if bin != "rsync" {
			return false
		}
		for _, a := range args {
			if strings.HasPrefix(a, "--delete") {
				return true
			}
		}
		return false
	}},
	{codeFindDelete, VerdictEscalate, approve.TierSensitive, "find -delete", func(bin string, args []string) bool {
		return bin == "find" && containsToken(args, "-delete")
	}},
	{codeKubectlDelete, VerdictEscalate, approve.TierSensitive, "kubectl delete", func(bin string, args []string) bool {
		return bin == "kubectl" && containsToken(args, "delete")
	}},
	{codeTerraformDestroy, VerdictEscalate, approve.TierSensitive, "terraform destroy", func(bin string, args []string) bool {
		return bin == "terraform" && (containsToken(args, "destroy") || containsToken(args, "-destroy"))
	}},
	{codePipeToShell, VerdictEscalate, approve.TierSensitive, "pipe-to-shell indicator", matchPipeToShell},
	{codeDecodeAndExec, VerdictEscalate, approve.TierSensitive, "decode-and-exec indicator", matchDecodeAndExec},
}

// syntacticVerifier is V1: a deterministic pattern lexer over irreversibility
// shapes in the raw argv token stream. INDEPENDENCE: it consumes only the
// literal token stream; its failure mode is novel obfuscation/encoding —
// disjoint from V2's parser gaps, V3's clock, and V4's filesystem.
type syntacticVerifier struct {
	// extraPatterns are ADD-ONLY config substrings (quorum.extra_patterns),
	// forced to tier ≥ Sensitive.
	extraPatterns []string
}

func (v *syntacticVerifier) name() string { return verifierSyntacticName }

func (v *syntacticVerifier) check(_ context.Context, act action) Vote {
	// Classify every EFFECTIVE command, not just argv[0]: a catastrophe cloaked
	// behind a privilege/exec wrapper or a shell interpreter -c payload is
	// re-derived by normalizeCommands and judged here (QG-1). Most-restrictive
	// across candidates wins; the earliest (raw) candidate breaks ties so
	// content-scan codes (pipe-to-shell, decode-and-exec) are preserved.
	cands, opaque := normalizeCommands(act.name, act.args)
	best := Vote{Verifier: verifierSyntacticName, Verdict: VerdictAllow, Confidence: ConfidenceHigh}
	for _, c := range cands {
		for _, r := range synRules {
			if r.match(c.bin, c.args) {
				vote := Vote{
					Verifier:   verifierSyntacticName,
					Verdict:    r.verdict,
					Confidence: ConfidenceHigh,
					Tier:       r.tier,
					Code:       r.code,
					Reason:     r.reason,
				}
				if voteMoreRestrictive(vote, best) {
					best = vote
				}
				break // first (most-severe) rule for this candidate
			}
		}
	}

	// ADD-ONLY extra patterns (tighten-only: forced tier >= Sensitive). Only
	// consulted when no compiled rule already produced a restrictive verdict.
	if effectiveOutcome(best) == OutcomeAllow {
		for _, pat := range v.extraPatterns {
			if pat == "" {
				continue
			}
			for _, tok := range append([]string{act.binary}, act.args...) {
				if strings.Contains(tok, pat) {
					return Vote{
						Verifier:   verifierSyntacticName,
						Verdict:    VerdictEscalate,
						Confidence: ConfidenceHigh,
						Tier:       approve.TierSensitive,
						Code:       codeExtraPattern,
						Reason:     "configured extra pattern matched",
					}
				}
			}
		}
	}

	// Opaque interpreter/wrapper net: an inline code payload we cannot verify
	// statically (python -c "…"), or a wrapper we could not fully decompose,
	// escalates by default rather than passing as a confident ALLOW (QG-1).
	if opaque && effectiveOutcome(best) == OutcomeAllow {
		return Vote{
			Verifier:   verifierSyntacticName,
			Verdict:    VerdictEscalate,
			Confidence: ConfidenceHigh,
			Tier:       approve.TierSensitive,
			Code:       codeOpaqueCommand,
			Reason:     "opaque interpreter/wrapper payload — cannot verify statically",
		}
	}
	return best
}

// hasRecursive reports a recursive flag: -r/-R anywhere in a single-dash
// cluster (split or combined) or --recursive.
func hasRecursive(args []string) bool {
	for _, a := range args {
		if a == "--recursive" {
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			if strings.ContainsAny(a[1:], "rR") {
				return true
			}
		}
	}
	return false
}

// hasForce reports a force flag: -f in a single-dash cluster or --force.
func hasForce(args []string) bool {
	for _, a := range args {
		if a == "--force" {
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			if strings.Contains(a[1:], "f") {
				return true
			}
		}
	}
	return false
}

// matchRmRoot detects the un-askable rm class: recursive+force (split-flag or
// combined) with a root-equivalent target, or --no-preserve-root at all. The
// target is NORMALIZED (tilde/$HOME expansion + filepath.Clean) so `/.`, `//`,
// `/*/`, and top-level system prefixes (`/usr`, `/etc`, …) resolve to the same
// un-askable DENY as a bare `/` instead of leaking to the milder
// rm-recursive-force ESCALATE (QG-3).
func matchRmRoot(bin string, args []string) bool {
	if bin != "rm" {
		return false
	}
	if containsToken(args, "--no-preserve-root") {
		return true
	}
	if !hasRecursive(args) || !hasForce(args) {
		return false
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if targetIsRootEquivalent(a) {
			return true
		}
	}
	return false
}

// targetIsRootEquivalent reports whether an rm target resolves to the
// filesystem root, the user's home directory, or a top-level system prefix.
func targetIsRootEquivalent(a string) bool {
	switch a {
	case "/*", "/*/": // filesystem-root glob
		return true
	case "~", "~/", "$HOME", "${HOME}": // bare home refs (even if HOME unresolved)
		return true
	}
	c := filepath.Clean(expandHomeRefs(a))
	if c == "/" {
		return true
	}
	if home := userHomeDir(); home != "" && c == home {
		return true
	}
	for _, p := range systemPrefixes {
		if c == p {
			return true
		}
	}
	return false
}

// expandHomeRefs expands a leading ~, ~/, $HOME, or ${HOME} against the user's
// home directory. We exec binaries directly (no shell), so these tokens would
// reach the binary un-expanded; expanding them here matches operator intent.
func expandHomeRefs(a string) string {
	home := userHomeDir()
	if home == "" {
		return a
	}
	switch {
	case a == "~" || a == "$HOME" || a == "${HOME}":
		return home
	case strings.HasPrefix(a, "~/"):
		return filepath.Join(home, a[2:])
	case strings.HasPrefix(a, "$HOME/"):
		return filepath.Join(home, a[len("$HOME/"):])
	case strings.HasPrefix(a, "${HOME}/"):
		return filepath.Join(home, a[len("${HOME}/"):])
	}
	return a
}

// matchForkBomb detects the classic shell fork-bomb shape in any token.
func matchForkBomb(_ string, args []string) bool {
	for _, a := range args {
		if strings.Contains(a, ":(){") || (strings.Contains(a, ":|:") && strings.Contains(a, "&")) {
			return true
		}
	}
	return false
}

// gitForceFlags reports whether a git argv carries a force indicator: a
// -f/--force/--force-with-lease flag OR a leading-'+' push refspec
// (e.g. `+main:main`, `+refs/heads/main`), which forces the ref update just
// like --force does but is not a dashed flag (QG force-push-refspec).
func gitForceFlags(args []string) bool {
	for _, a := range args {
		if a == "-f" || a == "--force" || a == "--force-with-lease" ||
			strings.HasPrefix(a, "--force-with-lease=") || strings.HasPrefix(a, "--force-if-includes") {
			return true
		}
		if isForcedRefspec(a) {
			return true
		}
	}
	return false
}

// isForcedRefspec reports whether a token is a force-push refspec: a leading
// '+' on the source side of a `+src[:dst]` / `+ref` push argument.
func isForcedRefspec(a string) bool {
	return len(a) > 1 && a[0] == '+' && a[1] != '-'
}

// matchForcePush detects any git force-push shape.
func matchForcePush(bin string, args []string) bool {
	return bin == "git" && containsToken(args, "push") && gitForceFlags(args)
}

// matchForcePushProtected detects a force-push whose token stream touches a
// compiled protected-branch token (main/master), including refspec and
// remote-qualified forms.
func matchForcePushProtected(bin string, args []string) bool {
	if !matchForcePush(bin, args) {
		return false
	}
	for _, a := range args {
		for _, branch := range v1ProtectedBranchTokens {
			if a == branch ||
				strings.HasSuffix(a, "/"+branch) ||
				strings.HasSuffix(a, ":"+branch) ||
				strings.HasPrefix(a, branch+":") {
				return true
			}
		}
	}
	return false
}

// matchDropTable detects SQL destruction statements inside any single arg.
func matchDropTable(_ string, args []string) bool {
	for _, a := range args {
		up := strings.ToUpper(a)
		if strings.Contains(up, "DROP TABLE") || strings.Contains(up, "DROP DATABASE") ||
			strings.Contains(up, "TRUNCATE ") || strings.HasSuffix(up, "TRUNCATE") {
			return true
		}
	}
	return false
}

// matchRecursiveChmodSystem detects recursive chmod/chown on system prefixes.
func matchRecursiveChmodSystem(bin string, args []string) bool {
	if bin != "chmod" && bin != "chown" {
		return false
	}
	if !hasRecursive(args) {
		return false
	}
	for _, a := range args {
		for _, p := range systemPrefixes {
			if a == p || strings.HasPrefix(a, p+"/") {
				return true
			}
		}
	}
	return false
}

// matchPipeToShell detects a curl/wget-pipe-to-shell shape inside one arg
// (the `sh -c "curl … | sh"` staging pattern).
func matchPipeToShell(_ string, args []string) bool {
	for _, a := range args {
		hasFetch := strings.Contains(a, "curl") || strings.Contains(a, "wget") || strings.Contains(a, "http://") || strings.Contains(a, "https://")
		hasPipeShell := strings.Contains(a, "| sh") || strings.Contains(a, "| bash") ||
			strings.Contains(a, "|sh") || strings.Contains(a, "|bash") ||
			strings.Contains(a, "| zsh") || strings.Contains(a, "|zsh")
		if hasFetch && hasPipeShell {
			return true
		}
	}
	return false
}

// matchDecodeAndExec detects decode-and-execute staging indicators inside a
// single arg: base64/hex decode piped to a shell or eval'd.
func matchDecodeAndExec(_ string, args []string) bool {
	for _, a := range args {
		hasDecode := strings.Contains(a, "base64 -d") || strings.Contains(a, "base64 --decode") ||
			strings.Contains(a, "base64 -D") || strings.Contains(a, "xxd -r")
		if !hasDecode {
			continue
		}
		if strings.Contains(a, "|") && (strings.Contains(a, "sh") || strings.Contains(a, "bash") || strings.Contains(a, "eval")) {
			return true
		}
		if strings.Contains(a, "eval") || strings.Contains(a, "$(") {
			return true
		}
	}
	return false
}
