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
	"path/filepath"
	"strings"
	"unicode"
)

// simpleCmd is one normalized (binary-basename, args) CLASSIFICATION CANDIDATE.
// The stage-0 floor and V1 evaluate their rule tables against every candidate,
// so a catastrophe cloaked behind a privilege/exec wrapper (sudo, env, nice,
// timeout, xargs, busybox, ssh, …) or wrapped in a shell interpreter payload
// (sh -c "…") is judged on its EFFECTIVE binary, not on argv[0].
type simpleCmd struct {
	bin  string
	args []string
}

// maxUnwrapDepth guards against pathological wrapper nesting (sudo env nice …).
// Reaching it is treated as opaque → escalate-by-default (fail closed).
const maxUnwrapDepth = 8

// wrapperSpec describes how to strip a privilege/exec wrapper down to the
// effective command it launches.
type wrapperSpec struct {
	// valueFlags are exact single-token flags that consume the FOLLOWING token
	// as their value (so a value is never mistaken for the wrapped command).
	valueFlags map[string]bool
	// skipPositional is the number of leading NON-flag positional arguments the
	// wrapper takes before the command itself (timeout's DURATION, ssh's HOST,
	// chroot's NEWROOT).
	skipPositional int
	// envAssign skips leading KEY=VALUE assignment tokens (env).
	envAssign bool
}

// wrapperSpecs is the compiled privilege/exec-wrapper table. These binaries do
// not perform a mutation themselves — they launch another command that must be
// re-classified. Membership here is deliberately broad: a wrapper we cannot
// fully decompose degrades to escalate-by-default, never to a silent ALLOW.
var wrapperSpecs = map[string]wrapperSpec{
	"sudo": {valueFlags: strSet(
		"-u", "--user", "-g", "--group", "-C", "--close-from", "-p", "--prompt",
		"-r", "--role", "-t", "--type", "-T", "--command-timeout", "-U", "--other-user",
		"-h", "--host", "-R", "--chroot", "-D", "--chdir")},
	"doas":    {valueFlags: strSet("-u", "-C")},
	"env":     {valueFlags: strSet("-u", "--unset", "-C", "--chdir", "-S", "--split-string"), envAssign: true},
	"nice":    {valueFlags: strSet("-n", "--adjustment")},
	"ionice":  {valueFlags: strSet("-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid")},
	"nohup":   {},
	"setsid":  {},
	"stdbuf":  {valueFlags: strSet("-i", "--input", "-o", "--output", "-e", "--error")},
	"timeout": {valueFlags: strSet("-s", "--signal", "-k", "--kill-after"), skipPositional: 1},
	"xargs": {valueFlags: strSet(
		"-a", "--arg-file", "-E", "-e", "--eof", "-I", "-i", "--replace",
		"-L", "-l", "--max-lines", "-n", "--max-args", "-P", "--max-procs",
		"-s", "--max-chars", "-d", "--delimiter")},
	"command":      {},
	"busybox":      {},
	"toybox":       {},
	"ssh":          {valueFlags: strSet("-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"), skipPositional: 1},
	"chroot":       {skipPositional: 1},
	"proxychains":  {valueFlags: strSet("-f")},
	"proxychains4": {valueFlags: strSet("-f")},
	"setpriv":      {valueFlags: strSet("--reuid", "--regid", "--groups", "--inh-caps", "--ambient-caps", "--bounding-set", "--securebits", "--pdeathsig", "--selinux-label", "--apparmor-profile")},
}

// shellBins are POSIX-ish shells whose -c payload is itself a command line that
// must be lexed (not exec'd) so the effective commands become visible.
var shellBins = strSet("sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish", "csh", "tcsh")

// interpreterCodeFlags are the flags that introduce an inline code payload for
// a NON-shell interpreter (python -c, perl -e, ruby -e, node --eval, …). We
// cannot lex those languages, so their presence marks the invocation opaque.
var interpreterCodeFlags = strSet("-c", "-e", "-E", "--eval", "-p", "--print", "--command")

// normalizeCommands expands (name, args) into every effective classification
// candidate and reports whether an OPAQUE interpreter/wrapper payload was
// present. Callers (the floor and V1) run their rule tables against every
// candidate; opaque==true tells V1 to escalate-by-default when nothing stronger
// fired. The raw argv[0] command is always the first candidate, so existing
// content scans (pipe-to-shell, decode-and-exec, fork-bomb) keep matching the
// literal payload string.
func normalizeCommands(name string, args []string) ([]simpleCmd, bool) {
	root := simpleCmd{bin: filepath.Base(name), args: args}
	return expandCommand(root, 0)
}

// expandCommand recursively unwraps wrappers and lexes shell interpreter
// payloads. The wrapper-level command is always retained (its argv still feeds
// the content scanners); the effective/sub commands are appended.
func expandCommand(c simpleCmd, depth int) ([]simpleCmd, bool) {
	if depth > maxUnwrapDepth {
		return []simpleCmd{c}, true // too deep to decompose → fail closed
	}

	// 1. Privilege/exec wrapper: re-derive the launched command and recurse.
	if inner, ok := unwrapWrapper(c); ok {
		sub, opaque := expandCommand(inner, depth+1)
		return append([]simpleCmd{c}, sub...), opaque
	}

	// 2. Shell interpreter with a -c payload: lex it into sub-commands. The
	//    payload is un-exec'd shell text, so treat the invocation as opaque
	//    (escalate-by-default) AND expose the extracted commands for the floor
	//    and V1 to reach a precise DENY when one is a catastrophe.
	if payload, ok := shellPayload(c); ok {
		out := []simpleCmd{c}
		for _, sc := range lexShell(payload) {
			sub, _ := expandCommand(sc, depth+1)
			out = append(out, sub...)
		}
		return out, true
	}

	// 3. Non-shell interpreter code payload: cannot lex → opaque.
	if isOpaqueInterpreter(c) {
		return []simpleCmd{c}, true
	}

	return []simpleCmd{c}, false
}

// unwrapWrapper returns the effective command a privilege/exec wrapper launches
// and true, or a zero value and false when c is not a wrapper (or carries no
// resolvable command).
func unwrapWrapper(c simpleCmd) (simpleCmd, bool) {
	spec, ok := wrapperSpecs[c.bin]
	if !ok {
		return simpleCmd{}, false
	}
	i, skips := 0, spec.skipPositional
	for i < len(c.args) {
		a := c.args[i]
		if a == "--" {
			i++
			break
		}
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			if spec.valueFlags[a] && i+1 < len(c.args) {
				i += 2
			} else {
				i++
			}
			continue
		}
		if spec.envAssign && isEnvAssign(a) {
			i++
			continue
		}
		if skips > 0 {
			skips--
			i++
			continue
		}
		break
	}
	if i >= len(c.args) {
		return simpleCmd{}, false
	}
	return simpleCmd{bin: filepath.Base(c.args[i]), args: c.args[i+1:]}, true
}

// shellPayload returns the -c payload string of a shell invocation and true.
// It recognizes a bare "-c" and single-dash clusters that end in c (bash -lc).
func shellPayload(c simpleCmd) (string, bool) {
	if !shellBins[c.bin] {
		return "", false
	}
	for i, a := range c.args {
		if a == "-c" || (len(a) > 1 && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.HasSuffix(a, "c")) {
			if i+1 < len(c.args) {
				return c.args[i+1], true
			}
		}
	}
	return "", false
}

// isOpaqueInterpreter reports whether c is a NON-shell interpreter carrying an
// inline code payload we cannot safely lex.
func isOpaqueInterpreter(c simpleCmd) bool {
	if !isInterpreterBin(c.bin) {
		return false
	}
	for _, a := range c.args {
		if interpreterCodeFlags[a] {
			return true
		}
	}
	return false
}

// isInterpreterBin reports whether bin is a known non-shell interpreter.
func isInterpreterBin(bin string) bool {
	if strings.HasPrefix(bin, "python") {
		return true
	}
	switch bin {
	case "perl", "ruby", "node", "nodejs", "php", "deno", "bun", "Rscript", "osascript", "lua", "tclsh":
		return true
	}
	return false
}

// lexShell splits a shell command string into simple commands, honoring single
// and double quotes and backslash escapes, and breaking on the command
// separators ; | & and newlines (runs of | or & cover || and &&). It is a
// pragmatic lexer, not a full shell parser: constructs it cannot model degrade
// to spurious-but-harmless candidates, and the opaque escalate-net still fires.
func lexShell(payload string) []simpleCmd {
	var cmds []simpleCmd
	var words []string
	var buf strings.Builder

	flushWord := func() {
		if buf.Len() > 0 {
			words = append(words, buf.String())
			buf.Reset()
		}
	}
	flushCmd := func() {
		flushWord()
		if len(words) > 0 {
			if c, ok := wordsToCmd(words); ok {
				cmds = append(cmds, c)
			}
			words = nil
		}
	}

	runes := []rune(payload)
	for i := 0; i < len(runes); i++ {
		switch r := runes[i]; r {
		case '\'', '"':
			i = scanQuoted(runes, i, &buf)
		case '\\':
			if i+1 < len(runes) {
				i++
				buf.WriteRune(runes[i])
			}
		case ' ', '\t', '\r':
			flushWord()
		case ';', '\n', '|', '&', '(', ')':
			flushCmd()
		default:
			buf.WriteRune(r)
		}
	}
	flushCmd()
	return cmds
}

// scanQuoted consumes a single- or double-quoted segment starting at the quote
// rune runes[start], appending its literal contents to buf, and returns the
// index of the closing quote (or the last index if unterminated). Double-quote
// segments honor backslash escapes; single-quote segments are fully literal.
func scanQuoted(runes []rune, start int, buf *strings.Builder) int {
	quote := runes[start]
	i := start + 1
	for i < len(runes) && runes[i] != quote {
		if quote == '"' && runes[i] == '\\' && i+1 < len(runes) {
			i++
		}
		buf.WriteRune(runes[i])
		i++
	}
	return i
}

// wordsToCmd drops leading KEY=VALUE assignments and returns the effective
// command (basename + args). It returns false when nothing but assignments
// remain.
func wordsToCmd(words []string) (simpleCmd, bool) {
	j := 0
	for j < len(words) && isEnvAssign(words[j]) {
		j++
	}
	if j >= len(words) {
		return simpleCmd{}, false
	}
	return simpleCmd{bin: filepath.Base(words[j]), args: append([]string{}, words[j+1:]...)}, true
}

// isEnvAssign reports whether w is a NAME=VALUE assignment (a leading env var).
func isEnvAssign(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for _, r := range w[:eq] {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// strSet builds a string membership set.
func strSet(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}
