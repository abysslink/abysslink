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

package shell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// maxSubprocessOutput caps stdout+stderr capture per subprocess invocation.
// Tailscale status JSON for a ~1000-node fleet is ~500 KB; 16 MiB is ~32x
// that maximum. Over-limit is a hard error returned from Run (A11 / DOS-01).
const maxSubprocessOutput = 16 * 1024 * 1024 // 16 MiB

// limitedWriter caps writes to cap bytes, then errors. Used to bound
// subprocess stdout/stderr capture without restructuring cmd.Stdout assignment.
// Write errors propagate through cmd.Run() as non-ExitError → returned as
// Result{}, err (A11 / DOS-01).
type limitedWriter struct {
	buf *bytes.Buffer
	cap int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.buf.Len()+len(p) > lw.cap {
		return 0, fmt.Errorf("subprocess output exceeded %d bytes", lw.cap)
	}
	return lw.buf.Write(p)
}

// minimalEnvExact is the allowlist of exact environment-variable names a child
// process spawned via RunMinimal inherits. It is deliberately small (B10 /
// T-32-14): a child binary should see only what it needs, never the parent's
// full os.Environ() (which can carry API keys, tokens, ntfy topic credentials).
//
// The set is curated to keep the keyless supply-chain flows working under
// minimization (Pitfall 5 / T-32-18):
//   - PATH, HOME: every tool needs these to find binaries and a config/home dir.
//   - SSH_AUTH_SOCK: git over SSH and any agent-backed signing.
//   - GIT_TERMINAL_PROMPT: already set to "0" by arm_cmd.go's git calls.
//   - TMPDIR: cosign/gh write transient material under TMPDIR.
//   - HTTPS_PROXY/HTTP_PROXY/NO_PROXY (and lowercase): cosign/gh reach Sigstore
//     and GitHub over HTTPS; corporate proxies must still apply.
//   - GITHUB_TOKEN/GH_TOKEN: `gh attestation verify` authenticates to the API.
//
// This is an ALLOWLIST, not a denylist: a newly-introduced parent var does NOT
// pass through by default (a denylist would leak it). Prefix families that the
// keyless flows need (SIGSTORE_*, XDG_*, etc.) are handled by minimalEnvPrefixes.
var minimalEnvExact = map[string]bool{
	"PATH":                true,
	"HOME":                true,
	"SSH_AUTH_SOCK":       true,
	"GIT_TERMINAL_PROMPT": true,
	"TMPDIR":              true,
	"HTTPS_PROXY":         true,
	"HTTP_PROXY":          true,
	"NO_PROXY":            true,
	"https_proxy":         true,
	"http_proxy":          true,
	"no_proxy":            true,
	"GITHUB_TOKEN":        true,
	"GH_TOKEN":            true,
	"GH_HOST":             true,
}

// minimalEnvPrefixes is the allowed-prefix half of the B10 env allowlist. A var
// whose key starts with one of these prefixes passes through minimization:
//   - SIGSTORE_*: cosign Sigstore endpoint overrides (Rekor/Fulcio/OIDC URLs).
//   - XDG_*: gh/cosign honour XDG base dirs for config/cache/state.
//   - COSIGN_*: cosign experimental/keyless toggles.
//
// Like minimalEnvExact this is strictly an allowlist — only these families pass.
var minimalEnvPrefixes = []string{
	"SIGSTORE_",
	"XDG_",
	"COSIGN_",
}

// buildMinimalEnv filters parent (KEY=VALUE lines, e.g. os.Environ()) down to
// the B10 allowlist: a var passes iff its key is in minimalEnvExact or matches
// a minimalEnvPrefixes entry. Everything else is dropped, so secret-bearing or
// unknown future vars never reach the child by default (allowlist, not denylist).
func buildMinimalEnv(parent []string) []string {
	out := make([]string, 0, len(minimalEnvExact))
	for _, e := range parent {
		k, _, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if minimalEnvExact[k] {
			out = append(out, e)
			continue
		}
		for _, p := range minimalEnvPrefixes {
			if strings.HasPrefix(k, p) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// ExecRunner is the production Runner that invokes real binaries via os/exec.
// internal/shell is the only PACKAGE in the codebase allowed to import
// os/exec (CLAUDE.md hard rule); within it, this file and stream.go are the
// importers.
type ExecRunner struct{}

// Run executes name with args, captures stdout and stderr, and returns the
// Result. A non-zero exit code is surfaced in Result.ExitCode, not as an error.
// An error is returned only when the process cannot be started or the context
// is cancelled before completion.
func (r *ExecRunner) Run(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &stdout, cap: maxSubprocessOutput}
	cmd.Stderr = &limitedWriter{buf: &stderr, cap: maxSubprocessOutput}

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return Result{
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				ExitCode: exitErr.ExitCode(),
			}, nil
		}
		return Result{}, err
	}
	return Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}, nil
}

// RunMinimal executes name with args exactly like Run, but the child receives a
// MINIMIZED environment built from the B10 allowlist (buildMinimalEnv) instead
// of inheriting the parent's full os.Environ() (T-32-14). Use it for child
// processes that do not need the parent's secret-bearing environment — the env
// is reduced to PATH/HOME plus the curated keyless-supply-chain set, so a leaked
// API key / token / ntfy topic credential in the parent never reaches the child.
//
// Run/RunWithEnv keep their full-inheritance semantics so callers that rely on
// the complete environment (or pass explicit overrides) are unaffected; this is
// the surgical, opt-in chokepoint for env minimization.
func (r *ExecRunner) RunMinimal(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
	cmd.Env = buildMinimalEnv(os.Environ())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &stdout, cap: maxSubprocessOutput}
	cmd.Stderr = &limitedWriter{buf: &stderr, cap: maxSubprocessOutput}

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return Result{
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				ExitCode: exitErr.ExitCode(),
			}, nil
		}
		return Result{}, err
	}
	return Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}, nil
}

// RunInteractive executes name with args wired to the parent's stdin/stdout/
// stderr so interactive flows (e.g. `tailscale up` browser login) work with a
// live terminal. Output is not captured.
func (r *ExecRunner) RunInteractive(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunWithEnv executes name with args, replacing the specified key→value pairs in
// the inherited process environment. Keys present in env take precedence over
// any existing value in the inherited environment — duplicates are removed so
// that the new value is the only occurrence (most libc getenv implementations
// return the first match, so appending-only leaves the old value in effect).
func (r *ExecRunner) RunWithEnv(ctx context.Context, env map[string]string, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
	override := make(map[string]bool, len(env))
	for k := range env {
		override[k] = true
	}
	base := os.Environ()
	merged := make([]string, 0, len(base)+len(env))
	for _, e := range base {
		k, _, _ := strings.Cut(e, "=")
		if !override[k] {
			merged = append(merged, e)
		}
	}
	for k, v := range env {
		merged = append(merged, k+"="+v)
	}
	cmd.Env = merged
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &stdout, cap: maxSubprocessOutput}
	cmd.Stderr = &limitedWriter{buf: &stderr, cap: maxSubprocessOutput}

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return Result{
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				ExitCode: exitErr.ExitCode(),
			}, nil
		}
		return Result{}, err
	}
	return Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}, nil
}

// RunWithStdin executes name with args, wiring stdin to the provided reader.
// Use this to deliver secrets to a process without placing them on argv.
func (r *ExecRunner) RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
	var stdout, stderr bytes.Buffer
	cmd.Stdin = stdin
	cmd.Stdout = &limitedWriter{buf: &stdout, cap: maxSubprocessOutput}
	cmd.Stderr = &limitedWriter{buf: &stderr, cap: maxSubprocessOutput}

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return Result{
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				ExitCode: exitErr.ExitCode(),
			}, nil
		}
		return Result{}, err
	}
	return Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}, nil
}

// LookPath reports whether binary is available on PATH.
// It uses exec.LookPath which only consults the filesystem — no subprocess is spawned.
// Use this instead of running `<binary> --version` to probe availability;
// ExecRunner.Run normalises exec.ExitError to (Result, nil) which makes
// exit-code-based availability checks unreliable (see B1 in Phase 26 notes).
// LookPath is a package-level function, not a Runner method, because it is a
// filesystem probe rather than a subprocess execution.
func LookPath(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// ResolvePath resolves name to an absolute binary path via exec.LookPath.
// It is a package-level function, not a Runner method, because it is a
// filesystem probe rather than a subprocess execution. It exists so that
// internal/gate (plan 27-04) can resolve binary paths for the D-39 closure
// hash without importing os/exec — the CLAUDE.md hard rule reserves os/exec
// for internal/shell alone.
func ResolvePath(name string) (string, error) {
	return exec.LookPath(name)
}
