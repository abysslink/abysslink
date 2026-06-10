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
	"context"
	"io"
)

// Result holds the captured output and exit code of a completed command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Ok reports whether the command exited successfully (exit code 0).
//
// ExecRunner.Run returns err == nil for a process that started and exited
// non-zero — the failure is carried in Result.ExitCode. Callers MUST check
// both the returned error AND Ok(); checking only the error silently treats
// failed commands as successes (the C3/C4 bug class). Prefer:
//
//	res, err := runner.Run(ctx, ...)
//	if err != nil || !res.Ok() { /* handle failure */ }
func (r Result) Ok() bool { return r.ExitCode == 0 }

// Runner executes external commands. All code outside internal/shell must call
// through this interface — never import os/exec directly.
type Runner interface {
	// Run executes name with args, capturing stdout and stderr.
	Run(ctx context.Context, name string, args ...string) (Result, error)
	// RunWithStdin executes name with args, wiring stdin to the provided reader.
	// Use this when a secret must be delivered via stdin instead of argv.
	RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (Result, error)
	// RunInteractive executes name with args wired directly to the parent
	// process's stdin/stdout/stderr (inheriting the terminal). Use it for
	// commands that need a live TTY — interactive auth flows such as
	// `tailscale up`, which prints a login URL, opens a browser, and blocks
	// until the user authenticates. Output is NOT captured; only the exit
	// status is returned.
	RunInteractive(ctx context.Context, name string, args ...string) error
	// RunWithEnv executes name with args, merging env (KEY=VALUE pairs) into the
	// inherited process environment. Use when a subprocess spawns git or other
	// tools that need environment overrides (e.g. GIT_TERMINAL_PROMPT=0) to
	// prevent interactive credential prompts.
	RunWithEnv(ctx context.Context, env map[string]string, name string, args ...string) (Result, error)
	// RunStream executes name with args and returns a Stream handle over the
	// process's stdout, one bounded line at a time. Use this for long-lived
	// line-oriented protocols such as tmux control mode. The returned Stream
	// is one process lifetime; callers own reconnect (D-34).
	RunStream(ctx context.Context, name string, args ...string) (*Stream, error)
}
