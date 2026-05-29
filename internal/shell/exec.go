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
	"io"
	"os"
	"os/exec"
	"strings"
)

// ExecRunner is the production Runner that invokes real binaries via os/exec.
// This is the only file in the codebase allowed to import os/exec.
type ExecRunner struct{}

// Run executes name with args, captures stdout and stderr, and returns the
// Result. A non-zero exit code is surfaced in Result.ExitCode, not as an error.
// An error is returned only when the process cannot be started or the context
// is cancelled before completion.
func (r *ExecRunner) Run(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
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
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec
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
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec
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
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
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
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec
	var stdout, stderr bytes.Buffer
	cmd.Stdin = stdin
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
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
