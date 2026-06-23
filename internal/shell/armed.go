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
	"os"
	"os/exec"
	"syscall"
)

// ArmedHandle is returned by RunArmed. It carries the process group id and a
// channel that closes when the process exits (normal or killed). The pgid is
// used by the budget watcher to signal the whole process group via
// syscall.Kill(-pgid, sig) (KILL-03, D-07).
type ArmedHandle struct {
	// PGID is the process-group id of the spawned process. On linux and darwin,
	// when SysProcAttr{Setpgid:true} is set, the kernel assigns pgid = pid of
	// the leader process, so PGID == cmd.Process.Pid (A1 in RESEARCH.md).
	// Always positive; assert pgid > 0 before syscall.Kill(-pgid, ...) to
	// avoid the double-negative pitfall (Pitfall 3 in RESEARCH.md).
	PGID int

	// Done closes when the process exits (normal or killed). The goroutine
	// spawned by RunArmed calls cmd.Wait() then closes this channel. Callers
	// should select on Done to detect process exit without blocking.
	Done <-chan struct{}

	// Wait blocks until the process exits and returns the exit error (nil for
	// a zero exit code). It may be called at most once after Done closes;
	// subsequent calls return the cached result immediately.
	Wait func() error
}

// ArmedRunner is the interface satisfied by ExecRunner for the arm spawn path.
// It is NOT embedded in or added to shell.Runner — the Runner interface is
// stable and must not require updating MockRunner, Gated, or test doubles
// (KILL-03, D-07, RESEARCH.md Pattern 1). cmd_arm.go depends on this narrow
// interface so tests can inject a fake that returns a synthetic ArmedHandle
// with a controllable Done channel and PGID.
type ArmedRunner interface {
	RunArmed(ctx context.Context, name string, args ...string) (*ArmedHandle, error)
}

// ArmedMinimalRunner is the OPTIONAL env-minimized sibling of ArmedRunner. A
// runner that implements it can spawn the armed agent with the B10-minimized
// environment (buildMinimalEnv) instead of the full os.Environ(). It is a
// SEPARATE, optional interface — ArmedRunner's signature is unchanged — so
// existing RunArmed-only fakes (MockRunner, gate.Gated, arm test doubles) stay
// valid and are not forced to implement env minimization (WR-01 / B10).
type ArmedMinimalRunner interface {
	RunArmedMinimal(ctx context.Context, name string, args ...string) (*ArmedHandle, error)
}

// RunArmed spawns name with args in a new process group (SysProcAttr.Setpgid=true)
// and returns an ArmedHandle carrying the PGID and a channel closed on process exit.
//
// IMPORTANT: RunArmed uses exec.Command (NOT exec.CommandContext). This is an
// explicit deviation from the exec.go pattern. exec.CommandContext sends SIGKILL
// directly to the process on ctx cancellation, bypassing the budget ladder
// (Pitfall 1 in RESEARCH.md). Context cancellation is managed manually by the
// budget watcher via syscall.Kill(-pgid, ...) through the escalation ladder.
//
// Stdin/stdout/stderr are wired to the parent process so the armed command
// runs interactively (mirrors RunInteractive). cmd_arm.go passes asciinema
// as the actual armed process, which handles its own pty allocation.
//
// RunArmed is on ExecRunner only (not on the Runner interface) because
// SysProcAttr changes spawn semantics incompatible with the generic Runner
// contract. internal/shell is the only package allowed to import os/exec
// (CLAUDE.md hard rule).
//
//nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
func (r *ExecRunner) RunArmed(ctx context.Context, name string, args ...string) (*ArmedHandle, error) {
	// MUST be exec.Command, NOT exec.CommandContext — see Pitfall 1 in RESEARCH.md.
	// ctx is unused here intentionally: the budget watcher manages cancellation
	// via syscall.Kill(-pgid, ...) to preserve the escalation ladder (D-07).
	_ = ctx                            // acknowledged: ctx cancellation handled externally via pgid kill
	cmd := exec.Command(name, args...) //nolint:gosec // G204: shell.Runner sanctioned exec path
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Inherit stdin/stdout/stderr so the armed command runs interactively.
	// asciinema (the typical armed process) handles pty allocation itself.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()

	return &ArmedHandle{
		// On linux and darwin, pgid == pid when Setpgid=true (A1 in RESEARCH.md).
		// cmd.Process.Pid is always positive after a successful Start().
		PGID: cmd.Process.Pid,
		Done: done,
		Wait: func() error { <-done; return waitErr },
	}, nil
}

// RunArmedMinimal is the env-MINIMIZED sibling of RunArmed (WR-01 / B10). It is
// identical to RunArmed in EVERY respect — exec.Command (NOT CommandContext, so
// the budget ladder owns cancellation via syscall.Kill, Pitfall 1), Setpgid for
// the process group, inherited stdin/stdout/stderr, the same ArmedHandle
// contract — EXCEPT it sets cmd.Env = buildMinimalEnv(os.Environ()) so the armed
// child receives ONLY the B10 allowlist (PATH/HOME plus the curated
// keyless-supply-chain set), not the full parent environment. This keeps
// secret-bearing parent vars (API keys, ntfy topic credentials) out of the
// untrusted armed-agent process.
//
// It is the opt-in production target for B10 env minimization, reached only when
// the operator sets Budget.MinimizeAgentEnv (the arm path then prefers this over
// RunArmed). Default behavior (RunArmed) is unchanged so agents that legitimately
// read provider keys from their environment are unaffected unless opted in.
//
//nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
func (r *ExecRunner) RunArmedMinimal(ctx context.Context, name string, args ...string) (*ArmedHandle, error) {
	// MUST be exec.Command, NOT exec.CommandContext — see Pitfall 1 in RESEARCH.md.
	_ = ctx                            // acknowledged: ctx cancellation handled externally via pgid kill
	cmd := exec.Command(name, args...) //nolint:gosec // G204: shell.Runner sanctioned exec path
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// B10: the armed child sees ONLY the minimized allowlist, never os.Environ().
	cmd.Env = buildMinimalEnv(os.Environ())
	// Inherit stdin/stdout/stderr so the armed command runs interactively.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()

	return &ArmedHandle{
		PGID: cmd.Process.Pid,
		Done: done,
		Wait: func() error { <-done; return waitErr },
	}, nil
}
