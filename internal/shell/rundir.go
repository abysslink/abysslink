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
)

// DirRunner is an optional Runner capability for interactive commands that must
// execute in a specific working directory. `ssh-keygen -K` writes resident-key
// handle files to its CWD only (no -f/-o destination flag exists for it), so the
// hardware-key enclave provider needs a controlled directory to guarantee the
// "already exists / Overwrite (y/n)?" blocker cannot fire and to fail-closed
// count the produced files.
//
// This follows the platform optional-capability precedent (platform.AppFirewall
// etc.): callers type-assert, and a Runner without the capability is refused —
// never worked around by chdir'ing the parent process.
type DirRunner interface {
	// RunInteractiveDir behaves exactly like Runner.RunInteractive (TTY
	// inherited, output not captured) but runs the command with dir as its
	// working directory.
	RunInteractiveDir(ctx context.Context, dir, name string, args ...string) error
}

// RunInteractiveDir executes name with args wired to the parent's stdin/stdout/
// stderr (same as RunInteractive) with the child's working directory set to dir.
func (r *ExecRunner) RunInteractiveDir(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: shell.Runner is the project-sanctioned exec abstraction (CLAUDE.md); argv is exec'd directly with no shell, never sh -c
	cmd.Dir = dir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
