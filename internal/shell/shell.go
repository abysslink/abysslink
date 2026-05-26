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

// Runner executes external commands. All code outside internal/shell must call
// through this interface — never import os/exec directly.
type Runner interface {
	// Run executes name with args, capturing stdout and stderr.
	Run(ctx context.Context, name string, args ...string) (Result, error)
	// RunWithStdin executes name with args, wiring stdin to the provided reader.
	// Use this when a secret must be delivered via stdin instead of argv.
	RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (Result, error)
}
