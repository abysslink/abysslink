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

package cli

import "fmt"

// Exit code constants documented here and in --help (root.go Long + doctor/up help text):
//
//	0  — OK: all checks passed; no action needed.
//	1  — Error/Warning: one or more warnings found; review recommended but system operable.
//	2  — Fatal: one or more fatal issues found; system is fail-closed or unsafe to use.
const (
	exitCodeOK    = 0 // OK — all checks passed.
	exitCodeError = 1 // Error/Warning — warnings present; review recommended.
	exitCodeFatal = 2 // Fatal — fail-closed or fatal issue; system is not safe to use.
)

// exitError carries a process exit code. Returned from cobra RunE functions to
// signal a specific exit code without calling os.Exit directly, which bypasses
// defer chains and makes unit testing impossible.
//
// When err is nil the command has already printed its own diagnostics and
// Execute only propagates the code (the doctor/status pattern). When err is
// non-nil, Execute renders it through the central error path before exiting —
// this is how fail-closed `up` gates report exit 2 with a visible message.
type exitError struct {
	code int
	err  error // optional underlying error; rendered by Execute when non-nil
}

func (e *exitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit %d", e.code)
}
func (e *exitError) ExitCode() int { return e.code }
func (e *exitError) Unwrap() error { return e.err }
