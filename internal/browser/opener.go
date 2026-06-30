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

package browser

import (
	"context"
	"fmt"

	"github.com/abysslink/abysslink/internal/shell"
)

// OpenURL opens url in the system browser. Returns an error if no browser opener
// is found on PATH or if the opener exits non-zero.
// runner is used for the actual exec so tests can inject a mock (shell.LookPath is
// a PATH probe that does not go through the runner). ctx is the caller's
// cancellable context (CLI-10 — never context.Background()).
//
// Security: OpenURL NEVER imports os/exec or pkg/browser (D-06 IMMUTABLE).
// The interactive() gate is the caller's responsibility in internal/cli (D-08).
func OpenURL(ctx context.Context, runner shell.Runner, url string) error {
	switch {
	case shell.LookPath("open"):
		res, err := runner.Run(ctx, "open", url) // macOS
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("open %s: exit %d", url, res.ExitCode)
		}
		return nil
	case shell.LookPath("xdg-open"):
		res, err := runner.Run(ctx, "xdg-open", url) // Linux
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("xdg-open %s: exit %d", url, res.ExitCode)
		}
		return nil
	}
	return fmt.Errorf("no browser opener found (tried: open, xdg-open)")
}
