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

package fleet

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"golang.org/x/sync/errgroup"
)

// safeRigName matches rig names that are safe to include in an SSH argv token.
// Only lowercase letters, digits, and hyphens are allowed (defense-in-depth
// against command injection even though Runner uses discrete argv, no sh -c).
var safeRigName = regexp.MustCompile(`^[a-z0-9-]+$`)

// safeHostname matches hostnames that are safe SSH target tokens (T-14-04).
// Requires at least 2 chars (first and last must be alphanumeric), allows
// lowercase letters, digits, hyphens, and dots in the middle. Rejects empty
// strings, leading/trailing hyphens or dots, and any shell-special characters.
var safeHostname = regexp.MustCompile(`^[a-z0-9][a-z0-9\-.]{0,252}[a-z0-9]$`)

// RigResult is the per-rig outcome from a FanOut call.
// UNREACHABLE is represented as Reachable=false — it is a result VALUE, not a
// returned error, so sibling rigs keep running (SC-2 / Pitfall 1).
type RigResult struct {
	Rig       config.RigConfig
	Reachable bool
	Stdout    string // raw stdout from remote `abysslink <subcmd> --json`
	Err       error  // transport / timeout error; kept for caller inspection
}

// FanOut SSHes to every enrolled rig concurrently (one goroutine per rig under
// errgroup), runs `abysslink <subArgs...>` on each, and collects per-rig results.
//
// Correctness contract (SC-2):
//   - An offline / timed-out rig sets Reachable=false and returns nil from g.Go
//     so the errgroup context is NOT cancelled and siblings keep running.
//   - Only when strict==true does the goroutine return a real error, which
//     cancels gctx and aborts remaining in-flight rigs (fail-fast / exit 1).
//
// Per-rig timeout wraps gctx, not the parent ctx (Pitfall 2) so that
// --strict cancellation propagates through the per-rig deadline too.
//
// Rig names and hostnames are validated against safe charsets before use as
// argv tokens (defense-in-depth: T-14-04 command injection).
func FanOut(
	ctx context.Context,
	runner shell.Runner,
	rigs []config.RigConfig,
	perRigTimeout time.Duration,
	strict bool,
	subArgs []string,
) ([]RigResult, error) {
	// Validate all rig names and hostnames before launching any goroutines.
	// Both are used as SSH argv tokens — charset validation is defense-in-depth
	// against command injection even though Runner uses discrete argv (T-14-04).
	for _, rig := range rigs {
		if !safeRigName.MatchString(rig.Name) {
			return nil, fmt.Errorf("invalid rig name %q: only [a-z0-9-] are allowed", rig.Name)
		}
		if !safeHostname.MatchString(rig.Hostname) {
			return nil, fmt.Errorf("invalid rig hostname %q for rig %q: must be a valid DNS name (no spaces, semicolons, or shell metacharacters)", rig.Hostname, rig.Name)
		}
	}

	results := make([]RigResult, len(rigs)) // disjoint indices — no mutex needed

	g, gctx := errgroup.WithContext(ctx) // D-FT-04: errgroup for concurrent fan-out

	for i, rig := range rigs {
		i, rig := i, rig // capture loop variables (safe on Go 1.22+; harmless earlier)

		g.Go(func() error {
			// Per-rig timeout MUST wrap gctx, not the parent ctx (Pitfall 2).
			// This ensures --strict cancellation (which fires on gctx) also
			// interrupts slow rigs.
			rctx, cancel := context.WithTimeout(gctx, perRigTimeout)
			defer cancel()

			// Build the SSH argv: ssh <hostname> abysslink <subArgs...>
			// CLAUDE.md: never sh -c; always discrete argv tokens (T-14-04).
			args := append([]string{rig.Hostname, "abysslink"}, subArgs...)
			res, err := runner.Run(rctx, "ssh", args...)

			if err != nil || res.ExitCode != 0 {
				results[i] = RigResult{Rig: rig, Reachable: false, Err: err}

				if strict {
					// Return an error to errgroup — this cancels gctx and
					// aborts all remaining in-flight rigs (fail-fast).
					return fmt.Errorf("rig %q unreachable: %w", rig.Name, err)
				}
				// SC-2: return nil so the errgroup does NOT cancel siblings.
				return nil
			}

			results[i] = RigResult{Rig: rig, Reachable: true, Stdout: res.Stdout}
			return nil
		})
	}

	// g.Wait() returns the first error returned by a goroutine (non-nil only
	// under --strict). All goroutines have completed when Wait returns.
	return results, g.Wait()
}
