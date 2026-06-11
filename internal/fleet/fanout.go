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
	"strings"
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

// sshTransportExitCode is the exit code ssh itself returns when the transport
// fails (connection refused, timeout, auth failure, DNS error). Any OTHER
// non-zero exit code came from the REMOTE command — e.g. `abysslink doctor
// --json` intentionally exits 1 on WARN and 2 on FATAL findings (CLI-06) —
// and the rig is still very much reachable with valid stdout.
const sshTransportExitCode = 255

// RigResult is the per-rig outcome from a FanOut call.
// UNREACHABLE is represented as Reachable=false — it is a result VALUE, not a
// returned error, so sibling rigs keep running (SC-2 / Pitfall 1).
//
// Reachable means the SSH TRANSPORT succeeded — the remote abysslink command
// may still have exited non-zero (degraded-but-reachable, T-14-06); its exit
// code is recorded in ExitCode and its stdout is preserved for decoding.
type RigResult struct {
	Rig       config.RigConfig
	Reachable bool
	Stdout    string // raw stdout from remote `abysslink <subcmd> --json`
	ExitCode  int    // remote command's exit code (0 unless Reachable)
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

			// Build the SSH argv: ssh -o BatchMode=yes -o ConnectTimeout=5
			// <hostname> abysslink <subArgs...>. BatchMode prevents ssh from
			// ever blocking on an askpass/password prompt; ConnectTimeout
			// fails fast on a dead host instead of eating the per-rig budget.
			// CLAUDE.md: never sh -c; always discrete argv tokens (T-14-04).
			args := append([]string{
				"-o", "BatchMode=yes",
				"-o", "ConnectTimeout=5",
				rig.Hostname, "abysslink",
			}, subArgs...)
			res, err := runner.Run(rctx, "ssh", args...)

			// Only a transport-level failure marks the rig UNREACHABLE:
			// either Run itself errored (exec/ctx failure) or ssh exited 255
			// (its own connection/auth failure code). Any other non-zero exit
			// is the REMOTE command's — `doctor --json` exits 1/2 BY DESIGN
			// on WARN/FATAL findings — so the rig is degraded-but-reachable
			// and its stdout must be kept for decoding (T-14-06).
			if err != nil || res.ExitCode == sshTransportExitCode {
				results[i] = RigResult{Rig: rig, Reachable: false, ExitCode: res.ExitCode, Err: err}

				if strict {
					// Return an error to errgroup — this cancels gctx and
					// aborts all remaining in-flight rigs (fail-fast).
					// err may be nil here (ssh exited 255 without a Go
					// error); never wrap a nil err (%!w(<nil>)) — surface
					// the exit code and stderr instead.
					if err != nil {
						return fmt.Errorf("rig %q unreachable: %w", rig.Name, err)
					}
					return fmt.Errorf("rig %q unreachable: ssh exited %d: %s",
						rig.Name, res.ExitCode, strings.TrimSpace(res.Stderr))
				}
				// SC-2: return nil so the errgroup does NOT cancel siblings.
				return nil
			}

			results[i] = RigResult{Rig: rig, Reachable: true, Stdout: res.Stdout, ExitCode: res.ExitCode}
			return nil
		})
	}

	// g.Wait() returns the first error returned by a goroutine (non-nil only
	// under --strict). All goroutines have completed when Wait returns.
	return results, g.Wait()
}
