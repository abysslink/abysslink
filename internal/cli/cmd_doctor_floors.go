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

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// SUPL-04 bespoke doctor floor detectors. Unlike the data-driven versionFloors
// table, these two checks need behavior beyond a single `--version` probe:
//
//   - tailscale-statedir (FATAL): when Tailnet Lock is enabled, tailscaled MUST
//     persist its signing state to a statedir or Lock's signature checks are not
//     enforced — a real spoofing regression. FATAL fail-closed, consistent with
//     the immutable Tailnet-Lock-on default (never weakened).
//   - openssh-version / openssh-pqkex (WARN): below OpenSSH 10.0 or missing the
//     mlkem768x25519-sha256 post-quantum KEX is advisory only — mosh provides a
//     working fallback transport (CONTEXT: never FATAL).
//
// All exec goes through shell.Runner (CLAUDE.md hard rule — no os/exec, no
// sh -c). Every probe failure degrades to WARN (fail-honest), never a silent OK.

// opensshPQKexAlgo is the post-quantum key-exchange algorithm OpenSSH 10.0
// ships by default; its presence in `ssh -Q kex` is the PQ-KEX advisory floor.
const opensshPQKexAlgo = "mlkem768x25519-sha256"

// opensshMinVer is the OpenSSH version floor (WARN below — mosh fallback).
const opensshMinVer = "10.0"

// tailscaleLockStatus is the subset of `tailscale lock status --json` consumed
// by the statedir detector. It mirrors internal/modules/lock.lockStatus; kept
// local to avoid a cli->modules/lock import for a single bool field.
type tailscaleLockStatus struct {
	Enabled bool `json:"Enabled"`
}

// tailscaledStatedirPresent reports whether tailscaled persists its state to a
// statedir. It is a package var so tests can inject a deterministic result
// without touching the host filesystem. The default implementation checks the
// TS_STATE_DIR env var and the well-known on-disk state paths; the runner is
// accepted for parity with other detectors and future flag-probing needs.
var tailscaledStatedirPresent = func(_ context.Context, _ shell.Runner) bool {
	if dir := os.Getenv("TS_STATE_DIR"); dir != "" {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return true
		}
	}
	// Well-known tailscaled state paths across the supported platforms (Linux
	// systemd default and macOS). Existence of the persisted state file proves
	// tailscaled runs with a statedir.
	for _, p := range []string{
		"/var/lib/tailscale/tailscaled.state",
		"/var/lib/tailscale",
		"/Library/Tailscale/tailscaled.state",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// tailscaleStatedirFinding returns the tailscale-statedir doctor finding.
// FATAL when Tailnet Lock is enabled but tailscaled runs without a statedir;
// OK when Lock is off or a statedir is present; WARN when the lock status
// cannot be probed (fail-honest — never a silent OK).
func tailscaleStatedirFinding(ctx context.Context, runner shell.Runner) modules.Finding {
	const check = "tailscale-statedir"

	res, err := runner.Run(ctx, "tailscale", "lock", "status", "--json")
	if err != nil || res.ExitCode != 0 {
		return modules.Finding{
			Module:   "tailscale",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "tailscale-statedir: could not query Tailnet Lock status (tailscale lock status --json failed) — Lock-statedir posture unknown; ensure tailscaled is running then re-run abysslink doctor",
		}
	}

	var status tailscaleLockStatus
	if jerr := json.Unmarshal([]byte(res.Stdout), &status); jerr != nil {
		return modules.Finding{
			Module:   "tailscale",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "tailscale-statedir: could not parse Tailnet Lock status JSON — Lock-statedir posture unknown",
		}
	}

	if !status.Enabled {
		return modules.Finding{
			Module:   "tailscale",
			Check:    check,
			Severity: modules.SeverityOK,
			Message:  "tailscale-statedir: Tailnet Lock is not enabled — statedir persistence not required",
		}
	}

	if !tailscaledStatedirPresent(ctx, runner) {
		return modules.Finding{
			Module:   "tailscale",
			Check:    check,
			Severity: modules.SeverityFatal,
			Message:  "tailscale-statedir: Tailnet Lock is ENABLED but tailscaled has no statedir (no TS_STATE_DIR and no persisted state file) — Lock signing checks are not enforced without persistent state; run tailscaled with --statedir (the fix boundary is Tailscale 1.98.1)",
		}
	}

	return modules.Finding{
		Module:   "tailscale",
		Check:    check,
		Severity: modules.SeverityOK,
		Message:  "tailscale-statedir: Tailnet Lock is enabled and tailscaled persists a statedir — Lock signing checks are enforced",
	}
}

// opensshFloorFindings returns the openssh-version and openssh-pqkex findings.
// Both are WARN advisory (mosh fallback exists per CONTEXT) — never FATAL.
// Probe failures degrade to WARN (fail-honest), never a silent OK.
func opensshFloorFindings(ctx context.Context, runner shell.Runner) []modules.Finding {
	return []modules.Finding{
		opensshVersionFinding(ctx, runner),
		opensshPQKexFinding(ctx, runner),
	}
}

// opensshVersionFinding probes `ssh -V` (version prints to STDERR) and WARNs
// when the version is below the OpenSSH 10.0 floor or cannot be probed.
func opensshVersionFinding(ctx context.Context, runner shell.Runner) modules.Finding {
	const check = "openssh-version"

	res, err := runner.Run(ctx, "ssh", "-V")
	if err != nil || res.ExitCode != 0 {
		return modules.Finding{
			Module:   "ssh",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "openssh-version: could not probe ssh version (ssh -V failed) — version unknown; install OpenSSH >= 10.0 for post-quantum KEX (mosh remains a working fallback)",
		}
	}

	// ssh -V prints to stderr; parse the combined stream with the package-level
	// versionRe (no new regex — D-09).
	ver := versionRe.FindString(res.Stdout + res.Stderr)
	if ver == "" {
		return modules.Finding{
			Module:   "ssh",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "openssh-version: could not parse a version from ssh -V output — version unknown (mosh remains a working fallback)",
		}
	}

	if semverLT(normalizeFloorVersion(ver), opensshMinVer) {
		return modules.Finding{
			Module:   "ssh",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "openssh-version: OpenSSH " + ver + " is below v" + opensshMinVer + " — upgrade for post-quantum key exchange; advisory only (mosh remains a working fallback)",
		}
	}

	return modules.Finding{
		Module:   "ssh",
		Check:    check,
		Severity: modules.SeverityOK,
		Message:  "openssh-version: OpenSSH " + ver + " meets the v" + opensshMinVer + " floor",
	}
}

// opensshPQKexFinding probes `ssh -Q kex` and WARNs when the post-quantum KEX
// mlkem768x25519-sha256 is absent or the probe cannot run.
func opensshPQKexFinding(ctx context.Context, runner shell.Runner) modules.Finding {
	const check = "openssh-pqkex"

	res, err := runner.Run(ctx, "ssh", "-Q", "kex")
	if err != nil || res.ExitCode != 0 {
		return modules.Finding{
			Module:   "ssh",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "openssh-pqkex: could not probe ssh key-exchange algorithms (ssh -Q kex failed) — PQ-KEX support unknown; advisory only (mosh remains a working fallback)",
		}
	}

	if !strings.Contains(res.Stdout, opensshPQKexAlgo) {
		return modules.Finding{
			Module:   "ssh",
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "openssh-pqkex: ssh does not list " + opensshPQKexAlgo + " — post-quantum key exchange unavailable; upgrade OpenSSH to >= 10.0 (advisory; mosh remains a working fallback)",
		}
	}

	return modules.Finding{
		Module:   "ssh",
		Check:    check,
		Severity: modules.SeverityOK,
		Message:  "openssh-pqkex: " + opensshPQKexAlgo + " post-quantum key exchange is available",
	}
}
