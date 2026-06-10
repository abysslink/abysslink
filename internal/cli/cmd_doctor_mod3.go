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
	"fmt"
	"os"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	atuin "github.com/abysslink/abysslink/internal/modules/atuin"
	sandbox "github.com/abysslink/abysslink/internal/modules/sandbox"
	"github.com/abysslink/abysslink/internal/shell"
)

// mod3DoctorFindings returns the Phase 21 optional-module doctor findings for
// every enabled mod3 module. This plan (21-01) implements the three WoL/upsnap
// findings; subsequent plans extend this function with atuin, sandbox,
// asciinema, and netbird checks (which is why it already accepts ctx and runner
// even though the WoL checks are config-only).
//
// This function is wired into the doctor RunE at cmd_doctor.go (its findings are
// appended to the doctor finding set there). It is also unit-tested directly.
//
// Severity contract (review W7): the structural advisories below (wol-apply-gate,
// atuin-bind, asciinema-rec-warning) are unconditional reminders that fire
// whenever the module is enabled — they probe nothing and detect no actual
// misconfiguration. They are SeverityWarning so a perfectly healthy rig with an
// optional module enabled does not permanently exit 2 ("system is not safe")
// from doctor/CI/--strict runs. FATAL is reserved for probed, genuinely unsafe
// states.
//
// WoL/upsnap findings (emitted only when cfg.Modules.Upsnap.Enabled):
//   - wol-apply-gate (WARN): structural advisory that every WoL send is audited
//     and gated behind --apply; `abysslink wol <rig>` without --apply must send
//     zero UDP packets (HARD FLOOR, T-21-01-01).
//   - upsnap-bind (WARN): if an UpSnap HTTP service is running, it must bind to
//     the tailnet IP only, never 0.0.0.0.
//   - upsnap-no-public (WARN): WoL broadcast stays LAN-local; do not expose any
//     UpSnap HTTP interface to the public internet.
//
// atuin findings (emitted only when cfg.Modules.Atuin.Enabled):
//   - atuin-bind (WARN): sync_address must stay local-only ("") and never point
//     at a public cloud endpoint (T-21-02-02).
//   - atuin-key-backed-up (WARN): the sync key must be backed up in a password
//     manager; the check only os.Stats the key path, never reads its contents.
//
// sandbox findings (emitted only when cfg.Modules.Sandbox.Enabled):
//   - sandbox-landlock-supported (WARN when unsupported, OK when supported):
//     probes the kernel via sandbox.IsLandlockSupported(); Landlock is a
//     Linux-only LSM (kernel >= 5.13), so this is always WARN on macOS and on
//     Linux kernels < 5.13 — the sandbox module is a no-op there (MOD3-03).
//
// asciinema findings (emitted only when cfg.Modules.Asciinema.Enabled):
//   - asciinema-rec-warning (WARN): structural invariant that `abysslink
//     asciinema rec` requires an interactive TTY and shows a non-suppressible
//     credential warning before any recording, with no bypass flag/env-var
//     (T-21-02-01); enforced by TestAsciinemaRec_RequiresInteractiveTTY.
func mod3DoctorFindings(ctx context.Context, cfg *config.Config, _ shell.Runner) []modules.Finding {
	var findings []modules.Finding

	if cfg.Modules.Upsnap.Enabled {
		findings = append(findings,
			modules.Finding{
				Module:   "upsnap",
				Check:    "wol-apply-gate",
				Severity: modules.SeverityWarning,
				Message:  "wol-apply-gate — WoL is enabled; every `abysslink wol --apply` send is audited and gated behind --apply; verify `abysslink wol <rig>` without --apply sends zero UDP packets",
			},
			modules.Finding{
				Module:   "upsnap",
				Check:    "upsnap-bind",
				Severity: modules.SeverityWarning,
				Message:  "upsnap-bind — ensure the UpSnap service (if running) binds to the tailnet IP only, never 0.0.0.0",
			},
			modules.Finding{
				Module:   "upsnap",
				Check:    "upsnap-no-public",
				Severity: modules.SeverityWarning,
				Message:  "upsnap-no-public — WoL broadcast stays LAN-local; do not expose the UpSnap HTTP interface to the public internet",
			},
		)
	}

	if cfg.Modules.Atuin.Enabled {
		findings = append(findings,
			modules.Finding{
				Module:   "atuin",
				Check:    "atuin-bind",
				Severity: modules.SeverityWarning,
				Message:  `atuin-bind — atuin sync_address must not point to a public cloud endpoint; local-only mode is enforced by abysslink config (sync_address = "")`,
			},
			atuinKeyBackedUpFinding(),
		)
	}

	if cfg.Modules.Sandbox.Enabled {
		findings = append(findings, sandboxLandlockSupportedFinding())
	}

	if cfg.Modules.Asciinema.Enabled {
		findings = append(findings,
			modules.Finding{
				Module:   "asciinema",
				Check:    "asciinema-rec-warning",
				Severity: modules.SeverityWarning,
				Message:  "asciinema-rec-warning — structural invariant: `abysslink asciinema rec` requires an interactive TTY and shows a non-suppressible credential warning before any recording; no bypass env-var or flag exists; verified by TestAsciinemaRec_RequiresInteractiveTTY",
			},
		)
	}

	if cfg.Backend.Type == "netbird" {
		findings = append(findings, nbPostureActiveFinding(ctx, cfg))
	}

	return findings
}

// nbPostureActiveFinding builds the nb-posture-active finding (MOD3-05). It is
// emitted only when the NetBird backend is configured.
//
//   - WARN when ABYSSLINK_NB_API_KEY is unset — the API cannot be reached to
//     count posture checks.
//   - WARN when the NetBird API is unreachable or returns an error.
//   - WARN when zero posture checks are configured — peers are unrestricted
//     (informational, not fatal: posture validation is optional).
//   - OK when one or more posture checks are active.
//
// The probe runs through the existing NetBird REST client (no new HTTP client;
// D-05); the API key flows only into the Authorization header (T-21-04-01).
func nbPostureActiveFinding(ctx context.Context, cfg *config.Config) modules.Finding {
	const (
		mod   = "netbird"
		check = "nb-posture-active"
	)

	if os.Getenv("ABYSSLINK_NB_API_KEY") == "" {
		return modules.Finding{
			Module:   mod,
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "nb-posture-active — NetBird backend configured but ABYSSLINK_NB_API_KEY not set; cannot check posture status",
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	checks, err := backend.NetBirdListPostureChecks(probeCtx, cfg)
	if err != nil {
		return modules.Finding{
			Module:   mod,
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "nb-posture-active — could not reach NetBird API to check posture status: " + err.Error(),
		}
	}
	if len(checks) == 0 {
		return modules.Finding{
			Module:   mod,
			Check:    check,
			Severity: modules.SeverityWarning,
			Message:  "nb-posture-active — no NetBird posture checks configured; all peers are unrestricted",
		}
	}
	return modules.Finding{
		Module:   mod,
		Check:    check,
		Severity: modules.SeverityOK,
		Message:  fmt.Sprintf("nb-posture-active — %d posture check(s) active", len(checks)),
	}
}

// atuinKeyBackedUpFinding builds the atuin-key-backed-up WARN finding. It only
// os.Stats the key path to report presence — it never reads the key contents
// (the key is a secret). Both "key present" and "key absent" are WARN states:
// the user must back up the key if present, or generate one if absent.
func atuinKeyBackedUpFinding() modules.Finding {
	keyPath := atuin.KeyPath()
	msg := fmt.Sprintf("atuin-key-backed-up — atuin sync key not found at %s; run `atuin key` after setup to get your backup key", keyPath)
	if _, err := os.Stat(keyPath); err == nil {
		msg = fmt.Sprintf("atuin-key-backed-up — atuin sync key found at %s; back it up with `atuin key` and store it in your password manager", keyPath)
	}
	return modules.Finding{
		Module:   "atuin",
		Check:    "atuin-key-backed-up",
		Severity: modules.SeverityWarning,
		Message:  msg,
	}
}

// sandboxLandlockSupportedFinding builds the sandbox-landlock-supported finding.
// It probes the running kernel via the build-tag-polymorphic
// sandbox.IsLandlockSupported(): WARN when Landlock is unavailable (non-Linux,
// or Linux kernel < 5.13 / Landlock disabled) — the sandbox module is then a
// no-op — and OK when Landlock V1 is available. The probe is a read-only no-op
// kernel call (empty RestrictPaths); it never mutates the process state.
func sandboxLandlockSupportedFinding() modules.Finding {
	if sandbox.IsLandlockSupported() {
		return modules.Finding{
			Module:   "sandbox",
			Check:    "sandbox-landlock-supported",
			Severity: modules.SeverityOK,
			Message:  "sandbox-landlock-supported — Landlock LSM available",
		}
	}
	return modules.Finding{
		Module:   "sandbox",
		Check:    "sandbox-landlock-supported",
		Severity: modules.SeverityWarning,
		Message:  "sandbox-landlock-supported — Landlock LSM not available on this platform (Linux kernel >= 5.13 required); sandbox module is a no-op",
	}
}
