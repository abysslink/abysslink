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

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	atuin "github.com/abysslink/abysslink/internal/modules/atuin"
	"github.com/abysslink/abysslink/internal/shell"
)

// mod3DoctorFindings returns the Phase 21 optional-module doctor findings for
// every enabled mod3 module. This plan (21-01) implements the three WoL/upsnap
// findings; subsequent plans extend this function with atuin, sandbox,
// asciinema, and netbird checks (which is why it already accepts ctx and runner
// even though the WoL checks are config-only).
//
// The function is NOT yet wired into the doctor RunE — that wiring lands in
// Plan 05 to avoid a file conflict. It is unit-tested directly here.
//
// WoL/upsnap findings (emitted only when cfg.Modules.Upsnap.Enabled):
//   - wol-apply-gate (FATAL): structural advisory that every WoL send is audited
//     and gated behind --apply; `abysslink wol <rig>` without --apply must send
//     zero UDP packets (HARD FLOOR, T-21-01-01).
//   - upsnap-bind (WARN): if an UpSnap HTTP service is running, it must bind to
//     the tailnet IP only, never 0.0.0.0.
//   - upsnap-no-public (WARN): WoL broadcast stays LAN-local; do not expose any
//     UpSnap HTTP interface to the public internet.
//
// atuin findings (emitted only when cfg.Modules.Atuin.Enabled):
//   - atuin-bind (FATAL): sync_address must stay local-only ("") and never point
//     at a public cloud endpoint (T-21-02-02).
//   - atuin-key-backed-up (WARN): the sync key must be backed up in a password
//     manager; the check only os.Stats the key path, never reads its contents.
//
// asciinema findings (emitted only when cfg.Modules.Asciinema.Enabled):
//   - asciinema-rec-warning (FATAL): structural invariant that `abysslink
//     asciinema rec` requires an interactive TTY and shows a non-suppressible
//     credential warning before any recording, with no bypass flag/env-var
//     (T-21-02-01); enforced by TestAsciinemaRec_RequiresInteractiveTTY.
func mod3DoctorFindings(_ context.Context, cfg *config.Config, _ shell.Runner) []modules.Finding {
	var findings []modules.Finding

	if cfg.Modules.Upsnap.Enabled {
		findings = append(findings,
			modules.Finding{
				Module:   "upsnap",
				Check:    "wol-apply-gate",
				Severity: modules.SeverityFatal,
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
				Severity: modules.SeverityFatal,
				Message:  `atuin-bind — atuin sync_address must not point to a public cloud endpoint; local-only mode is enforced by abysslink config (sync_address = "")`,
			},
			atuinKeyBackedUpFinding(),
		)
	}

	if cfg.Modules.Asciinema.Enabled {
		findings = append(findings,
			modules.Finding{
				Module:   "asciinema",
				Check:    "asciinema-rec-warning",
				Severity: modules.SeverityFatal,
				Message:  "asciinema-rec-warning — structural invariant: `abysslink asciinema rec` requires an interactive TTY and shows a non-suppressible credential warning before any recording; no bypass env-var or flag exists; verified by TestAsciinemaRec_RequiresInteractiveTTY",
			},
		)
	}

	return findings
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
