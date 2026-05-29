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

// Package cli — security-notes layer.
//
// This file is the SINGLE SOURCE OF TRUTH for all 12 required security callouts
// defined in USER-JOURNEY-TUI.md §7. Notes are defined once here as a slice;
// call sites reference note IDs only — never duplicate note text at call sites.
//
// Use emitSecurityNote(p, jsonOut, id) to render a note at a journey point.
// Notes are rendered via tui.Note() and printed through the Printer. Notes MUST
// be suppressed under --json (the journey/notes are off under --json per §9);
// emitSecurityNote self-guards on jsonOut so a new call site cannot leak note
// prose into the JSON stream.
//
// If any of the 12 notes is missing = the journey is not complete (§7).
// The test in notes_test.go asserts len(allSecurityNotes)==12.

package cli

import (
	"github.com/abysslink/abysslink/internal/tui"
)

// securityNote holds the definition of one of the 12 §7 required callouts.
// All user-visible strings live here — this is also the i18n string location (§10).
type securityNote struct {
	id    string // unique stable ID for call-site references
	level tui.NoteLevel
	title string
	lines []string
}

// allSecurityNotes is the authoritative list of all 12 §7 security callouts.
// Do NOT duplicate note text at call sites — call emitSecurityNote(p, id) instead.
//
// Note 1: SSO hardening (Stage 1, runbook)
// Note 2: --dry-run default (Stage 0)
// Note 3: Backups + audit log / reversibility (Stage 0 + Done)
// Note 4: sudo notice (Stage 2/3)
// Note 5: Disk encryption required / fail-closed (Stage 3 gate)
// Note 6: Tailnet Lock secrets shown once (Stage 4)
// Note 7: SSH re-auth 12h / checkperiod extension flag (conditional)
// Note 8: No Tailscale Funnel (Done / threat-model)
// Note 9: ntfy binds to tailnet IP only (Stage 3 when ntfy enabled)
// Note 10: Lock screen + SSH client hygiene (runbook)
// Note 11: doctor is not a full security audit (Stage 6)
// Note 12: panic is reversible; uninstall --purge is not (Done)
//
//nolint:gochecknoglobals // the notes slice is a package-level constant; it is never mutated.
var allSecurityNotes = []securityNote{
	{
		id:    "sso-hardening",
		level: tui.NoteSecurity,
		title: "SSO hardening required",
		lines: []string{
			"Sign in with Google, GitHub, Microsoft, or Apple — never SMS.",
			"After setup: enable a passkey and disable SMS 2FA on your SSO provider.",
			"See the printed runbook for exact steps.",
		},
	},
	{
		id:    "dry-run-default",
		level: tui.NoteInfo,
		title: "--dry-run is the default; nothing mutates without --apply",
		lines: []string{
			"Every destructive command requires --apply to execute.",
			"Without --apply you see a plan only — no changes are made.",
		},
	},
	{
		id:    "backups-reversible",
		level: tui.NoteInfo,
		title: "Every mutation is backed up and reversible",
		lines: []string{
			"Abysslink writes a backup before every file change.",
			"Run: abysslink backup ls    to see the backup history.",
			"Run: abysslink backup restore <id>   to undo a specific change.",
			"Run: abysslink uninstall    to reverse the entire setup.",
		},
	},
	{
		id:    "sudo-notice",
		level: tui.NoteWarn,
		title: "sudo will be requested for the following actions",
		lines: []string{
			"• Installing or configuring system packages (Tailscale, mosh).",
			"• Writing to system SSH config directories.",
			"• Configuring Application Firewall on macOS.",
			"Only the listed actions require elevation — nothing else.",
		},
	},
	{
		id:    "disk-encryption",
		level: tui.NoteDanger,
		title: "Disk encryption is required — we fail closed if it is off",
		lines: []string{
			"abysslink will not converge if disk encryption is disabled.",
			"Enable FileVault (macOS): System Settings → Privacy & Security → FileVault.",
			"Enable LUKS (Linux) before exposing remote access.",
			"Use --force-unsafe only in ephemeral/test environments.",
		},
	},
	{
		id:    "tailnet-lock-secrets",
		level: tui.NoteDanger,
		title: "Tailnet Lock secrets are shown ONCE and never stored",
		lines: []string{
			"The disablement secret will appear in the next step.",
			"Save it in your password manager NOW — it will not be shown again.",
			"Losing it can permanently lock you out of your tailnet.",
			"abysslink lock status shows state only, never the secret.",
		},
	},
	{
		id:    "ssh-checkperiod",
		level: tui.NoteSecurity,
		title: "SSH re-auth every 12h; raising it requires an explicit flag",
		lines: []string{
			"The ssh_check_period default (12h) limits stolen-session exposure.",
			"To extend it beyond 12h you must pass --accept-checkperiod-extension.",
			"Raising checkPeriod weakens the re-auth guarantee — do it only if necessary.",
		},
	},
	{
		id:    "no-funnel",
		level: tui.NoteSecurity,
		title: "Tailscale Funnel is permanently rejected at the schema level",
		lines: []string{
			"Abysslink never exposes services to the public internet via Funnel.",
			"All remote access is restricted to your tailnet only.",
			"This is a hard floor — it cannot be configured away.",
		},
	},
	{
		id:    "ntfy-tailnet-only",
		level: tui.NoteSecurity,
		title: "ntfy binds to the tailnet IP only — never 0.0.0.0",
		lines: []string{
			"Your ntfy push server listens only on the Tailscale interface.",
			"It is not reachable from the public internet.",
			"This is enforced by abysslink and rejected at the config schema level.",
		},
	},
	{
		id:    "lock-screen-hygiene",
		level: tui.NoteWarn,
		title: "Lock your screen and SSH client — see the runbook",
		lines: []string{
			"Disable notification previews on your phone lock screen.",
			"Lock your SSH client (Blink / Termius) with a PIN or biometric.",
			"These manual steps are in the printed runbook.",
		},
	},
	{
		id:    "doctor-not-full-audit",
		level: tui.NoteInfo,
		title: "doctor checks known footguns; it is not a full security audit",
		lines: []string{
			"abysslink doctor verifies the configuration Abysslink manages.",
			"It does not replace a professional security audit.",
			"See docs/DESIGN.md §6.1 for the scope boundary.",
		},
	},
	{
		id:    "panic-reversible",
		level: tui.NoteWarn,
		title: "panic is reversible via repair; uninstall --purge is not",
		lines: []string{
			"abysslink panic disconnects and revokes credentials — it can be undone.",
			"Run: abysslink repair --apply   to reconnect after a panic.",
			"abysslink uninstall --purge removes the audit log and backups (irreversible).",
		},
	},
}

// noteIndex is a map from ID to note definition, built once at init time.
//
//nolint:gochecknoglobals // read-only lookup table built from allSecurityNotes.
var noteIndex = func() map[string]*securityNote {
	idx := make(map[string]*securityNote, len(allSecurityNotes))
	for i := range allSecurityNotes {
		idx[allSecurityNotes[i].id] = &allSecurityNotes[i]
	}
	return idx
}()

// emitSecurityNote renders the security note with the given ID via tui.Note and
// prints it through p. Call sites reference IDs only — text lives in allSecurityNotes.
//
// It is a no-op when jsonOut is true: notes are human-facing prose and would
// corrupt the newline-delimited JSON stream (§9). Guarding here rather than at
// every call site keeps the suppression robust as call sites are added (WR-01).
// If id is not found (programming error), emitSecurityNote is also a no-op.
func emitSecurityNote(p Printer, jsonOut bool, id string) {
	if jsonOut {
		return
	}
	n, ok := noteIndex[id]
	if !ok {
		return
	}
	printerInfo(p, tui.Note(n.level, n.title, n.lines))
}
