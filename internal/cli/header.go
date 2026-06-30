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

// commandHeader renders the canonical Tier-1 branded command header box followed
// by a trailing blank line. It is the single source of truth for every command's
// human header so the whole CLI reads as one branded surface (TUI migration §3.1).
//
//   - cmd  is the bare command path, e.g. "doctor", "lock init", "enroll rig myrig".
//     The "abysslink " prefix and the cyan brand accent (styleTitle / ColorAccent)
//     are applied here — callers pass only the path.
//   - mode is an OPTIONAL, already-styled subtitle. Ordinary commands pass
//     styleMuted.Render("health check"); commands with a semantic signal pass it
//     in the matching colour (e.g. up's styleWarn "preview only…" vs styleSuccess
//     "✦  applying"). Pass "" for no subtitle.
//
// The box uses boxBorder() (rounded on a TTY, ASCII +/-/| when piped) and
// boxWidth(), so non-TTY / NO_COLOR captures stay byte-stable. CALLERS MUST NOT
// invoke this on the --json path — the header is a human affordance only and
// would corrupt a machine-readable or redirected (`> file`) stream.
func commandHeader(p Printer, cmd, mode string) {
	// Self-guard: the header is a human affordance only. Emitting it into a
	// jsonPrinter would push a {"msg":"<box>"} record into the newline-delimited
	// JSON stream (or a redirected `> file`). Mirrors spinWork/emitSecurityNote,
	// so a forgetful caller cannot corrupt --json (TUI-migration verify L3/L11).
	if _, isJSON := p.(*jsonPrinter); isJSON {
		return
	}
	line := styleTitle.Render("abysslink " + cmd)
	if mode != "" {
		line += "  " + mode
	}
	printerInfo(p, styleHeaderBox.Render(line))
	printerInfo(p, "")
}
