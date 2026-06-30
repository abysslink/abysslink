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

	"github.com/abysslink/abysslink/internal/tui"
)

// spinWork shows liveness feedback while a long, UI-blocking operation runs.
//
//   - On an interactive colour TTY it renders tui's animated cyan spinner
//     (tui.RunSpinner), which is wired with tea.WithContext so Ctrl-C/Esc and a
//     cancelled ctx stop the visual promptly (WR-02). This replaces the old
//     pattern of printing a STATIC ◌ glyph and then blocking, which made a
//     15-second daemon wait or a multi-minute package install look frozen on a
//     phone SSH session (the user could not tell "working" from "hung").
//   - Otherwise — a JSON printer, NO_COLOR, CLICOLOR=0, or a non-TTY (pipe / CI
//     / redirected log) — it prints a single static status line through the
//     Printer and runs the work directly. No Bubble Tea program is started, so
//     machine-readable / captured output stays clean and the call never hangs.
//
// work MUST honour ctx so cancellation actually stops the side effect; the
// spinner only stops the visual.
func spinWork(ctx context.Context, p Printer, label string, work func(context.Context) error) error {
	// JSON (or any machine printer): run the work silently. Printing a status
	// line here would emit a {"msg":"  ◌  …"} record into the newline-delimited
	// JSON stream and corrupt it — the spinner is a human affordance only. This
	// makes spinWork safe to call from a collector that runs BEFORE a command's
	// cc.jsonOut branch, so call sites do not each have to re-gate it.
	if _, isJSON := p.(*jsonPrinter); isJSON {
		return work(ctx)
	}
	// Human colour TTY: the animated, ctx-cancellable cyan spinner.
	if colorEnabled() {
		return tui.RunSpinner(ctx, label, work, true)
	}
	// Human non-colour surface (NO_COLOR / CLICOLOR=0 / dumb terminal): a single
	// static status line, then run the work.
	printerInfo(p, "  "+iconSpinStr()+"  "+label)
	return work(ctx)
}
