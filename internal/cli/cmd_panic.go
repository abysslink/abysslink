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
	"log/slog"
	"os"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// errPanicStepFailed is the error type returned by a failed panic step,
// distinguishing it from "step succeeded" for the panicStep helper.
type errPanicStepFailed struct{ msg string }

func (e errPanicStepFailed) Error() string { return e.msg }

// panicStep prints a ✓ or ✕ marker for a single panic step. This helper is
// exported for unit-testing; do NOT add confirmation calls here — panic is
// promptless by design (§4/§6 emergency design contract, T-10-19).
func panicStep(p Printer, label string, err error) {
	if err == nil {
		printerError(p, iconDoneStr()+"  "+label)
	} else {
		printerError(p, iconFatalStr()+"  "+label+": "+err.Error())
	}
}

func newPanicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "panic",
		Short: "Emergency: disconnect, revoke the phone, and destroy the local API key — no confirmation",
		Long: `EMERGENCY KILL SWITCH — executes immediately with no confirmation prompt.

Panic disconnects your machine from the tailnet, revokes all phone devices
tagged with your mobile tag, and destroys the local Anthropic API key from
the keychain. The consequences are audited and REVERSIBLE via repair:

  abysslink repair --apply     # reconnect after a panic

Output:
  ✓ / ✕ per step — live feedback without blocking.
  "done in Xs" timing line.

NOTE: panic is designed for one-tap emergency use. It will NEVER prompt
for confirmation; if you need that, use abysslink uninstall instead.`,
		Example: `  # Emergency kill switch — no confirmation, immediate action
  abysslink panic`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd) // best-effort — proceed even on config load failure
			if err != nil || cc == nil {
				// Emergency kill switch MUST NOT crash: on a config-load failure cc is
				// nil, so synthesize a defaults context rather than deref a nil pointer
				// at the first cc.runner use below (CR-02).
				slog.Warn("panic: could not load config, proceeding with defaults", "err", err)
				cc = &cmdContext{cfg: config.Defaults(), runner: &shell.ExecRunner{}}
			}
			p := newPrinter(cmd)
			start := time.Now()

			// Bold-red banner — "what panic does" for the user landing in emergency mode.
			banner := styleFatal.Render("PANIC — Emergency kill switch executing NOW")
			printerError(p, styleHeaderBox.Render(banner))
			printerError(p, "")
			printerError(p, styleFatal.Render("Actions: disconnect tailnet · revoke phone devices · destroy local API key"))
			printerError(p, styleMuted.Render("No confirmation required — this is the emergency design contract."))
			printerError(p, "")

			logPanic := panicAuditLogger()

			// Step 1: disconnect tailnet via the backend abstraction. Prefer the
			// backend-neutral Down(ctx) so a future backend's adapter can perform
			// its own disconnect; fall back to the raw `tailscale down` shellout
			// only if backend construction fails (best-effort, like the rest of
			// panic) (WR-03).
			panicDisconnect(ctx, cc, p, logPanic)

			// Steps 2+: revoke phone devices and destroy local API key.
			revokePhoneDevicesWithStep(ctx, cc, p, logPanic)
			destroyLocalAPIKeyWithStep(ctx, cc, p, logPanic)

			// Timing line.
			elapsed := time.Since(start)
			printerError(p, "")
			printerError(p, styleMuted.Render(fmt.Sprintf("done in %.1fs", elapsed.Seconds())))
			printerError(p, "")

			// Required manual follow-up.
			printerError(p, styleBold.Render("Required manual follow-up:"))
			printerError(p, "  1. Revoke the Anthropic API key in the console:")
			printerError(p, "       https://console.anthropic.com/settings/keys")
			printerError(p, "  2. If devices could not be revoked above, remove them at:")
			printerError(p, "       https://login.tailscale.com/admin/machines")

			// §7 note 12: panic is reversible via repair.
			emitSecurityNote(p, cc.jsonOut, "panic-reversible")
			return nil
		},
	}
}

// panicDisconnect disconnects the node from the tailnet. It prefers the
// backend-neutral backend.Client.Down(ctx) so the kill switch stays generic
// across backends; if backend construction fails it falls back to the raw
// `tailscale down` shellout so the emergency disconnect still happens
// best-effort (WR-03). Either path emits a ✓/✕ step marker and audits success.
func panicDisconnect(ctx context.Context, cc *cmdContext, p Printer, logPanic func(string)) {
	if b, err := cc.backend(); err == nil {
		if err := b.Down(ctx); err != nil {
			panicStep(p, "disconnect tailnet", errPanicStepFailed{"backend disconnect failed — disconnect manually: " + err.Error()})
		} else {
			panicStep(p, "tailnet disconnected", nil)
			logPanic("tailscale_down")
		}
		return
	}
	// Fallback: backend could not be constructed (e.g. config load failed and
	// the synthesized defaults context cannot build one). Use the raw shellout.
	if res, runErr := cc.runner.Run(ctx, "tailscale", "down"); runErr != nil || res.ExitCode != 0 {
		panicStep(p, "disconnect tailnet", errPanicStepFailed{"tailscale down failed — disconnect manually"})
	} else {
		panicStep(p, "tailnet disconnected", nil)
		logPanic("tailscale_down")
	}
}

// panicAuditLogger returns a function that appends panic actions to the audit
// log. It is best-effort — a failure to log must never block the kill switch.
func panicAuditLogger() func(action string) {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return func(string) {}
	}
	a := audit.New(logPath)
	return func(action string) { _ = a.Append("panic:"+action, "panic", nil, false) }
}

// revokePhoneDevicesWithStep deletes every device tagged with the mobile tag
// and emits ✓/✕ per device. Requires admin credentials.
func revokePhoneDevicesWithStep(ctx context.Context, cc *cmdContext, p Printer, logPanic func(string)) {
	if cc.cfg.Tailnet.Admin.Tailnet == "" || cc.cfg.Tailnet.Admin.OAuthClientID == "" || os.Getenv(oauthSecretEnv) == "" {
		panicStep(p, "revoke phone devices", errPanicStepFailed{"no admin credentials — cannot auto-revoke (see manual steps)"})
		return
	}
	b, err := cc.backend()
	if err != nil {
		panicStep(p, "revoke phone devices", errPanicStepFailed{"backend init failed: " + err.Error()})
		return
	}
	admin, ok := b.(backend.AdminAPI)
	if !ok {
		panicStep(p, "revoke phone devices", errPanicStepFailed{"backend has no admin API — cannot auto-revoke (see manual steps)"})
		return
	}
	devices, err := admin.Devices(ctx)
	if err != nil {
		panicStep(p, "list devices to revoke", errPanicStepFailed{err.Error()})
		return
	}
	tag := "tag:" + cc.cfg.Mobile.Tag
	for _, d := range devices {
		for _, t := range d.Tags {
			if t != tag {
				continue
			}
			if rErr := admin.DeleteDevice(ctx, d.ID); rErr != nil {
				panicStep(p, "revoke device "+d.Name, errPanicStepFailed{rErr.Error()})
			} else {
				panicStep(p, "revoked device "+d.Name, nil)
				logPanic("revoke_device")
			}
		}
	}
}

// destroyLocalAPIKeyWithStep deletes the Anthropic API key from the local
// keychain and emits a ✓/✕ step marker.
func destroyLocalAPIKeyWithStep(ctx context.Context, cc *cmdContext, p Printer, logPanic func(string)) {
	deps, err := buildDeps(ctx, cc)
	if err != nil || deps.Keychain == nil {
		return
	}
	if err := deps.Keychain.Delete(ctx, "abysslink", "anthropic-api-key"); err != nil {
		panicStep(p, "destroy local API key", errPanicStepFailed{err.Error()})
		return
	}
	panicStep(p, "deleted local Anthropic API key from keychain", nil)
	logPanic("destroy_local_api_key")
}
