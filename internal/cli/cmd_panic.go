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

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/tailscale"
	"github.com/spf13/cobra"
)

func newPanicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "panic",
		Short: "Emergency: disconnect, revoke the phone, and destroy the local API key — no confirmation",
		// No confirmation prompt — designed for one-tap emergency use.
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd) // best-effort — proceed even on config load failure
			if err != nil {
				slog.Warn("panic: could not load config, proceeding with defaults", "err", err)
			}
			p := newPrinter(cmd)
			emit := func(format string, args ...any) {
				printerError(p, "PANIC: "+fmt.Sprintf(format, args...))
			}
			logPanic := panicAuditLogger()

			emit("disconnecting from the tailnet...")
			if res, err := cc.runner.Run(ctx, "tailscale", "down"); err != nil || res.ExitCode != 0 {
				emit("tailscale down failed — disconnect manually")
			} else {
				emit("tailnet disconnected.")
				logPanic("tailscale_down")
			}

			revokePhoneDevices(ctx, cc, emit, logPanic)
			destroyLocalAPIKey(ctx, cc, emit, logPanic)

			emit("complete. Required manual follow-up:")
			emit("  1. Revoke the Anthropic API key in the console (the local copy is now deleted):")
			emit("       https://console.anthropic.com/settings/keys")
			emit("  2. If devices could not be revoked above, remove them at:")
			emit("       https://login.tailscale.com/admin/machines")
			// §7 note 12: panic is reversible via repair.
			emitSecurityNote(p, "panic-reversible")
			return nil
		},
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

// revokePhoneDevices deletes every device tagged with the mobile tag via the
// admin API. Requires admin credentials; otherwise the user is directed to the
// console in the final instructions.
func revokePhoneDevices(ctx context.Context, cc *cmdContext, emit func(string, ...any), logPanic func(string)) {
	if cc.cfg.Tailnet.Admin.Tailnet == "" || cc.cfg.Tailnet.Admin.OAuthClientID == "" || os.Getenv(oauthSecretEnv) == "" {
		emit("no admin credentials — cannot auto-revoke the phone (see manual steps below).")
		return
	}
	admin := tailscale.NewAdminClient(cc.cfg.Tailnet.Admin.Tailnet, cc.cfg.Tailnet.Admin.OAuthClientID, os.Getenv(oauthSecretEnv))
	devices, err := admin.Devices(ctx)
	if err != nil {
		emit("could not list devices to revoke: %v", err)
		return
	}
	tag := "tag:" + cc.cfg.Mobile.Tag
	for _, d := range devices {
		for _, t := range d.Tags {
			if t != tag {
				continue
			}
			if err := admin.DeleteDevice(ctx, d.ID); err != nil {
				emit("failed to revoke device %s: %v", d.Name, err)
			} else {
				emit("revoked device %s", d.Name)
				logPanic("revoke_device")
			}
		}
	}
}

// destroyLocalAPIKey deletes the Anthropic API key from the local keychain so a
// stolen laptop session cannot use it. Console revocation is a manual step.
func destroyLocalAPIKey(ctx context.Context, cc *cmdContext, emit func(string, ...any), logPanic func(string)) {
	deps, err := buildDeps(ctx, cc)
	if err != nil || deps.Keychain == nil {
		return
	}
	if err := deps.Keychain.Delete(ctx, "abysslink", "anthropic-api-key"); err != nil {
		emit("could not delete local API key from keychain: %v", err)
		return
	}
	emit("deleted the local Anthropic API key from the keychain.")
	logPanic("destroy_local_api_key")
}
