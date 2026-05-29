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
	"path/filepath"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/qr"
	"github.com/abysslink/abysslink/internal/tailscale"
	"github.com/spf13/cobra"
)

const oauthSecretEnv = "ABYSSLINK_TS_OAUTH_SECRET" //nolint:gosec // env var name, not a secret

func newEnrollCmd() *cobra.Command {
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a device into the tailnet",
	}
	enroll.AddCommand(
		newEnrollPhoneCmd(),
		&cobra.Command{
			Use:   "rig",
			Short: "Add another laptop to the tailnet (v2 placeholder)",
			RunE: func(cmd *cobra.Command, _ []string) error {
				printerInfo(newPrinter(cmd), "Multi-rig enrollment is a v2 feature. For now, run `abysslink init` + `abysslink up` on the new machine.")
				return nil
			},
		},
	)
	return enroll
}

func newEnrollPhoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "phone",
		Short: "Mint a tagged auth key, show a QR, and walk through phone pairing",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			tag := "tag:" + cc.cfg.Mobile.Tag

			admin := tailscale.NewAdminClient(
				cc.cfg.Tailnet.Admin.Tailnet,
				cc.cfg.Tailnet.Admin.OAuthClientID,
				os.Getenv(oauthSecretEnv),
			)
			hasCreds := cc.cfg.Tailnet.Admin.Tailnet != "" &&
				cc.cfg.Tailnet.Admin.OAuthClientID != "" && os.Getenv(oauthSecretEnv) != ""

			printerInfo(p, styleBold.Render("Enroll phone"))
			printerInfo(p, "")
			printerInfo(p, "1. Install Tailscale on your phone (scan to open the download page):")
			qr.PrintANSI(os.Stdout, "https://tailscale.com/download")
			printerInfo(p, "")

			if !hasCreds {
				printerInfo(p, styleWarn.Render("No admin OAuth client configured — cannot mint an auth key automatically."))
				printerInfo(p, "Create a single-use, pre-authorized key tagged "+styleCode.Render(tag)+" at:")
				printerInfo(p, "  "+styleCode.Render("https://login.tailscale.com/admin/settings/keys"))
				printerInfo(p, "Then sign in on the phone with that key.")
			} else if err := enrollWithAdminKey(ctx, p, admin, tag); err != nil {
				return fmt.Errorf("enroll phone: %w", err)
			}

			// ntfy subscription QR (best-effort — needs the tailnet IP).
			printNtfyQR(ctx, p, cc)

			// Printable runbook for the remaining manual steps.
			if path, err := writeRunbook(ctx, cc); err == nil {
				printerInfo(p, "")
				printerInfo(p, "Manual steps (SSO passkey, disable SMS 2FA, hide lock-screen previews) are in:")
				printerInfo(p, "  "+styleCode.Render(path))
			}
			return nil
		},
	}
}

// enrollWithAdminKey mints a tagged auth key, shows its QR, and polls for the
// phone to appear on the tailnet with the expected tag.
func enrollWithAdminKey(ctx context.Context, p Printer, admin *tailscale.AdminClient, tag string) error {
	key, err := admin.CreateAuthKey(ctx, []string{tag})
	if err != nil {
		return fmt.Errorf("mint auth key: %w", err)
	}
	printerInfo(p, "2. In the Tailscale app choose \"Sign in with auth key\" and scan:")
	qr.PrintANSI(os.Stdout, key)
	printerInfo(p, "")
	printerInfo(p, "Waiting for the phone to join the tailnet (up to 2 minutes)...")

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
		devices, derr := admin.Devices(ctx)
		if derr != nil {
			continue
		}
		for _, d := range devices {
			for _, t := range d.Tags {
				if t == tag {
					printerInfo(p, styleSuccess.Render(fmt.Sprintf("Phone joined: %s (%s)", d.Name, t)))
					return nil
				}
			}
		}
	}
	printerInfo(p, styleWarn.Render("Timed out waiting for the phone. Re-run `abysslink doctor` once it has joined."))
	return nil
}

// printNtfyQR shows a QR for the ntfy subscription URL when the tailnet IP is known.
func printNtfyQR(ctx context.Context, p Printer, cc *cmdContext) {
	if !cc.cfg.Modules.Ntfy.Enabled {
		return
	}
	res, err := cc.runner.Run(ctx, "tailscale", "ip", "--4")
	if err != nil || res.ExitCode != 0 {
		printerInfo(p, styleWarn.Render("⚠  Could not get tailnet IP — ntfy subscription QR skipped."))
		printerInfo(p, styleMuted.Render("  Run `tailscale up` then re-run `abysslink enroll phone` to get the QR."))
		return
	}
	ip := strings.TrimSpace(res.Stdout)
	if ip == "" {
		printerInfo(p, styleWarn.Render("⚠  tailscale ip returned empty — ntfy subscription QR skipped."))
		return
	}
	topic := cc.cfg.Modules.Notify.DefaultTopic
	if topic == "" {
		topic = "rig"
	}
	port := cc.cfg.Modules.Ntfy.ListenPort()

	// Prefer MagicDNS hostname — survives IP changes.
	hostname := ip
	if statusRes, err := cc.runner.Run(ctx, "tailscale", "status", "--json"); err == nil && statusRes.ExitCode == 0 {
		for _, line := range strings.Split(statusRes.Stdout, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, `"DNSName"`) {
				parts := strings.SplitN(line, `"`, 4)
				if len(parts) >= 4 {
					hostname = strings.TrimRight(parts[3], `".,`)
				}
				break
			}
		}
	}

	deepLink := fmt.Sprintf("ntfy://%s:%d/%s", hostname, port, topic)
	printerInfo(p, "")
	printerInfo(p, "3. Subscribe to notifications in the ntfy app:")
	printerInfo(p, styleMuted.Render("   Android: tap + → Scan QR code"))
	qr.PrintANSI(os.Stdout, deepLink)
	printerInfo(p, styleMuted.Render("   iPhone:  tap + → enter manually:"))
	printerInfo(p, fmt.Sprintf("     Server:  http://%s:%d", hostname, port))
	printerInfo(p, fmt.Sprintf("     Topic:   %s", topic))
}

// writeRunbook writes a Markdown runbook of the remaining manual steps and
// returns its path. It is recorded through the audit log like any other write.
func writeRunbook(ctx context.Context, cc *cmdContext) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Documents")
	if _, statErr := os.Stat(dir); statErr != nil {
		dir = abysslinkStateDir()
	}
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return "", mkErr
	}
	path := filepath.Join(dir, "abysslink-runbook-"+time.Now().Format("20060102")+".md")

	body := runbookMarkdown(cc)
	if cc.cfg == nil {
		return "", fmt.Errorf("no config")
	}
	deps, err := buildDeps(ctx, cc)
	if err != nil {
		return "", err
	}
	if err := deps.Audit.WriteFile(path, []byte(body), 0o600, false); err != nil {
		return "", err
	}
	return path, nil
}

func runbookMarkdown(cc *cmdContext) string {
	return fmt.Sprintf(`# Abysslink phone runbook

Generated %s for %s.

These steps cannot be automated — do them on your phone / in the SSO console:

## 1. SSO hardening (one-time)
- Enroll a **passkey** (or hardware security key) for your Tailscale SSO identity (%s).
- **Disable SMS 2FA** if it is enabled — SMS is SIM-swap vulnerable.

## 2. Phone lock screen
- Hide notification **previews** on the lock screen so notification bodies are not exposed.
- Enable an app lock / biometric lock on your SSH client.

## 3. Tailnet Lock (if enabled)
- Store the disablement secrets printed by "abysslink lock init" in your password manager.
- Print at least one on paper and keep it somewhere safe.

## 4. SSH client
- iOS: Blink Shell (paid, best mosh support) or Termius (free tier). No fully-free FOSS SSH+mosh client exists on iOS.
- Android: ConnectBot (SSH) or Termux from F-Droid (SSH + mosh).
- Connect with:  mosh %s -- tmux new -A -s main

## 5. Verify
- Run "abysslink doctor" on the laptop — everything should be green.
`,
		time.Now().Format("2006-01-02"),
		cc.cfg.Identity.Email,
		cc.cfg.Identity.Email,
		cc.cfg.Tailnet.Hostname,
	)
}
