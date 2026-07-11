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
	"os/user"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/hwkey"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// newHwkeyProvider is a seam over hwkey.NewProvider so CLI tests inject a
// hwkey.MockProvider — no CLI test ever constructs a real provider (and so
// can never reach a live authenticator, keychain, or ssh-keygen -w).
var newHwkeyProvider = func(kind hwkey.Kind, runner shell.Runner, opts hwkey.Options) (hwkey.Provider, error) { //nolint:gochecknoglobals // test seam, mirrors newRunner
	return hwkey.NewProvider(kind, runner, opts)
}

// enrollHwkeyInteractive is a seam over the term.go interactive() gate so the
// --apply success path is testable without a real TTY. Production behavior is
// identical to interactive().
var enrollHwkeyInteractive = interactive //nolint:gochecknoglobals // test seam, mirrors newRunner

// newEnrollHardwareKeyCmd builds `abysslink enroll hardware-key` (HWK-04).
//
// Dry-run is the DEFAULT (repo rule): it prints the provider availability
// probe (non-interactive Runner calls only: LookPath, `ssh -V`, stat), the
// EXACT argv --apply would run, and the interactive prompts to expect. No
// mutation, no interactive exec.
//
// --apply hard-gates on a live terminal (the touch/PIN prompts are handled by
// sc_auth / ssh-keygen on the inherited TTY; abysslink never reads a PIN) and
// rejects --json (an interactive flow cannot be machine-driven).
func newEnrollHardwareKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hardware-key",
		Short: "Enroll a hardware-backed SSH key (Secure Enclave or FIDO2) — dry-run by default",
		Example: `  # Preview: availability probe + the exact commands --apply would run
  abysslink enroll hardware-key

  # Enroll interactively (authenticator touch / PIN on YOUR terminal)
  abysslink enroll hardware-key --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)

			hk := cc.cfg.HardwareKeys
			if !hk.Enabled || hk.Provider == "" {
				return fmt.Errorf("enroll hardware-key: hardware_keys is not enabled in abysslink.yaml — run `abysslink enroll rig <name> --key-kind secure-enclave|fido2` or set hardware_keys.enabled + provider first")
			}

			prov, pErr := newHwkeyProvider(hwkey.Kind(hk.Provider), cc.runner, hwkey.Options{FIDO2ProviderPath: hk.FIDO2ProviderPath})
			if pErr != nil {
				return fmt.Errorf("enroll hardware-key: %w", pErr)
			}

			req, rErr := buildHwkeyEnrollRequest(cc.cfg)
			if rErr != nil {
				return rErr
			}

			if !cc.apply {
				printEnrollHardwareKeyPlan(ctx, p, prov, hk, req)
				return nil
			}
			return runEnrollHardwareKeyApply(ctx, cmd, cc, p, prov, req)
		},
	}
}

// buildHwkeyEnrollRequest derives the EnrollRequest from config: destination
// dir from the resolved handle path, a hostname-scoped label, and the
// config-resolved key type / application / resident settings. The key type
// resolution is PROVIDER-AWARE (config.ResolvedKeyType): the default enclave
// config resolves to ecdsa-sk — resolving the fido2 default ed25519-sk for
// every provider made the enclave --apply path a guaranteed refusal (finding
// P37-01). It carries NO secrets by construction.
func buildHwkeyEnrollRequest(cfg *config.Config) (hwkey.EnrollRequest, error) {
	home, err := os.UserHomeDir()
	if err != nil && cfg.HardwareKeys.KeyPath == "" {
		return hwkey.EnrollRequest{}, fmt.Errorf("enroll hardware-key: cannot resolve key path (home directory unknown): %w", err)
	}
	keyPath := cfg.HardwareKeys.ResolvedKeyPath(home)

	label := "abysslink"
	if cfg.Tailnet.Hostname != "" {
		label = "abysslink-" + cfg.Tailnet.Hostname
	}
	u := ""
	if cur, uErr := user.Current(); uErr == nil {
		u = cur.Username
	}
	return hwkey.EnrollRequest{
		Dir:         filepath.Dir(keyPath),
		Label:       label,
		KeyType:     cfg.HardwareKeys.ResolvedKeyType(),
		Application: cfg.HardwareKeys.ResolvedApplication(),
		User:        u,
		Resident:    cfg.HardwareKeys.Resident,
	}, nil
}

// printEnrollHardwareKeyPlan renders the dry-run preview: the availability
// probe result, the EXACT argv --apply would run (single argv source shared
// with the providers — hwkey.FIDO2EnrollArgv / hwkey.EnclaveEnrollArgvs, so
// the preview can never drift), and the interactive prompts to expect.
func printEnrollHardwareKeyPlan(ctx context.Context, p Printer, prov hwkey.Provider, hk config.HardwareKeysConfig, req hwkey.EnrollRequest) {
	commandHeader(p, "enroll hardware-key", styleWarn.Render("preview only — run with --apply to enroll"))

	probe := prov.Available(ctx)
	if probe.OK {
		printerInfo(p, "  "+iconOKStr()+"  provider "+hk.Provider+" available (OpenSSH "+probe.SSHVersion+")")
	} else {
		printerInfo(p, "  "+iconFatalStr()+"  provider "+hk.Provider+" NOT available: "+probe.Reason)
	}

	printerInfo(p, "")
	printerInfo(p, "[plan] would run (interactive — authenticator touch / PIN on your terminal):")
	if hwkey.Kind(hk.Provider) == hwkey.KindSecureEnclave {
		for _, argv := range hwkey.EnclaveEnrollArgvs(req.Label, hwkey.EnclaveDylibPath) {
			printerInfo(p, "  "+styleCode.Render(shellJoin(argv)))
		}
		printerInfo(p, "[plan] expect: a Touch ID prompt (identity creation), then ssh-keygen's PIN prompt (empty for biometric-protected keys) and a touch confirmation")
	} else {
		argv := hwkey.FIDO2EnrollArgv(req, filepath.Join(req.Dir, hwkey.HandleBaseName), hk.FIDO2ProviderPath)
		printerInfo(p, "  "+styleCode.Render(shellJoin(argv)))
		printerInfo(p, "[plan] expect: ssh-keygen's authenticator touch prompt (and your FIDO2 PIN if the token requires it)")
	}
	printerInfo(p, "[plan] would verify the produced public key is sk-backed (refusing + deleting the files otherwise), move the handle into "+req.Dir+" via the audited writer, and record hardware_keys.key_path in abysslink.yaml")
	printerInfo(p, "")
	printerInfo(p, "Next: run "+styleCode.Render("abysslink enroll hardware-key --apply")+" from an interactive terminal.")
}

// shellJoin renders an argv for DISPLAY only (the real exec always receives
// the []string directly — never a shell).
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t") {
			parts[i] = "'" + a + "'"
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

// runEnrollHardwareKeyApply is the --apply path: hard TTY gate (never blocks
// unattended), --json rejected, Provider.Enroll, audited config update, and
// the connection guidance print.
func runEnrollHardwareKeyApply(ctx context.Context, cmd *cobra.Command, cc *cmdContext, p Printer, prov hwkey.Provider, req hwkey.EnrollRequest) error {
	if cc.jsonOut {
		return fmt.Errorf("enroll hardware-key: --apply is interactive (authenticator touch / PIN) and cannot be combined with --json")
	}
	if !enrollHwkeyInteractive(cc.yes, cc.jsonOut) {
		return fmt.Errorf("enroll hardware-key: --apply requires an interactive terminal (authenticator touch / PIN prompts) — run it directly, without --yes, --json, or redirected stdin")
	}

	commandHeader(p, "enroll hardware-key", styleSuccess.Render("✦  applying"))
	printerInfo(p, styleMuted.Render("  Watch your terminal and authenticator: touch / PIN prompts come from ssh-keygen and sc_auth directly."))

	enrolled, err := prov.Enroll(ctx, req)
	if err != nil {
		return fmt.Errorf("enroll hardware-key: %w", err)
	}

	// Persist the handle path (audited write — config.Write goes through
	// internal/audit). The handle is NOT secret material; the private key
	// lives in the enclave/authenticator.
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	cc.cfg.HardwareKeys.KeyPath = enrolled.PrivateHandle
	if wErr := config.Write(cfgPath, cc.cfg); wErr != nil {
		return fmt.Errorf("enroll hardware-key: record key path: %w", wErr)
	}

	printEnrollHardwareKeySuccess(p, cc.cfg.HardwareKeys, enrolled)
	return nil
}

// printEnrollHardwareKeySuccess prints the resulting PUBLIC key and the
// explicit connection guidance. The explicit -o flags are load-bearing:
// without IdentitiesOnly/IdentityAgent=none ssh can silently succeed with
// some OTHER credential (auth-downgrade hazard), and SecurityKeyProvider must
// be the explicit flag because SSH_SK_PROVIDER is ignored by some builds.
func printEnrollHardwareKeySuccess(p Printer, hk config.HardwareKeysConfig, enrolled *hwkey.EnrolledKey) {
	printerInfo(p, "")
	printerInfo(p, styleSuccess.Render("Hardware key enrolled and verified sk-backed."))
	printerInfo(p, "  handle:     "+enrolled.PrivateHandle)
	printerInfo(p, "  public key: "+enrolled.PublicKeyPath)
	if data, err := os.ReadFile(enrolled.PublicKeyPath); err == nil { //nolint:gosec // G304: path was just produced by the audited enroll flow
		printerInfo(p, "")
		printerInfo(p, "Add this PUBLIC key to the target's authorized_keys:")
		printerInfo(p, "  "+strings.TrimSpace(string(data)))
	}

	skProvider := ""
	switch hwkey.Kind(hk.Provider) {
	case hwkey.KindSecureEnclave:
		skProvider = hwkey.EnclaveDylibPath
	case hwkey.KindFIDO2:
		skProvider = hk.FIDO2ProviderPath // empty on Linux (internal provider)
	}
	printerInfo(p, "")
	printerInfo(p, "Connect with EXPLICIT options (prevents a silent fallback to another credential):")
	line := "  ssh -o IdentitiesOnly=yes -o IdentityAgent=none -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no"
	if skProvider != "" {
		line += " -o SecurityKeyProvider=" + skProvider
	}
	line += " -i " + enrolled.PrivateHandle + " <user>@<host>"
	printerInfo(p, styleCode.Render(line))
	printerInfo(p, styleMuted.Render("  Every connection requires an authenticator touch (and PIN where verify-required applies)."))
}
