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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/browser"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/spf13/cobra"
)

const newAnthropicKeyEnv = "ABYSSLINK_NEW_ANTHROPIC_KEY" //nolint:gosec // env var name, not a secret

func newRotateCmd() *cobra.Command {
	rotate := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate secrets stored in the OS keychain (dry-run by default)",
	}
	rotate.AddCommand(newRotateAnthropicCmd(), newRotateNtfyCmd(), newRotateAuditHMACCmd())
	return rotate
}

// newRotateAuditHMACCmd rotates the audit-chain HMAC key to a fresh epoch
// (ROT-02). Dry-run by default; --apply performs the rotation. The key
// material is never printed — only the new key's SHA-256 fingerprint — because
// the HMAC key never leaves the machine, so printing it would be pure downside
// while the fingerprint fully serves the audit-trail intent.
func newRotateAuditHMACCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit-hmac",
		Short: "Rotate the tamper-evident audit log's HMAC key to a new epoch",
		Long: `Rotate the audit chain's HMAC signing key to a new key epoch.

Pre-rotation history stays verifiable: the old key is retained in the keychain
and an in-chain rotation marker (signed by the old key) records the hand-off.
Only new entries are signed under the new key. Verification selects the key by
epoch, so a rotated chain still verifies end to end.

Dry-run by default — re-run with --apply to rotate.`,
		Example: `  # Preview the rotation (dry-run)
  abysslink rotate audit-hmac

  # Rotate the audit HMAC key
  abysslink rotate audit-hmac --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			commandHeader(p, "rotate audit-hmac", styleMuted.Render("rotate the audit HMAC key to a new epoch"))
			return runRotateAuditHMAC(ctx, cc, p)
		},
	}
}

func runRotateAuditHMAC(ctx context.Context, cc *cmdContext, p Printer) error {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("rotate audit-hmac: %w", err)
	}
	kc := auditKeychain(ctx, cc)
	if kc == nil {
		return fmt.Errorf("rotate audit-hmac: no keychain backend available — cannot rotate the audit key")
	}

	if cc.dryRun {
		preview, perr := audit.RotatePreview(ctx, logPath, kc)
		if perr != nil {
			return fmt.Errorf("rotate audit-hmac: %w", perr)
		}
		if preview.Resumed {
			printerInfo(p, fmt.Sprintf("[plan] a previous rotation to epoch %d did not finish; --apply will COMPLETE it (advance the pointer, re-anchor).", preview.NewEpoch))
			return nil
		}
		printerInfo(p, fmt.Sprintf("[plan] rotate the audit HMAC key from epoch %d to epoch %d: generate a new key, append an in-chain rotation marker signed by the old key, retain the old key, and re-anchor. Re-run with --apply.", preview.OldEpoch, preview.NewEpoch))
		return nil
	}

	sa, saErr := cmdSignedAudit(ctx, cc)
	if saErr != nil {
		return fmt.Errorf("rotate audit-hmac: %w", saErr)
	}
	res, rerr := sa.RotateHMACKey(ctx)
	if rerr != nil {
		return fmt.Errorf("rotate audit-hmac: %w", rerr)
	}
	if res.Resumed {
		printerInfo(p, styleSuccess.Render(fmt.Sprintf("Completed a half-finished rotation to epoch %d.", res.NewEpoch)))
	} else {
		printerInfo(p, styleSuccess.Render(fmt.Sprintf("Rotated the audit HMAC key: epoch %d → %d.", res.OldEpoch, res.NewEpoch)))
	}
	printerInfo(p, styleMuted.Render("New key fingerprint (SHA-256): ")+styleCode.Render(res.NewKeyFingerprint))
	printerInfo(p, styleMuted.Render("The previous key is retained so pre-rotation history stays verifiable; verify with `abysslink audit verify`."))
	return nil
}

func newRotateAnthropicCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "anthropic-key",
		Short: "Store a new Anthropic API key in the keychain and verify it",
		Example: `  # Rotate the Anthropic API key (reads from ABYSSLINK_NEW_ANTHROPIC_KEY env)
  ABYSSLINK_NEW_ANTHROPIC_KEY=<key> abysslink rotate anthropic-key --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			commandHeader(p, "rotate anthropic-key", styleMuted.Render("rotate the Anthropic API key"))

			if cc.dryRun {
				printerInfo(p, "[plan] open the Anthropic console, read the new key from "+newAnthropicKeyEnv+
					", store it in the keychain, and verify it. Re-run with --apply.")
				return nil
			}

			const consoleURL = "https://console.anthropic.com/settings/keys"
			// Use the shared browser.OpenURL (probes xdg-open/open via LookPath and
			// checks the exit code) instead of a GOOS-hardcoded opener that drops
			// the error. Track whether the tab actually opened so the revoke hint
			// below does not claim a tab that never appeared (e.g. a headless rig).
			consoleOpened := browser.OpenURL(ctx, cc.runner, consoleURL) == nil
			if !consoleOpened {
				printerInfo(p, styleMuted.Render("Open the Anthropic console to manage keys: ")+styleCode.Render(consoleURL))
			}
			newKey := os.Getenv(newAnthropicKeyEnv)
			if newKey == "" {
				return fmt.Errorf("rotate anthropic-key: set %s to the new key (kept off argv), then re-run --apply", newAnthropicKeyEnv)
			}

			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("rotate anthropic-key: %w", err)
			}
			if deps.Keychain == nil {
				return fmt.Errorf("rotate anthropic-key: no keychain backend available")
			}

			ok, verifyErr := verifyAnthropicKey(ctx, newKey)
			if verifyErr != nil {
				// Transport failure ≠ key rejection: tell the offline user the
				// truth instead of "the new key was rejected".
				return fmt.Errorf("rotate anthropic-key: could not reach the Anthropic API to verify the new key (%w); not storing it — check your connection and retry", verifyErr)
			}
			if !ok {
				return fmt.Errorf("rotate anthropic-key: the new key was rejected by the Anthropic API (401/403); not storing it")
			}
			if err := deps.Keychain.Set(ctx, "abysslink", "anthropic-api-key", newKey); err != nil {
				return fmt.Errorf("rotate anthropic-key: store: %w", err)
			}
			// Rig-scoped migrated copies (enroll rig copies the v1 entry into
			// fleet.RigService(name)) must be rotated too — otherwise the old,
			// still-valid key survives under every rig service.
			if err := updateRigScopedAnthropicKeys(ctx, deps.Keychain, cc.cfg.Rigs, p, newKey); err != nil {
				return err
			}
			printerInfo(p, styleSuccess.Render("New Anthropic key verified and stored in the keychain."))
			if consoleOpened {
				printerInfo(p, styleMuted.Render("Now REVOKE the old key in the console tab that just opened."))
			} else {
				printerInfo(p, styleMuted.Render("Now REVOKE the old key at ")+styleCode.Render(consoleURL))
			}
			return nil
		},
	}
}

func newRotateNtfyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ntfy-creds",
		Short: "Generate a new ntfy admin password, update ntfy and the keychain",
		Example: `  # Rotate ntfy admin credentials
  abysslink rotate ntfy-creds --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			commandHeader(p, "rotate ntfy-creds", styleMuted.Render("rotate the ntfy admin password"))

			if cc.dryRun {
				printerInfo(p, "[plan] generate a new ntfy admin password, update ntfy + the keychain, and reload the service. Re-run with --apply.")
				return nil
			}

			deps, err := buildDeps(ctx, cc)
			if err != nil {
				return fmt.Errorf("rotate ntfy-creds: %w", err)
			}
			if deps.Keychain == nil {
				return fmt.Errorf("rotate ntfy-creds: no keychain backend available")
			}

			pw, err := modules.GenPassword()
			if err != nil {
				return fmt.Errorf("rotate ntfy-creds: %w", err)
			}
			// ntfy user change-pass reads the new password from stdin (never argv).
			res, err := cc.runner.RunWithStdin(ctx, strings.NewReader(pw+"\n"+pw+"\n"),
				"ntfy", "user", "change-pass", "admin")
			if err != nil {
				return fmt.Errorf("rotate ntfy-creds: ntfy change-pass: %w", err)
			}
			if res.ExitCode != 0 {
				return fmt.Errorf("rotate ntfy-creds: ntfy change-pass exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
			}
			if err := deps.Keychain.Set(ctx, "abysslink", "ntfy-password", pw); err != nil {
				return fmt.Errorf("rotate ntfy-creds: store: %w", err)
			}
			_ = deps.Platform.ServiceStop(ctx, "dev.abysslink.ntfy")
			_ = deps.Platform.ServiceStart(ctx, "dev.abysslink.ntfy")

			printerInfo(p, styleSuccess.Render("ntfy admin password rotated and stored in the keychain."))
			printerInfo(p, styleMuted.Render("Re-pair your phone: run `abysslink enroll phone` to get a fresh ntfy QR."))
			return nil
		},
	}
}

// updateRigScopedAnthropicKeys writes newKey over every rig-scoped
// anthropic-api-key copy that exists (created by enroll rig's keychain
// migration). Rigs that were never migrated are skipped. Extracted for unit
// testability with a mock keychain.
func updateRigScopedAnthropicKeys(ctx context.Context, kc secrets.KeychainStore, rigs []config.RigConfig, p Printer, newKey string) error {
	for _, rig := range rigs {
		svc := fleet.RigService(rig.Name)
		if _, getErr := kc.Get(ctx, svc, "anthropic-api-key"); getErr != nil {
			continue // never migrated for this rig — nothing to update
		}
		if setErr := kc.Set(ctx, svc, "anthropic-api-key", newKey); setErr != nil {
			return fmt.Errorf("rotate anthropic-key: update rig-scoped copy for %q: %w", rig.Name, setErr)
		}
		printerInfo(p, styleMuted.Render("Updated rig-scoped key copy: "+rig.Name))
	}
	return nil
}

// verifyAnthropicKey makes a 1-token ping to confirm the key authenticates.
// A 401/403 means the key is bad (ok=false); anything else (including 400)
// means auth ok. A transport failure (offline, DNS, timeout) is returned as a
// non-nil error so callers can distinguish "could not verify" from "rejected".
func verifyAnthropicKey(ctx context.Context, key string) (bool, error) {
	body := []byte(`{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("network: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden, nil
}
