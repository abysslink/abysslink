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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/evidence"
	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/spf13/cobra"
)

// isJSON reports whether p emits machine-readable JSON (the --json path).
func isJSON(p Printer) bool { _, ok := p.(*jsonPrinter); return ok }

// newAuditEvidenceCmd builds `abysslink audit evidence`: produce a signed,
// externally-verifiable audit-evidence bundle (.alevidence) for a SOC 2 auditor
// or a compliance platform. Distinct from `audit export` (raw JSONL dump): this
// attests the chain-verification result and ed25519-signs the manifest.
func newAuditEvidenceCmd() *cobra.Command {
	var out, since, until string
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Build a signed audit-evidence bundle (.alevidence) for compliance/audit",
		Long: `Build a signed, externally-verifiable evidence bundle from the audit log.

The bundle (a .alevidence tar.gz) contains the hash-chained audit entries, a
human-readable report, and a manifest that attests the chain-verification
result. The manifest is ed25519-signed with the rig's evidence key so an
auditor can verify it WITHOUT the (secret) HMAC key — they pin the signing
key's fingerprint, printed below, out-of-band.

Read-only: the audit log is never modified. Verify a bundle with
` + "`abysslink audit verify-evidence`" + `.`,
		Example: `  # Write a full-history evidence bundle
  abysslink audit evidence --out evidence.alevidence

  # Only actions since a timestamp
  abysslink audit evidence --since 2026-07-01T00:00:00Z --out july.alevidence`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			commandHeader(p, "audit evidence", styleMuted.Render("build a signed audit-evidence bundle"))

			logPath, err := audit.DefaultLogPath()
			if err != nil {
				return fmt.Errorf("audit evidence: %w", err)
			}
			kc := auditKeychain(ctx, cc)
			if kc == nil {
				return fmt.Errorf("audit evidence: no keychain backend available — cannot sign the bundle")
			}

			if out == "" {
				return fmt.Errorf("audit evidence: --out FILE is required")
			}
			// Refuse to clobber an existing file: an evidence bundle is a record;
			// silently overwriting one is the wrong default.
			if _, statErr := os.Stat(out); statErr == nil {
				return fmt.Errorf("audit evidence: %s already exists — choose a different --out path", out)
			}

			f, ferr := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // out is an operator-supplied output path
			if ferr != nil {
				return fmt.Errorf("audit evidence: create %s: %w", out, ferr)
			}
			defer func() { _ = f.Close() }()

			m, cerr := evidence.Create(ctx, kc, evidence.CreateOptions{
				LogPath:          logPath,
				Hostname:         notifyv2.ShortHostname(),
				AbysslinkVersion: version,
				Since:            since,
				Until:            until,
				Now:              time.Now(),
			}, f)
			if cerr != nil {
				_ = os.Remove(out) // don't leave a half-written bundle
				return fmt.Errorf("audit evidence: %w", cerr)
			}

			if isJSON(p) {
				p.PrintJSON(m)
				return nil
			}
			printerInfo(p, styleSuccess.Render("Evidence bundle written: ")+styleCode.Render(out))
			verdict := "VALID"
			if !m.Chain.Verified {
				verdict = "NOT VALID — see the bundle report"
			}
			printerInfo(p, styleMuted.Render(fmt.Sprintf("Chain: %s (%d entries, %d signatures verified, key epoch %d).",
				verdict, m.Chain.EntryCount, m.Chain.SigsVerified, m.Chain.KeyEpoch)))
			printerInfo(p, styleMuted.Render("Signing key fingerprint (give this to your auditor to pin):"))
			printerInfo(p, "  "+styleCode.Render(m.Signing.Fingerprint))
			printerInfo(p, styleMuted.Render("Verify with: ")+styleCode.Render("abysslink audit verify-evidence "+out))
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "output path for the .alevidence bundle (required)")
	cmd.Flags().StringVar(&since, "since", "", "only include actions at/after this RFC3339 UTC time")
	cmd.Flags().StringVar(&until, "until", "", "only include actions at/before this RFC3339 UTC time")
	return cmd
}

// newAuditVerifyEvidenceCmd builds `abysslink audit verify-evidence FILE`:
// verify a bundle's ed25519 signature and content hashes, and surface the
// signing-key fingerprint for out-of-band comparison. Exit 0 valid, 2 invalid.
func newAuditVerifyEvidenceCmd() *cobra.Command {
	var expectKey string
	cmd := &cobra.Command{
		Use:   "verify-evidence FILE",
		Short: "Verify a signed audit-evidence bundle (.alevidence)",
		Args:  cobra.ExactArgs(1),
		Long: `Verify an evidence bundle's ed25519 signature and pinned content hashes.

This confirms the bundle is internally intact and authentic to its signing key.
It prints the signing-key fingerprint: an auditor MUST compare it to the value
the operator stated out-of-band — a valid signature over an unexpected key is
still "internally valid". Pass --expect-key to assert the fingerprint and fail
closed on a mismatch.`,
		Example: `  abysslink audit verify-evidence evidence.alevidence
  abysslink audit verify-evidence --expect-key <sha256> evidence.alevidence`,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := newPrinter(cmd)
			f, err := os.Open(args[0]) //nolint:gosec // operator-supplied bundle path
			if err != nil {
				return fmt.Errorf("audit verify-evidence: open %s: %w", args[0], err)
			}
			defer func() { _ = f.Close() }()

			res, verr := evidence.Verify(f)
			if verr != nil {
				return &exitError{code: exitCodeFatal, err: fmt.Errorf("audit verify-evidence: %w", verr)}
			}

			if isJSON(p) {
				p.PrintJSON(res)
			}

			if !res.Valid {
				if !isJSON(p) {
					p.Error(styleFatal.Render("INVALID: ") + res.Reason)
				}
				return &exitError{code: exitCodeFatal, err: fmt.Errorf("evidence bundle failed verification: %s", res.Reason)}
			}
			// Signature + hashes good. Enforce the operator's pin if given.
			if expectKey != "" && !strings.EqualFold(expectKey, res.Fingerprint) {
				if !isJSON(p) {
					p.Error(styleFatal.Render("KEY MISMATCH: ") +
						fmt.Sprintf("bundle signed by %s, expected %s", res.Fingerprint, expectKey))
				}
				return &exitError{code: exitCodeFatal, err: fmt.Errorf("evidence signing key %s does not match --expect-key %s", res.Fingerprint, expectKey)}
			}

			if !isJSON(p) {
				printerInfo(p, styleSuccess.Render("VALID")+styleMuted.Render(" — signature and content hashes verified."))
				verdict := "VALID"
				if !res.Manifest.Chain.Verified {
					verdict = "NOT VALID"
				}
				printerInfo(p, styleMuted.Render(fmt.Sprintf("Attested chain: %s (%d entries, %d signatures verified, key epoch %d).",
					verdict, res.Manifest.Chain.EntryCount, res.Manifest.Chain.SigsVerified, res.Manifest.Chain.KeyEpoch)))
				printerInfo(p, styleMuted.Render("Signed by key fingerprint (compare to your pinned value):"))
				printerInfo(p, "  "+styleCode.Render(res.Fingerprint))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&expectKey, "expect-key", "", "fail unless the bundle is signed by this key fingerprint (SHA-256 hex)")
	return cmd
}
