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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// verifyResult is the JSON record emitted by `abysslink verify --json`.
type verifyResult struct {
	BundleOK bool   `json:"bundle_ok"`
	SLSAOK   bool   `json:"slsa_ok"`
	Version  string `json:"version"`
	Commit   string `json:"commit"`
}

// verifyCosignBundle verifies a cosign v3 bundle file against a target artifact.
// Uses --offline so Rekor transparency-log lookup is not required (Pitfall 14
// mitigation: verification must work air-gapped and never depend on a network
// service that could fail open). All exec goes through shell.Runner per the
// CLAUDE.md hard rule — never os/exec directly.
func verifyCosignBundle(ctx context.Context, runner shell.Runner, target, bundleFile string) error {
	res, err := runner.Run(ctx, "cosign", "verify-blob",
		"--bundle", bundleFile,
		"--offline",
		"--certificate-identity-regexp", upgradeIdentityRegexp,
		"--certificate-oidc-issuer", upgradeOIDCIssuer,
		target,
	)
	if err != nil {
		// A non-nil error from the runner typically means the cosign binary
		// could not be executed (not on PATH). Surface a clear message.
		return fmt.Errorf("cosign not found or failed to execute: %w", err)
	}
	if res.ExitCode != 0 {
		combined := strings.TrimSpace(res.Stdout + res.Stderr)
		return fmt.Errorf("cosign verify-blob exited %d: %s", res.ExitCode, combined)
	}
	return nil
}

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the installed binary's cosign signature and SLSA provenance",
		Long: `Fetch the cosign v3 bundle and checksum manifest for this release and
verify them offline (no Rekor dependency). Optionally confirms that a SLSA
provenance attestation is published for the release artifacts.`,
		Example: `  # Verify the running binary's release signature
  abysslink verify

  # Machine-readable result
  abysslink verify --json`,
		GroupID: "ops",
		RunE: func(c *cobra.Command, _ []string) error {
			jsonOut, _ := c.Flags().GetBool("json")
			bundleOverride, _ := c.Flags().GetString("bundle")
			verOverride, _ := c.Flags().GetString("version")
			p := newPrinter(c)
			return runVerify(c.Context(), p, &shell.ExecRunner{}, verifyOpts{
				jsonOut:        jsonOut,
				bundleOverride: bundleOverride,
				version:        verOverride,
			})
		},
	}
	cmd.Flags().Bool("json", false, "emit the verification result as JSON")
	cmd.Flags().String("bundle", "", "path to a local cosign bundle file (overrides the auto-downloaded one)")
	cmd.Flags().String("version", version, "release version to verify against (defaults to the running build)")
	return cmd
}

// verifyOpts carries the resolved flag values for runVerify.
type verifyOpts struct {
	jsonOut        bool
	bundleOverride string
	version        string
}

// runVerify performs the on-demand cosign v3 bundle verification plus an
// informational SLSA provenance presence check. The runner is injected so tests
// can substitute a shell.MockRunner for the cosign invocation. Network access is
// only used to download the bundle/checksums; tests pass a --bundle override and
// a synthetic version to keep cosign mockable while download is skipped.
func runVerify(ctx context.Context, p Printer, runner shell.Runner, opts verifyOpts) error {
	ver := strings.TrimPrefix(opts.version, "v")
	if ver == "" {
		ver = strings.TrimPrefix(version, "v")
	}

	// CLI-28: a dev/unknown build has no published release artifacts — without
	// this gate the command would try to download abysslink_dev_checksums.txt
	// and fail with an opaque HTTP error. Short-circuit with clear guidance
	// unless the user supplied a local --bundle to verify against.
	if (ver == "dev" || ver == "unknown") && opts.bundleOverride == "" {
		return fmt.Errorf("verify: this is a development build (version %q) with no published release artifacts to verify; "+
			"pass --version vX.Y.Z to verify a specific release, or --bundle <path> to verify a local cosign bundle", ver)
	}

	tmpDir, err := os.MkdirTemp("", "abysslink-verify-*")
	if err != nil {
		return fmt.Errorf("verify: create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	checksumPath, bundlePath, err := resolveVerifyArtifacts(ctx, tmpDir, ver, opts.bundleOverride)
	if err != nil {
		return err
	}

	// Verify the cosign v3 bundle offline.
	bundleOK := true
	verr := verifyCosignBundle(ctx, runner, checksumPath, bundlePath)
	if verr != nil {
		bundleOK = false
	}

	// Informational SLSA provenance presence check (best-effort, never fatal).
	// Skipped when a local bundle override is supplied (offline / test mode):
	// the attestations API lookup requires network and is purely advisory.
	slsaOK := false
	if opts.bundleOverride == "" {
		slsaOK = slsaProvenanceExists(ctx, checksumPath)
	}

	res := verifyResult{
		BundleOK: bundleOK,
		SLSAOK:   slsaOK,
		Version:  ver,
		Commit:   commit,
	}

	if opts.jsonOut {
		p.PrintJSON(res)
		if !bundleOK {
			return &exitError{code: exitCodeError}
		}
		return nil
	}

	emitVerifyHuman(p, res, verr)
	if !bundleOK {
		return &exitError{code: exitCodeError}
	}
	return nil
}

// resolveVerifyArtifacts resolves the checksum + bundle file paths for the
// target version: both are downloaded unless a local bundle override is
// supplied, in which case a co-located checksums file is preferred and only
// the checksums are downloaded when absent. Extracted from runVerify to keep
// it under the gocyclo threshold.
func resolveVerifyArtifacts(ctx context.Context, tmpDir, ver, bundleOverride string) (checksumPath, bundlePath string, err error) {
	checksumName := fmt.Sprintf("abysslink_%s_checksums.txt", ver)
	baseURL := fmt.Sprintf("https://github.com/%s/releases/download/v%s", upgradeRepo, ver)

	checksumPath = filepath.Join(tmpDir, checksumName)
	bundlePath = bundleOverride

	if bundlePath == "" {
		// Auto-download bundle + checksums for the target version.
		bundlePath = filepath.Join(tmpDir, checksumName+".bundle")
		if err := downloadFile(ctx, baseURL+"/"+checksumName, checksumPath); err != nil {
			return "", "", fmt.Errorf("verify: download checksums: %w", err)
		}
		if err := downloadFile(ctx, baseURL+"/"+checksumName+".bundle", bundlePath); err != nil {
			return "", "", fmt.Errorf("verify: download bundle: %w", err)
		}
		return checksumPath, bundlePath, nil
	}

	// A local bundle was supplied. Use a sibling checksums file if present,
	// otherwise download just the checksums to verify against the bundle.
	sibling := filepath.Join(filepath.Dir(bundlePath), checksumName)
	if _, statErr := os.Stat(sibling); statErr == nil {
		checksumPath = sibling
	} else if err := downloadFile(ctx, baseURL+"/"+checksumName, checksumPath); err != nil {
		return "", "", fmt.Errorf("verify: download checksums: %w", err)
	}
	return checksumPath, bundlePath, nil
}

// emitVerifyHuman prints a human-readable verification summary.
func emitVerifyHuman(p Printer, res verifyResult, verr error) {
	printerInfo(p, styleBold.Render("abysslink verify")+"  "+styleMuted.Render("v"+res.Version))
	if res.BundleOK {
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("cosign bundle verified (offline)"))
	} else {
		msg := "cosign bundle verification FAILED"
		if verr != nil {
			msg += ": " + verr.Error()
		}
		printerInfo(p, "  "+iconFatalStr()+"  "+styleFatal.Render(msg))
	}
	if res.SLSAOK {
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("SLSA provenance attestation found"))
	} else {
		printerInfo(p, "  "+iconWarnStr()+"  "+styleWarn.Render("no SLSA provenance attestation found (informational)"))
	}
}

// slsaProvenanceExists queries the GitHub attestations API for a SLSA provenance
// attestation bound to the sha256 digest of the checksum file. Returns true only
// when the API responds 200 with at least one attestation. Any error or non-200
// response yields false — provenance is informational, never fatal.
func slsaProvenanceExists(ctx context.Context, checksumPath string) bool {
	data, err := os.ReadFile(checksumPath) //nolint:gosec // G304: checksumPath is an internally-derived checksum file path, not user input
	if err != nil {
		return false
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	url := fmt.Sprintf("https://api.github.com/repos/%s/attestations/sha256:%s", upgradeRepo, digest)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false
	}
	// Decode the envelope and check for a populated attestations array rather
	// than substring-guessing the raw JSON (which could false-positive on an
	// empty array that merely mentions "bundle", or false-negative on a schema
	// change).
	var ar struct {
		Attestations []json.RawMessage `json:"attestations"`
	}
	if json.Unmarshal(body, &ar) != nil {
		return false
	}
	return len(ar.Attestations) > 0
}
