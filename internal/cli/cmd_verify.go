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
	"runtime"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// slsaOwner / slsaSignerWorkflow bind `gh attestation verify` to the exact
// isolated reusable workflow that produces the release provenance (SLSA Build
// L3). The owner scopes the attestation lookup; --signer-workflow is what
// enforces that the provenance came from THIS pipeline and nothing else.
const (
	slsaOwner          = "abysslink"
	slsaSignerWorkflow = "abysslink/abysslink/.github/workflows/release-build.yml"
)

// verifyResult is the JSON record emitted by `abysslink verify --json`.
type verifyResult struct {
	BundleOK bool `json:"bundle_ok"`
	// BinaryChecked is true when the running executable was hashed against the
	// release binary extracted from the signed-manifest-verified tarball. It is
	// false in --bundle override (offline/test) mode, where no release
	// artifacts are downloaded.
	BinaryChecked bool `json:"binary_checked"`
	BinaryOK      bool `json:"binary_ok"`
	// SLSAChecked is true when the fail-closed `gh attestation verify` leg ran
	// (the network verify path). It is false in --bundle override (offline/test)
	// mode, where provenance is only an advisory presence check via the API.
	SLSAChecked bool   `json:"slsa_checked"`
	SLSAOK      bool   `json:"slsa_ok"`
	Version     string `json:"version"`
	Commit      string `json:"commit"`
}

// verifyGHAttestation verifies the SLSA build provenance for target by invoking
// `gh attestation verify --signer-workflow`, the ONLY verifier compatible with
// actions/attest-build-provenance output (slsa-verifier rejects it). This is
// the fail-closed contract: a non-zero exit (tampered/missing provenance) OR an
// inability to execute gh (gh absent) both return an error — never a warning
// that proceeds. All exec goes through shell.Runner per the CLAUDE.md hard rule.
func verifyGHAttestation(ctx context.Context, runner shell.Runner, target, signerWorkflow string) error {
	res, err := runner.Run(ctx, "gh", "attestation", "verify", target,
		"--owner", slsaOwner,
		"--signer-workflow", signerWorkflow,
	)
	if err != nil {
		// A non-nil runner error means gh could not be executed (not on PATH).
		// Fail closed with install guidance (Open Question 2).
		return fmt.Errorf("gh not found or failed to execute — cannot verify SLSA provenance "+
			"(install the GitHub CLI: https://cli.github.com): %w", err)
	}
	if res.ExitCode != 0 {
		combined := strings.TrimSpace(res.Stdout + res.Stderr)
		return fmt.Errorf("gh attestation verify exited %d (SLSA provenance missing or invalid): %s", res.ExitCode, combined)
	}
	return nil
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
		Long: `Fetch the cosign v3 bundle and checksum manifest for this release, verify
them offline (no Rekor dependency), then hash the RUNNING executable against
the released binary extracted from the checksum-verified tarball — a locally
tampered binary fails verification. Optionally confirms that a SLSA provenance
attestation is published for the release artifacts.

With --bundle (offline/test mode) only the manifest signature is verified; the
binary self-check is skipped because no release artifacts are downloaded.`,
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
			// newRunner() keeps the exec-gate decoration (D-38) on the cosign
			// invocation — never a bare ExecRunner.
			return runVerify(c.Context(), p, newRunner(), verifyOpts{
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

	// Self-verification: hash the RUNNING executable against the release binary
	// from the signed-manifest-verified tarball. Without this step a locally
	// tampered binary would pass `abysslink verify` on the strength of the
	// manifest signature alone. Skipped in --bundle override (offline/test)
	// mode and when the bundle itself failed (an unverified manifest proves
	// nothing about the binary).
	binaryChecked, binaryOK := false, false
	var binErr error
	if bundleOK && opts.bundleOverride == "" {
		binaryChecked = true
		binaryOK, binErr = verifySelfBinary(ctx, tmpDir, ver, checksumPath)
	}

	res := verifyResult{
		BundleOK:      bundleOK,
		BinaryChecked: binaryChecked,
		BinaryOK:      binaryOK,
		SLSAChecked:   false,
		SLSAOK:        false,
		Version:       ver,
		Commit:        commit,
	}

	// SLSA provenance leg.
	//   • Network path (no --bundle): FAIL-CLOSED via `gh attestation verify
	//     --signer-workflow`. A missing/invalid provenance — or an absent gh —
	//     maps to a non-zero exit (the locked fail-closed decision, OQ2). The
	//     tarball downloaded by verifySelfBinary is reused as the verify target.
	//   • Offline --bundle path: only an advisory API presence check (no gh
	//     requirement, purely informational, never fatal).
	var slsaErr error
	if opts.bundleOverride == "" {
		res.SLSAChecked = true
		tarball := fmt.Sprintf("abysslink_%s_%s_%s.tar.gz", ver, runtime.GOOS, runtime.GOARCH)
		slsaErr = verifyGHAttestation(ctx, runner, filepath.Join(tmpDir, tarball), slsaSignerWorkflow)
		res.SLSAOK = slsaErr == nil
	} else {
		res.SLSAOK = slsaProvenanceExists(ctx, checksumPath)
	}

	return emitVerifyResult(p, res, opts.jsonOut, verr, binErr, slsaErr)
}

// emitVerifyResult renders the verification result (JSON or human) and maps
// any bundle/binary failure to exit 1. Extracted from runVerify (gocyclo).
func emitVerifyResult(p Printer, res verifyResult, jsonOut bool, verr, binErr, slsaErr error) error {
	if jsonOut {
		p.PrintJSON(res)
	} else {
		emitVerifyHuman(p, res, verr, binErr, slsaErr)
	}
	// Fail-closed: any failed leg maps to a non-zero exit. The SLSA leg is
	// fatal only when it was actually run (network path) — never in the
	// advisory --bundle offline mode.
	if !res.BundleOK || (res.BinaryChecked && !res.BinaryOK) || (res.SLSAChecked && !res.SLSAOK) {
		return &exitError{code: exitCodeError}
	}
	return nil
}

// verifySelfBinary downloads the release tarball for this OS/arch, verifies its
// SHA-256 against the (already cosign-verified) checksum manifest, extracts the
// abysslink binary, and compares its SHA-256 with the running executable's.
// Returns (true, nil) only when the running binary is byte-identical to the
// released one.
func verifySelfBinary(ctx context.Context, tmpDir, ver, checksumPath string) (bool, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("resolve running executable: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return false, fmt.Errorf("resolve symlinks: %w", err)
	}

	tarball := fmt.Sprintf("abysslink_%s_%s_%s.tar.gz", ver, runtime.GOOS, runtime.GOARCH)
	baseURL := fmt.Sprintf("https://github.com/%s/releases/download/v%s", upgradeRepo, ver)
	tarPath := filepath.Join(tmpDir, tarball)
	if err := downloadFile(ctx, baseURL+"/"+tarball, tarPath); err != nil {
		return false, fmt.Errorf("download release tarball: %w", err)
	}
	// The tarball hash MUST match the signed manifest before its contents are
	// trusted as the comparison baseline.
	if err := verifyChecksum(checksumPath, tarball, tarPath); err != nil {
		return false, fmt.Errorf("tarball checksum: %w", err)
	}
	released, err := extractBinary(tarPath, tmpDir)
	if err != nil {
		return false, fmt.Errorf("extract released binary: %w", err)
	}

	selfSum, err := sha256File(selfPath)
	if err != nil {
		return false, fmt.Errorf("hash running executable: %w", err)
	}
	releasedSum, err := sha256File(released)
	if err != nil {
		return false, fmt.Errorf("hash released binary: %w", err)
	}
	if selfSum != releasedSum {
		return false, fmt.Errorf("running binary sha256 %s does not match released v%s binary sha256 %s — the installed binary is NOT the released artifact", selfSum, ver, releasedSum)
	}
	return true, nil
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
func emitVerifyHuman(p Printer, res verifyResult, verr, binErr, slsaErr error) {
	commandHeader(p, "verify", styleMuted.Render("v"+res.Version))
	if res.BundleOK {
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("cosign bundle verified (offline)"))
	} else {
		msg := "cosign bundle verification FAILED"
		if verr != nil {
			msg += ": " + verr.Error()
		}
		printerInfo(p, "  "+iconFatalStr()+"  "+styleFatal.Render(msg))
	}
	switch {
	case res.BinaryChecked && res.BinaryOK:
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("running binary matches the released artifact (sha256)"))
	case res.BinaryChecked:
		msg := "running binary does NOT match the released artifact"
		if binErr != nil {
			msg += ": " + binErr.Error()
		}
		printerInfo(p, "  "+iconFatalStr()+"  "+styleFatal.Render(msg))
	default:
		printerInfo(p, "  "+iconWarnStr()+"  "+styleWarn.Render("binary self-check skipped (local --bundle mode or bundle verification failed)"))
	}
	switch {
	case res.SLSAChecked && res.SLSAOK:
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("SLSA provenance verified (gh attestation verify --signer-workflow)"))
	case res.SLSAChecked:
		// Fail-closed leg failed: this is fatal, not informational.
		msg := "SLSA provenance verification FAILED"
		if slsaErr != nil {
			msg += ": " + slsaErr.Error()
		}
		printerInfo(p, "  "+iconFatalStr()+"  "+styleFatal.Render(msg))
	case res.SLSAOK:
		printerInfo(p, "  "+iconDoneStr()+"  "+styleSuccess.Render("SLSA provenance attestation found"))
	default:
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
