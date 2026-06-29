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
	"archive/tar"
	"bufio"
	"compress/gzip"
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

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/limitio"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

const (
	upgradeRepo           = "abysslink/abysslink"
	upgradeOIDCIssuer     = "https://token.actions.githubusercontent.com"
	upgradeIdentityRegexp = `^https://github\.com/abysslink/abysslink/\.github/workflows/release\.yml@refs/tags/.*$`
)

// upgradeArtifactCeiling bounds downloaded/extracted release artifacts
// (200 MiB). Reads use an N+1 sentinel — never a silent truncation. Declared
// as a var so tests can exercise the overflow path with a small ceiling.
var upgradeArtifactCeiling int64 = 200 << 20 //nolint:gochecknoglobals // test seam for the overflow-sentinel path; production value is constant

// upgradeExitUpdateAvailable is the `upgrade --check` exit code signalling that
// a newer release exists (convention: softwareupdate / gh-style distinct code
// so cron/scripts can branch). 0 = up to date, 1 = error, 3 = update available.
const upgradeExitUpdateAvailable = 3

func newUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade abysslink to the latest release",
		Long: `Check GitHub for the latest release and (with --apply) download, verify the
cosign signature + SHA-256 checksum, and atomically self-replace the binary.

Exit codes with --check:
  0  — already up to date (or the installed build is newer than the latest release).
  1  — the check itself failed (network, API error).
  3  — a newer release is available.`,
		Example: `  # Preview the upgrade (dry-run — no changes)
  abysslink upgrade

  # Script-friendly check: exit 3 when a newer release is available
  abysslink upgrade --check

  # Download and install the latest release
  abysslink upgrade --apply`,
		RunE: func(c *cobra.Command, _ []string) error {
			if os.Getuid() == 0 {
				return fmt.Errorf("upgrade: refusing to run as root — run as your normal user")
			}

			checkOnly, _ := c.Flags().GetBool("check")
			apply, _ := c.Flags().GetBool("apply")
			force, _ := c.Flags().GetBool("force")
			p := newPrinter(c)

			latest, err := latestReleaseTag(c.Context())
			if err != nil {
				return fmt.Errorf("upgrade: check latest release: %w", err)
			}
			printerInfo(p, fmt.Sprintf("Installed: %s   Latest: %s", version, latest))

			// Semver comparison, not string equality: a build NEWER than the
			// latest release must not be advertised (and silently downgraded)
			// as "a newer release is available".
			rel := compareUpgradeVersions(version, latest)
			switch rel {
			case upgradeUpToDate:
				printerInfo(p, styleSuccess.Render("Already up to date."))
				return nil
			case upgradeInstalledNewer:
				printerInfo(p, styleWarn.Render("Installed version is NEWER than the latest release."))
				if checkOnly {
					return nil // not "update available" — exit 0
				}
				if !force {
					return fmt.Errorf("upgrade: installed %s is newer than latest release %s — refusing downgrade (pass --force to downgrade anyway)", version, latest)
				}
				printerInfo(p, styleWarn.Render("--force: downgrading to "+latest+"."))
			case upgradeNewerAvailable:
				printerInfo(p, styleWarn.Render("A newer release is available."))
			case upgradeUnknownInstalled:
				printerInfo(p, styleWarn.Render("Installed version is not a release build; latest release is "+latest+"."))
			}

			if checkOnly {
				// Distinct exit code so cron/scripts can branch (documented in Long).
				return &exitError{code: upgradeExitUpdateAvailable}
			}

			if !apply {
				printerInfo(p, "")
				printerInfo(p, "Run "+styleCode.Render("abysslink upgrade --apply")+" to self-update.")
				printerInfo(p, "Or use a trusted install path:")
				printerInfo(p, "  • "+styleCode.Render("curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/install.sh | bash"))
				printerInfo(p, "  • your package manager (brew / apt / dnf)")
				return nil
			}

			// --apply path: download → verify cosign → verify checksum → self-replace.
			// newRunner() keeps the exec-gate decoration (D-38) on the cosign call.
			return applyUpgrade(c.Context(), p, newRunner(), latest)
		},
	}
	cmd.Flags().Bool("check", false, "Only check for a newer version, do not upgrade (exit 3 when an update is available)")
	cmd.Flags().Bool("apply", false, "Download, verify signature, and self-replace the binary")
	cmd.Flags().Bool("force", false, "Allow installing the latest release even when the installed build is newer (downgrade)")
	return cmd
}

// Upgrade version relations as computed by compareUpgradeVersions.
const (
	upgradeUpToDate         = iota // installed == latest
	upgradeNewerAvailable          // installed < latest
	upgradeInstalledNewer          // installed > latest (downgrade territory)
	upgradeUnknownInstalled        // installed is not a semver (dev/unknown builds)
)

// compareUpgradeVersions classifies the installed/latest version relationship
// using the semver comparison shared with the headscale/netbird upgrade paths.
// A non-semver installed version (dev, unknown, commit hashes) cannot be
// ordered, so it is classified separately — those builds may install the
// latest release but are never told "already up to date".
func compareUpgradeVersions(installed, latest string) int {
	iv := normalizeTag(installed)
	lv := normalizeTag(latest)
	if iv == lv {
		return upgradeUpToDate
	}
	if semverParts(iv) == [3]int{} {
		// Not parseable as semver (e.g. "dev"): treat as unknown.
		return upgradeUnknownInstalled
	}
	if semverLT(iv, lv) {
		return upgradeNewerAvailable
	}
	if semverLT(lv, iv) {
		return upgradeInstalledNewer
	}
	// Same major.minor.patch but different raw tags (pre-release suffix):
	// treat as up to date rather than flapping.
	return upgradeUpToDate
}

// applyUpgrade downloads the release for the current OS/arch, verifies its
// cosign signature, checks SHA-256 integrity, and performs an atomic
// self-replace of the running binary.
func applyUpgrade(ctx context.Context, p Printer, runner shell.Runner, tag string) error {
	if err := checkCosignInstalled(); err != nil {
		return err
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("upgrade: resolve self path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return fmt.Errorf("upgrade: resolve symlinks: %w", err)
	}

	ver := strings.TrimPrefix(tag, "v")
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	tarball := fmt.Sprintf("abysslink_%s_%s_%s.tar.gz", ver, goos, goarch)
	checksums := fmt.Sprintf("abysslink_%s_checksums.txt", ver)
	baseURL := fmt.Sprintf("https://github.com/%s/releases/download/%s", upgradeRepo, tag)

	tmpDir, err := os.MkdirTemp("", "abysslink-upgrade-*")
	if err != nil {
		return fmt.Errorf("upgrade: create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Download all artifacts. The cosign v3 bundle embeds both the signature and
	// the signing certificate, so a single .bundle file replaces the v2 .sig/.pem pair.
	for _, name := range []string{tarball, checksums, checksums + ".bundle"} {
		dl := name
		// Animated liveness during each network download; spinWork is json-safe.
		if err := spinWork(ctx, p, "Downloading "+dl+"…", func(ctx context.Context) error {
			return downloadFile(ctx, baseURL+"/"+dl, filepath.Join(tmpDir, dl))
		}); err != nil {
			return fmt.Errorf("upgrade: download %s: %w", dl, err)
		}
	}

	// Fail-closed verification: cosign signature THEN SLSA provenance. Both
	// legs must pass before the binary is trusted; a failure on either aborts
	// the upgrade before the atomic replace ever runs.
	printerInfo(p, "  ✦  verifying cosign signature + SLSA provenance...")
	if err := verifyUpgradeArtifact(ctx, runner,
		filepath.Join(tmpDir, checksums),
		filepath.Join(tmpDir, checksums+".bundle"),
		filepath.Join(tmpDir, tarball),
	); err != nil {
		return fmt.Errorf("upgrade: %w — refusing to install", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  signature + provenance verified"))

	// Verify tarball SHA-256 against the signed checksum manifest.
	printerInfo(p, "  ✦  verifying checksum...")
	if err := verifyChecksum(filepath.Join(tmpDir, checksums), tarball, filepath.Join(tmpDir, tarball)); err != nil {
		return fmt.Errorf("upgrade: checksum verification FAILED: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  checksum verified"))

	// Extract binary from tarball.
	newBin, err := extractBinary(filepath.Join(tmpDir, tarball), tmpDir)
	if err != nil {
		return fmt.Errorf("upgrade: extract binary: %w", err)
	}

	// Atomic self-replace. nil sa → production keychain-backed audit (built inside).
	printerInfo(p, "  ↺  replacing "+selfPath)
	if err := atomicReplace(ctx, selfPath, newBin, nil); err != nil {
		return fmt.Errorf("upgrade: self-replace: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  upgraded to "+tag))
	printerInfo(p, "  Run "+styleCode.Render("abysslink version")+" to confirm.")
	return nil
}

// checkCosignInstalled returns an error with install guidance if cosign is absent.
// Uses shell.LookPath (CLI-16) — never os/exec outside internal/shell.
func checkCosignInstalled() error {
	if !shell.LookPath("cosign") {
		return fmt.Errorf("upgrade: cosign not found — install it first:\n" +
			"  https://docs.sigstore.dev/cosign/system_config/installation/\n" +
			"  brew install cosign   (macOS)\n" +
			"  go install github.com/sigstore/cosign/v2/cmd/cosign@latest")
	}
	return nil
}

// verifyUpgradeArtifact runs the full fail-closed verification for the upgrade
// path: (1) the cosign v3 bundle signature on the checksum manifest, then
// (2) the SLSA build provenance on the release tarball via `gh attestation
// verify --signer-workflow`. Both legs must pass; a failure (or an absent
// cosign/gh) returns an error so applyUpgrade aborts before the atomic replace.
// All exec routes through the injected shell.Runner — never os/exec.
func verifyUpgradeArtifact(ctx context.Context, runner shell.Runner, checksums, bundle, tarball string) error {
	if err := verifyCosignBlob(ctx, runner, checksums, bundle); err != nil {
		return fmt.Errorf("cosign verification FAILED: %w", err)
	}
	if err := verifyGHAttestation(ctx, runner, tarball, slsaSignerWorkflow); err != nil {
		return fmt.Errorf("SLSA provenance verification FAILED: %w", err)
	}
	return nil
}

// verifyCosignBlob verifies the cosign v3 keyless signature on target using the
// provided .bundle file from the release. The bundle embeds the signature and
// signing certificate, so no separate .sig/.pem files are needed. It delegates
// to verifyCosignBundle, which runs cosign in --offline mode (no Rekor lookup).
func verifyCosignBlob(ctx context.Context, runner shell.Runner, target, bundleFile string) error {
	return verifyCosignBundle(ctx, runner, target, bundleFile)
}

// verifyChecksum reads the sha256 checksum file and checks that the file at
// filePath matches the recorded hash for wantName.
func verifyChecksum(checksumFile, wantName, filePath string) error {
	f, err := os.Open(checksumFile) //nolint:gosec // G304: checksumFile is an internally-staged download temp path, not user input
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		want, name := parts[0], parts[1]
		if strings.TrimPrefix(name, "*") != wantName {
			continue
		}
		got, err := sha256File(filePath)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("SHA-256 mismatch for %s: got %s want %s", wantName, got, want)
		}
		return nil
	}
	if err := sc.Err(); err != nil {
		// A read error mid-scan would otherwise look like "entry absent" —
		// surface it so a truncated checksum file never passes silently.
		return fmt.Errorf("read checksum file %s: %w", checksumFile, err)
	}
	return fmt.Errorf("no checksum entry found for %s in %s", wantName, checksumFile)
}

// sha256File returns the lower-hex SHA-256 of a file.
func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is an internally-staged download temp path, not user input
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// extractBinary extracts the `abysslink` binary from a .tar.gz archive to outDir.
func extractBinary(tarPath, outDir string) (string, error) {
	f, err := os.Open(tarPath) //nolint:gosec // G304: tarPath is an internally-staged download temp path, not user input
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if base != "abysslink" && base != "abysslink.exe" {
			continue
		}
		outPath := filepath.Join(outDir, base)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) //nolint:gosec // G302: 0o755 required — extracted file is an executable binary
		if err != nil {
			return "", err
		}
		// N+1 sentinel: a bare LimitReader would silently TRUNCATE an oversize
		// binary AFTER checksum verification — installing a truncated "verified"
		// binary. Copy one byte past the cap and fail when it arrives.
		// nosemgrep: go.lang.security.decompression_bomb.potential-dos-via-decompression-bomb
		n, err := io.Copy(out, io.LimitReader(tr, upgradeArtifactCeiling+1)) //nolint:gosec // G110: bounded copy with N+1 overflow sentinel — decompression bomb mitigated
		if err != nil {
			_ = out.Close()
			return "", err
		}
		_ = out.Close()
		if n > upgradeArtifactCeiling {
			return "", fmt.Errorf("extracted binary exceeds %d byte ceiling — refusing truncated install", int64(upgradeArtifactCeiling))
		}
		return outPath, nil
	}
	return "", fmt.Errorf("abysslink binary not found in archive")
}

// atomicReplace replaces dst with src via audit.WriteFilePath — streaming
// io.Copy with a 256 MiB ceiling (D-06 / WR-02). WriteFilePath handles temp
// creation, chmod, and atomic rename; the binary is never fully in memory.
// Per CLAUDE.md hard rule: every file mutation goes through internal/audit.
// The keychain store uses shell.ExecRunner — keychain operations are always
// real system calls and must never be routed through the CLI mock runner.
// atomicReplace streams src over dst through the tamper-evident audit log.
// A nil sa builds the production keychain-backed audit (real keychain via
// ExecRunner — keychain ops are real system calls, never the CLI mock runner).
// Tests inject a SignedAudit backed by a mock keychain + temp log so the path is
// exercisable on platforms without a libsecret/Keychain backend (e.g. Linux CI).
func atomicReplace(ctx context.Context, dst, src string, sa *audit.SignedAudit) error {
	if sa == nil {
		logPath, err := audit.DefaultLogPath()
		if err != nil {
			return fmt.Errorf("atomicReplace: audit log path: %w", err)
		}
		kc, err := secrets.NewStore(ctx, &shell.ExecRunner{})
		if err != nil {
			return fmt.Errorf("atomicReplace: keychain: %w", err)
		}
		sa, err = audit.NewSigned(logPath, kc)
		if err != nil {
			return fmt.Errorf("atomicReplace: audit init: %w", err)
		}
	}
	if err := sa.WriteFilePath(ctx, src, dst, 0o755, false); err != nil {
		return fmt.Errorf("atomicReplace: write: %w", err)
	}
	return nil
}

// downloadFile downloads url to dest, following redirects.
func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(limitio.ReadSnippet(resp.Body)))
	}
	f, err := os.Create(dest) //nolint:gosec // G304: dest is an internally-derived download temp path, not user input
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	// N+1 sentinel: never silently truncate at the cap (a truncated download
	// would otherwise surface only as a confusing checksum mismatch — or not at
	// all for callers without a checksum step).
	n, err := io.Copy(f, io.LimitReader(resp.Body, upgradeArtifactCeiling+1)) //nolint:gosec // G110: bounded copy with N+1 overflow sentinel — oversize bomb mitigated
	if err != nil {
		return err
	}
	if n > upgradeArtifactCeiling {
		return fmt.Errorf("download %s exceeds %d byte ceiling — refusing truncated artifact", url, int64(upgradeArtifactCeiling))
	}
	return nil
}

// latestReleaseTag returns the tag_name of the latest GitHub release.
func latestReleaseTag(ctx context.Context) (string, error) {
	const url = "https://api.github.com/repos/abysslink/abysslink/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, strings.TrimSpace(limitio.ReadSnippet(resp.Body)))
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	relData, err := limitio.ReadLimited(resp.Body, limitio.MaxBackendBody)
	if err != nil {
		return "", fmt.Errorf("GitHub releases: read response: %w", err)
	}
	if err := json.Unmarshal(relData, &rel); err != nil {
		return "", fmt.Errorf("GitHub releases: decode response: %w", err)
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("no tag_name in latest release")
	}
	return rel.TagName, nil
}

// normalizeTag strips a leading "v" so "v1.2.3" and "1.2.3" compare equal.
func normalizeTag(t string) string { return strings.TrimPrefix(strings.TrimSpace(t), "v") }
