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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/limitio"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	headscaleDefaultVersion = "v0.28.0"
	headscaleMinVersion     = "v0.23.0"
	headscaleBaseURL        = "https://github.com/juanfont/headscale/releases/download"
	headscaleAPIKeyService  = "abysslink"
	headscaleAPIKeyAccount  = "headscale-api-key" //nolint:gosec // service name for keychain lookup, not a credential
	headscalePreAuthService = "abysslink"
	headscalePreAuthAccount = "headscale-preauth-key" //nolint:gosec // service name for keychain lookup, not a credential
	// preAuthKeyExpiry is the default pre-auth key lifetime (D-11: explicit expiry required).
	preAuthKeyExpiry = 1 * time.Hour
)

// ── Command tree ──────────────────────────────────────────────────────────────

// newServerCmd returns the "server" parent command. It is registered in root.go
// opsCmds so it appears under the Operations group.
func newServerCmd() *cobra.Command {
	srv := &cobra.Command{
		Use:   "server",
		Short: "Manage self-hosted backend server (Headscale, NetBird)",
	}
	srv.AddCommand(newServerHeadscaleCmd())
	srv.AddCommand(newServerNetBirdCmd())
	return srv
}

// newServerHeadscaleCmd returns the "server headscale" sub-group with four
// subcommands: init, status, upgrade, backup.
func newServerHeadscaleCmd() *cobra.Command {
	hs := &cobra.Command{
		Use:   "headscale",
		Short: "Manage a locally-provisioned Headscale control server",
	}
	hs.AddCommand(
		newServerHeadscaleInitCmd(),
		newServerHeadscaleStatusCmd(),
		newServerHeadscaleUpgradeCmd(),
		newServerHeadscaleBackupCmd(),
	)
	return hs
}

// ── init subcommand ────────────────────────────────────────────────────────────

func newServerHeadscaleInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Download, configure, and start Headscale (dry-run by default)",
		Example: `  # Preview what init would do (dry-run — no changes)
  abysslink server headscale init

  # Execute the full provisioning sequence
  abysslink server headscale init --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			runner := cc.runner
			return headscaleInitRunE(cmd.Context(), cc.cfg, cc, runner)
		},
	}
}

// headscaleInitRunE is the testable implementation of "server headscale init".
// The init sequence follows the security-safe order from the plan:
//
//	Step 0: TLS gate — backend.ValidateHeadscaleTLS (fail-closed, before any mutation)
//	Step 1-2: Download binary + verify SHA-256 checksum (R-01)
//	Step 3: macOS xattr quarantine clear (ignore error)
//	Step 4: Version floor check (>= v0.23.0) on temp binary
//	Step 5: Write binary via audit.WriteFile mode 0o755
//	Step 6: MergeHeadscaleConfig (hardened config.yaml)
//	Step 7-11: Service install + health-check + API key + user-ensure + pre-auth key
//	           (delegated to completeInit — skipped in dryRun mode)
func headscaleInitRunE(ctx context.Context, cfg *config.Config, cc *cmdContext, runner shell.Runner) error {
	p := newHumanPrinterStdout()

	// ── Step 0: TLS gate (fail-closed, before any mutation) ───────────────────
	// This call imports internal/backend (cli→backend direction — no cycle).
	// TLS gate always runs, even in dry-run mode.
	if err := backend.ValidateHeadscaleTLS(ctx, cfg); err != nil {
		return fmt.Errorf("headscale init: TLS validation failed: %w", err)
	}

	// ── Dry-run gate ──────────────────────────────────────────────────────────
	if cc.dryRun {
		slog.InfoContext(ctx, "headscale init [dry-run]",
			"binary_path", headscaleBinaryPath(cfg),
			"config_path", headscaleConfigPath(cfg),
			"version", headscaleVersion(),
			"acme", cfg.Server.Headscale.ACME,
		)
		printerInfo(p, "[plan] headscale init:")
		printerInfo(p, "  1. Download headscale "+headscaleVersion()+" + checksums.txt (HTTPS)")
		printerInfo(p, "  2. Verify SHA-256 checksum")
		printerInfo(p, "  3. Clear macOS quarantine (if darwin)")
		printerInfo(p, "  4. Check version floor >= "+headscaleMinVersion)
		printerInfo(p, "  5. Write binary to "+headscaleBinaryPath(cfg))
		printerInfo(p, "  6. Merge hardened config.yaml → "+headscaleConfigPath(cfg))
		printerInfo(p, "  7. Install + start service (systemd/launchd)")
		printerInfo(p, "  8. Health-check (30s timeout)")
		printerInfo(p, "  9. Bootstrap API key")
		printerInfo(p, " 10. Ensure 'abysslink' user via REST GET/POST /api/v1/user")
		printerInfo(p, " 11. Mint pre-auth key via POST /api/v1/preauthkey")
		printerInfo(p, "Re-run with --apply to execute.")
		return nil
	}

	ver := headscaleVersion()
	binPath := headscaleBinaryPath(cfg)
	cfgPath := headscaleConfigPath(cfg)

	// ── Step 1: Download binary + checksums.txt ────────────────────────────────
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	verNum := strings.TrimPrefix(ver, "v")
	artifactName := fmt.Sprintf("headscale_%s_%s_%s", verNum, goos, goarch)
	checksumsName := "checksums.txt"

	downloadURL := headscaleBaseURL + "/" + ver + "/" + artifactName
	checksumsURL := headscaleBaseURL + "/" + ver + "/" + checksumsName

	tmpDir, err := os.MkdirTemp("", "abysslink-headscale-*")
	if err != nil {
		return fmt.Errorf("headscale init: create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmpBinPath := filepath.Join(tmpDir, artifactName)
	tmpChksPath := filepath.Join(tmpDir, checksumsName)

	printerInfo(p, "  ↓  "+artifactName)
	if err := downloadFile(ctx, downloadURL, tmpBinPath); err != nil {
		return fmt.Errorf("headscale init: download binary: %w", err)
	}

	printerInfo(p, "  ↓  "+checksumsName)
	if err := downloadFile(ctx, checksumsURL, tmpChksPath); err != nil {
		return fmt.Errorf("headscale init: download checksums: %w", err)
	}

	// ── Step 2: Verify SHA-256 checksum ───────────────────────────────────────
	printerInfo(p, "  ✦  verifying checksum...")
	if err := verifyChecksum(tmpChksPath, artifactName, tmpBinPath); err != nil {
		return fmt.Errorf("headscale init: checksum FAILED — refusing to install: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  checksum verified"))

	// ── Step 3: Clear macOS quarantine (ignore error) ─────────────────────────
	if runtime.GOOS == "darwin" {
		_, _ = runner.Run(ctx, "xattr", "-d", "com.apple.quarantine", tmpBinPath)
	}

	// ── Step 4: Version floor check ───────────────────────────────────────────
	if err := checkHeadscaleVersionFloor(ctx, runner, tmpBinPath); err != nil {
		return fmt.Errorf("headscale init: %w", err)
	}

	// ── Step 5: Write binary via audit.WriteFilePath (streaming — D-06 / WR-02) ──
	// Stream src→dst via io.Copy with 256 MiB ceiling; binary never fully in memory.
	initLogPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("headscale init: audit log path: %w", err)
	}
	// Keychain uses ExecRunner — secrets CLI calls are always real system calls.
	initKC, kcErr := secrets.NewStore(ctx, &shell.ExecRunner{})
	if kcErr != nil {
		return fmt.Errorf("headscale init: keychain: %w", kcErr)
	}
	initSA, err := audit.NewSigned(initLogPath, initKC)
	if err != nil {
		return fmt.Errorf("headscale init: audit init: %w", err)
	}
	if err := initSA.WriteFilePath(ctx, tmpBinPath, binPath, 0o755, false); err != nil {
		return fmt.Errorf("headscale init: write binary: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  binary installed → "+binPath))

	// ── Step 6: Merge hardened config.yaml ────────────────────────────────────
	if err := backend.MergeHeadscaleConfig(ctx, cfgPath, cfg.Server.Headscale, false); err != nil {
		return fmt.Errorf("headscale init: config merge: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  config.yaml merged → "+cfgPath))

	// ── Steps 7-11: Service + secrets (completeInit) ──────────────────────────
	return completeInit(ctx, cfg, cc, runner, p)
}

// completeInit implements init steps 7-11: service install + start, health-check,
// API key bootstrap, user-ensure, and pre-auth key mint.
// macOS: creates _headscale service account via dscl, writes launchd plist, and
// loads the service via launchctl. Requires sudo; approved via checkpoint:human-verify
// (Task 2 of Plan 12-04, user response "approved").
func completeInit(ctx context.Context, cfg *config.Config, cc *cmdContext, runner shell.Runner, p Printer) error {
	// ── Step 7: Service install + start ───────────────────────────────────────
	binPath := headscaleBinaryPath(cfg)
	cfgPath := headscaleConfigPath(cfg)

	if runtime.GOOS == "darwin" {
		// macOS service-account creation (dscl) and launchd plist installation.
		// Approved via checkpoint:human-verify (Task 2 of Plan 12-04, R-03).
		if err := installHeadscaleMacOS(ctx, cfg, runner, p, binPath, cfgPath, cc.dryRun); err != nil {
			return err
		}
	} else {
		// Linux: systemd service install.
		if err := installHeadscaleLinux(ctx, cfg, runner, p, binPath, cfgPath, cc.dryRun); err != nil {
			return err
		}
	}

	// ── Step 8: Health-check (30s timeout, before any REST admin calls) ───────
	baseURL := cfg.Server.Headscale.ServerURL
	if err := doHeadscaleHealthCheck(ctx, baseURL+"/api/v1/node"); err != nil {
		return fmt.Errorf("headscale init: health-check: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  Headscale is responding"))

	// ── Step 9: API key bootstrap ─────────────────────────────────────────────
	kc, err := loadKeychainForInit(ctx, cc)
	if err != nil {
		return fmt.Errorf("headscale init: keychain unavailable: %w", err)
	}

	apiKey, err := ensureAPIKey(ctx, cfg, runner, kc, binPath, baseURL)
	if err != nil {
		return fmt.Errorf("headscale init: API key: %w", err)
	}
	// SECURITY: apiKey is printed ONLY through Printer — never via slog or audit.
	printerInfo(p, styleSuccess.Render("  ✓  API key obtained"))

	// ── Step 10: D-13 user-ensure ─────────────────────────────────────────────
	userName := headscaleUserName(cfg)
	if err := ensureHeadscaleUser(ctx, baseURL, apiKey, userName); err != nil {
		return fmt.Errorf("headscale init: user-ensure: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  Headscale user '"+userName+"' ensured"))

	// ── Step 11: Pre-auth key mint ────────────────────────────────────────────
	keyExpiry := headscalePreAuthKeyExpiry(cfg)
	preAuthKey, err := mintPreAuthKey(ctx, baseURL, apiKey, userName, keyExpiry)
	if err != nil {
		return fmt.Errorf("headscale init: pre-auth key: %w", err)
	}

	// Store pre-auth key in keychain — never on argv, never in audit log.
	if err := kc.Set(ctx, headscalePreAuthService, headscalePreAuthAccount, preAuthKey); err != nil {
		return fmt.Errorf("headscale init: store pre-auth key: %w", err)
	}
	// SECURITY: pre-auth key routed ONLY to Printer (T-12-04-02 / T-12-04-03).
	printerInfo(p, styleSuccess.Render("  ✓  Pre-auth key minted and stored in keychain"))

	return nil
}

// ── Service install helpers ────────────────────────────────────────────────────

// installHeadscaleLinux writes a systemd unit file and starts the service.
// All file mutations go through audit.WriteFile. All exec calls go through runner.
func installHeadscaleLinux(
	ctx context.Context,
	cfg *config.Config,
	runner shell.Runner,
	p Printer,
	binPath, cfgPath string,
	dryRun bool,
) error {
	unitContent := fmt.Sprintf(`[Unit]
Description=Headscale VPN control server
After=network.target

[Service]
Type=simple
User=headscale
ExecStart=%s serve --config %s
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, binPath, cfgPath)

	unitPath := "/etc/systemd/system/headscale.service"
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("headscale init: audit log path: %w", err)
	}
	if err := audit.New(logPath).WriteFile(unitPath, []byte(unitContent), 0o644, dryRun); err != nil {
		return fmt.Errorf("headscale init: write systemd unit: %w", err)
	}

	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "headscale"},
		{"systemctl", "start", "headscale"},
	} {
		if _, err := runner.Run(ctx, args[0], args[1:]...); err != nil {
			return fmt.Errorf("headscale init: %s: %w", strings.Join(args, " "), err)
		}
	}

	printerInfo(p, styleSuccess.Render("  ✓  headscale systemd service installed and started"))
	return nil
}

// macOS service account and plist constants (T-12-04-05, RF-2).
const (
	macOSHeadscaleUser   = "_headscale"
	macOSHeadscaleGroup  = "_headscale"
	macOSHeadscaleUID    = "399" // preferred UID/GID; findFreeMacOSID falls back if taken
	macOSHeadscaleHome   = "/var/lib/headscale"
	macOSHeadscaleLogDir = "/var/log/headscale"
	macOSHeadscalePlist  = "/Library/LaunchDaemons/net.abysslink.headscale.plist"
	macOSHeadscaleLabel  = "net.abysslink.headscale"
)

// installHeadscaleMacOS creates the _headscale service account via dscl (idempotent),
// sets up directory ownership, writes the launchd plist, and loads the service.
// Approved via checkpoint:human-verify (Task 2 of Plan 12-04, R-03).
//
// Security: runs as _headscale (UID 399), not root (T-12-04-05). listen_addr uses
// ":443" (all interfaces) — macOS non-root port <1024 only works for 0.0.0.0 (RF-2).
func installHeadscaleMacOS(
	ctx context.Context,
	cfg *config.Config,
	runner shell.Runner,
	p Printer,
	binPath, cfgPath string,
	dryRun bool,
) error {
	// Ensure service account exists (idempotent dscl check).
	if err := ensureMacOSServiceAccount(ctx, runner, p, dryRun); err != nil {
		return err
	}

	// Create and chown required directories.
	if err := ensureMacOSDirs(ctx, runner, p, dryRun); err != nil {
		return err
	}

	// Write launchd plist and load service.
	return writeMacOSPlistAndLoad(ctx, cfg, runner, p, binPath, cfgPath, dryRun)
}

// ensureMacOSServiceAccount creates the _headscale OS account + group if absent.
// Idempotent: checks existence via dscl read before running create commands.
func ensureMacOSServiceAccount(ctx context.Context, runner shell.Runner, p Printer, dryRun bool) error {
	// A non-zero exit from `dscl -read` means the account does not exist (the
	// normal create path). An err != nil means the command could not run at all
	// (binary missing, context cancelled) — distinguish it so we don't mistake an
	// exec failure (which returns a zero-value Result, ExitCode 0) for "exists".
	existsRes, err := runner.Run(ctx, "dscl", ".", "-read", "/Users/"+macOSHeadscaleUser)
	if err != nil {
		return fmt.Errorf("headscale init (macOS): dscl read /Users/%s: %w", macOSHeadscaleUser, err)
	}
	if existsRes.ExitCode == 0 {
		printerInfo(p, "  ✓  service account "+macOSHeadscaleUser+" already exists (idempotent)")
		return nil
	}

	// The preferred ID (399) collides with Apple-allocated GIDs on stock macOS
	// (e.g. com.apple.access_ssh owns GID 399), so creating a second group with
	// the same GID produces a duplicate-GID conflict. Pick an ID that is free in
	// BOTH the user and group namespaces, preferring the default when available.
	idStr, err := findFreeMacOSID(ctx, runner, p)
	if err != nil {
		return fmt.Errorf("headscale init (macOS): allocate uid/gid: %w", err)
	}

	if dryRun {
		printerInfo(p, "[plan] would create macOS service account "+macOSHeadscaleUser+" (UID/GID "+idStr+")")
		return nil
	}

	printerInfo(p, "  →  creating macOS service account "+macOSHeadscaleUser+" (UID/GID "+idStr+")")
	userCmds := [][]string{
		{"dscl", ".", "-create", "/Users/" + macOSHeadscaleUser},
		{"dscl", ".", "-create", "/Users/" + macOSHeadscaleUser, "UserShell", "/usr/bin/false"},
		{"dscl", ".", "-create", "/Users/" + macOSHeadscaleUser, "NFSHomeDirectory", macOSHeadscaleHome},
		{"dscl", ".", "-create", "/Users/" + macOSHeadscaleUser, "UniqueID", idStr},
		{"dscl", ".", "-create", "/Users/" + macOSHeadscaleUser, "PrimaryGroupID", idStr},
	}
	for _, args := range userCmds {
		if _, err := runner.Run(ctx, args[0], args[1:]...); err != nil {
			return fmt.Errorf("headscale init (macOS): %s: %w", strings.Join(args[2:], " "), err)
		}
	}

	groupCmds := [][]string{
		{"dscl", ".", "-create", "/Groups/" + macOSHeadscaleGroup},
		{"dscl", ".", "-create", "/Groups/" + macOSHeadscaleGroup, "PrimaryGroupID", idStr},
		{"dscl", ".", "-append", "/Groups/" + macOSHeadscaleGroup, "GroupMembership", macOSHeadscaleUser},
	}
	for _, args := range groupCmds {
		if _, err := runner.Run(ctx, args[0], args[1:]...); err != nil {
			return fmt.Errorf("headscale init (macOS): %s: %w", strings.Join(args[2:], " "), err)
		}
	}
	printerInfo(p, styleSuccess.Render("  ✓  service account "+macOSHeadscaleUser+" created (UID/GID "+idStr+")"))
	return nil
}

// findFreeMacOSID returns an ID that is unused in BOTH the macOS user and group
// namespaces, suitable for a service account's UniqueID and PrimaryGroupID. It
// prefers macOSHeadscaleUID when that value is free in both; otherwise it scans
// downward through the hidden service-account range (200–499, the convention for
// macOS daemon accounts) and returns the first free value. This avoids the
// duplicate-GID conflict that a hardcoded 399 hits on stock macOS, where
// com.apple.access_ssh already owns GID 399.
func findFreeMacOSID(ctx context.Context, runner shell.Runner, p Printer) (string, error) {
	usedUID, err := listUsedMacOSIDs(ctx, runner, "/Users", "UniqueID")
	if err != nil {
		return "", err
	}
	usedGID, err := listUsedMacOSIDs(ctx, runner, "/Groups", "PrimaryGroupID")
	if err != nil {
		return "", err
	}

	preferred, _ := strconv.Atoi(macOSHeadscaleUID)
	if preferred != 0 && !usedUID[preferred] && !usedGID[preferred] {
		return macOSHeadscaleUID, nil
	}

	for id := 499; id >= 200; id-- {
		if !usedUID[id] && !usedGID[id] {
			printerInfo(p, fmt.Sprintf("  →  default ID %s is in use; allocating free UID/GID %d", macOSHeadscaleUID, id))
			return strconv.Itoa(id), nil
		}
	}
	return "", fmt.Errorf("no free uid/gid available in range 200-499")
}

// listUsedMacOSIDs returns the set of numeric IDs already assigned in a dscl
// namespace, e.g. `dscl . -list /Users UniqueID`. Output lines look like
// "_name    399"; the trailing field is the numeric ID.
func listUsedMacOSIDs(ctx context.Context, runner shell.Runner, path, key string) (map[int]bool, error) {
	res, err := runner.Run(ctx, "dscl", ".", "-list", path, key)
	if err != nil {
		return nil, fmt.Errorf("dscl -list %s %s: %w", path, key, err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("dscl -list %s %s exited %d", path, key, res.ExitCode)
	}
	used := make(map[int]bool)
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if n, convErr := strconv.Atoi(fields[len(fields)-1]); convErr == nil {
			used[n] = true
		}
	}
	return used, nil
}

// ensureMacOSDirs creates /var/lib/headscale, /etc/headscale, /var/log/headscale
// and chowns them to _headscale:_headscale.
func ensureMacOSDirs(ctx context.Context, runner shell.Runner, p Printer, dryRun bool) error {
	dirs := []string{macOSHeadscaleHome, "/etc/headscale", macOSHeadscaleLogDir}
	for _, dir := range dirs {
		if dryRun {
			printerInfo(p, "[plan] would mkdir -p "+dir)
			continue
		}
		if _, err := runner.Run(ctx, "mkdir", "-p", dir); err != nil {
			return fmt.Errorf("headscale init (macOS): mkdir %s: %w", dir, err)
		}
		if _, err := runner.Run(ctx, "chown", "-R", macOSHeadscaleUser+":"+macOSHeadscaleGroup, dir); err != nil {
			return fmt.Errorf("headscale init (macOS): chown %s: %w", dir, err)
		}
	}
	return nil
}

// writeMacOSPlistAndLoad writes the launchd plist and loads it with launchctl.
// listen_addr ":443" (0.0.0.0:443) — non-root port <1024 on macOS only works for
// all interfaces, not a specific IP (RF-2 / Pitfall 5).
func writeMacOSPlistAndLoad(
	ctx context.Context,
	cfg *config.Config,
	runner shell.Runner,
	p Printer,
	binPath, cfgPath string,
	dryRun bool,
) error {
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>            <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>serve</string>
        <string>--config</string>
        <string>%s</string>
    </array>
    <key>UserName</key>         <string>%s</string>
    <key>GroupName</key>        <string>%s</string>
    <key>InitGroups</key>       <true/>
    <key>RunAtLoad</key>        <true/>
    <key>KeepAlive</key>        <true/>
    <key>WorkingDirectory</key> <string>%s</string>
    <key>StandardOutPath</key>  <string>%s/headscale.log</string>
    <key>StandardErrorPath</key><string>%s/headscale.err</string>
</dict>
</plist>
`, macOSHeadscaleLabel, binPath, cfgPath,
		macOSHeadscaleUser, macOSHeadscaleGroup,
		macOSHeadscaleHome, macOSHeadscaleLogDir, macOSHeadscaleLogDir)

	if dryRun {
		printerInfo(p, "[plan] would write launchd plist → "+macOSHeadscalePlist)
		printerInfo(p, "[plan] would launchctl load "+macOSHeadscalePlist)
		return nil
	}

	logAuditPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("headscale init (macOS): audit log path: %w", err)
	}
	if err := audit.New(logAuditPath).WriteFile(macOSHeadscalePlist, []byte(plistContent), 0o644, false); err != nil {
		return fmt.Errorf("headscale init (macOS): write launchd plist: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  launchd plist written → "+macOSHeadscalePlist))

	// launchctl load is idempotent: already-loaded services print a message but exit 0.
	if _, err := runner.Run(ctx, "launchctl", "load", macOSHeadscalePlist); err != nil {
		return fmt.Errorf("headscale init (macOS): launchctl load: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  launchd service loaded: "+macOSHeadscaleLabel))

	// Assert service runs as _headscale, not root (T-12-04-05).
	if err := assertHeadscaleRunsAsUser(ctx, runner, macOSHeadscaleUser); err != nil {
		slog.WarnContext(ctx, "headscale init (macOS): process user assertion failed — hs-proc-user will report WARN",
			"err", err)
		printerInfo(p, styleWarn.Render("  !  could not verify process user (may still be starting): "+err.Error()))
	} else {
		printerInfo(p, styleSuccess.Render("  ✓  headscale running as "+macOSHeadscaleUser+" (not root)"))
	}

	_ = cfg // retained for future config-driven overrides
	return nil
}

// assertHeadscaleRunsAsUser checks that the headscale process is running as the
// expected user (not root). Uses pgrep to find the PID, then ps to get the user.
// T-12-04-05: launchd UserName key is ASSUMED to work (A1); this probe detects if
// the assumption fails.
func assertHeadscaleRunsAsUser(ctx context.Context, runner shell.Runner, expectedUser string) error {
	pgrepRes, err := runner.Run(ctx, "pgrep", "-x", "headscale")
	if err != nil || strings.TrimSpace(pgrepRes.Stdout) == "" {
		return fmt.Errorf("pgrep headscale: process not found (may still be starting)")
	}
	pid := strings.TrimSpace(pgrepRes.Stdout)
	// Take only the first PID if multiple.
	if idx := strings.IndexAny(pid, "\n "); idx >= 0 {
		pid = pid[:idx]
	}

	psRes, err := runner.Run(ctx, "ps", "-o", "user=", "-p", pid)
	if err != nil {
		return fmt.Errorf("ps -o user= -p %s: %w", pid, err)
	}
	actualUser := strings.TrimSpace(psRes.Stdout)
	if actualUser != expectedUser {
		return fmt.Errorf("headscale is running as %q, expected %q — hs-proc-user will FAIL", actualUser, expectedUser)
	}
	return nil
}

// ── upgrade subcommand ─────────────────────────────────────────────────────────

func newServerHeadscaleUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade the Headscale binary (dry-run by default)",
		Example: `  # Preview the upgrade
  abysslink server headscale upgrade

  # Execute the upgrade
  abysslink server headscale upgrade --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			ver, _ := cmd.Flags().GetString("version")
			if ver == "" {
				ver = headscaleDefaultVersion
			}
			return headscaleUpgradeRunE(cmd.Context(), cc.cfg, cc, cc.runner, ver)
		},
	}
	cmd.Flags().String("version", "", "Target version (default: "+headscaleDefaultVersion+")")
	return cmd
}

// headscaleUpgradeRunE is the testable implementation of "server headscale upgrade".
// Sequence: check installed version → refuse downgrade → download + verify → swap binary → restart.
func headscaleUpgradeRunE(ctx context.Context, cfg *config.Config, cc *cmdContext, runner shell.Runner, targetVer string) error {
	binPath := headscaleBinaryPath(cfg)

	// Check installed version first (before download).
	installed, err := headscaleInstalledVersion(ctx, runner, binPath)
	if err != nil {
		return fmt.Errorf("headscale upgrade: get installed version: %w", err)
	}

	// Compare versions — refuse downgrade (T-12-04-04).
	if semverLT(targetVer, installed) {
		return fmt.Errorf("headscale upgrade: refusing downgrade from %s to %s — use a higher version", installed, targetVer)
	}

	if cc.dryRun {
		slog.InfoContext(ctx, "headscale upgrade [dry-run]", "installed", installed, "target", targetVer)
		return nil
	}

	// Download, verify, and check version floor on the new binary.
	tmpBinPath, tmpDir, err := downloadAndVerifyHeadscale(ctx, runner, targetVer)
	if tmpDir != "" {
		defer func() { _ = os.RemoveAll(tmpDir) }()
	}
	if err != nil {
		return fmt.Errorf("headscale upgrade: %w", err)
	}

	// AUD-01: build a chain-recording *SignedAudit for the DB backup.
	// headscaleSwapBinary is fail-closed on backup failure, so use sa when
	// available; if keychain is unavailable, sa is nil and headscaleSwapBinary
	// will fall back to the unchained Backup (documented at that call site).
	sa, _ := cmdSignedAudit(ctx, cc)

	// Swap binary: backup DB → stop → write → start → health-check.
	return headscaleSwapBinary(ctx, cfg, runner, binPath, tmpBinPath, sa)
}

// downloadAndVerifyHeadscale downloads the headscale binary for targetVer, verifies
// its SHA-256 checksum, and runs the version floor check. Returns the temp binary
// path and the temp dir (caller must remove the dir). Extracted to keep upgrade
// cyclomatic complexity below gocyclo limit of 15.
func downloadAndVerifyHeadscale(ctx context.Context, runner shell.Runner, targetVer string) (tmpBinPath, tmpDir string, err error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	verNum := strings.TrimPrefix(targetVer, "v")
	artifactName := fmt.Sprintf("headscale_%s_%s_%s", verNum, goos, goarch)
	checksumsName := "checksums.txt"

	downloadURL := headscaleBaseURL + "/" + targetVer + "/" + artifactName
	checksumsURL := headscaleBaseURL + "/" + targetVer + "/" + checksumsName

	tmpDir, err = os.MkdirTemp("", "abysslink-headscale-upgrade-*")
	if err != nil {
		return "", "", fmt.Errorf("create temp dir: %w", err)
	}

	tmpBinPath = filepath.Join(tmpDir, artifactName)
	tmpChksPath := filepath.Join(tmpDir, checksumsName)

	if err = downloadFile(ctx, downloadURL, tmpBinPath); err != nil {
		return "", tmpDir, fmt.Errorf("download binary: %w", err)
	}
	if err = downloadFile(ctx, checksumsURL, tmpChksPath); err != nil {
		return "", tmpDir, fmt.Errorf("download checksums: %w", err)
	}
	if err = verifyChecksum(tmpChksPath, artifactName, tmpBinPath); err != nil {
		return "", tmpDir, fmt.Errorf("checksum FAILED: %w", err)
	}
	if err = checkHeadscaleVersionFloor(ctx, runner, tmpBinPath); err != nil {
		return "", tmpDir, err
	}
	return tmpBinPath, tmpDir, nil
}

// headscaleSwapBinary performs the atomic binary swap: backup DB → stop service →
// write new binary → start service → health-check. Extracted to keep upgrade
// cyclomatic complexity below gocyclo limit of 15.
// sa is the chain-recording *SignedAudit from the caller; if nil (keychain
// unavailable), falls back to unchained audit.Backup with a slog.Warn
// (AUD-01 T-24-07-04 documented fallback; not silent).
func headscaleSwapBinary(ctx context.Context, cfg *config.Config, runner shell.Runner, binPath, tmpBinPath string, sa *audit.SignedAudit) error {
	// AUD-01: backup DB before any mutation (D-04) using chain-recorded BackupWithChain.
	// Fail-closed: an error aborts the upgrade to preserve the append-before-write ordering.
	if dbPath := cfg.Server.Headscale.DBPath; dbPath != "" {
		if sa != nil {
			if _, err := audit.BackupWithChain(ctx, dbPath, sa); err != nil {
				return fmt.Errorf("headscale upgrade: backup DB: %w", err)
			}
		} else {
			// Keychain unavailable — unchained fallback (AUD-01 T-24-07-04; not silent).
			slog.WarnContext(ctx, "headscale upgrade: chain backup unavailable (keychain missing); using unchained backup", "db_path", dbPath)
			if _, err := audit.Backup(dbPath); err != nil {
				return fmt.Errorf("headscale upgrade: backup DB: %w", err)
			}
		}
	}

	// Stop service.
	if err := headscaleServiceControl(ctx, runner, "stop"); err != nil {
		return fmt.Errorf("headscale upgrade: stop service: %w", err)
	}

	// Write new binary via audit.WriteFilePath (streaming — D-06 / WR-02).
	// Stream src→dst via io.Copy with 256 MiB ceiling; binary never fully in memory.
	// sa is the chain-recording *SignedAudit from the caller; if nil, fall back to
	// a fresh SignedAudit (mirrors the DB backup fallback above).
	swapSA := sa
	if swapSA == nil {
		swapLogPath, lerr := audit.DefaultLogPath()
		if lerr != nil {
			return fmt.Errorf("headscale upgrade: audit log path: %w", lerr)
		}
		// Keychain uses ExecRunner — secrets CLI calls are always real system calls.
		swapKC, kcErr := secrets.NewStore(ctx, &shell.ExecRunner{})
		if kcErr != nil {
			return fmt.Errorf("headscale upgrade: keychain: %w", kcErr)
		}
		var saErr error
		swapSA, saErr = audit.NewSigned(swapLogPath, swapKC)
		if saErr != nil {
			return fmt.Errorf("headscale upgrade: audit init: %w", saErr)
		}
	}
	if err := swapSA.WriteFilePath(ctx, tmpBinPath, binPath, 0o755, false); err != nil {
		return fmt.Errorf("headscale upgrade: write binary: %w", err)
	}

	// Start service + health-check.
	if err := headscaleServiceControl(ctx, runner, "start"); err != nil {
		return fmt.Errorf("headscale upgrade: start service: %w", err)
	}
	baseURL := cfg.Server.Headscale.ServerURL
	if err := doHeadscaleHealthCheck(ctx, baseURL+"/api/v1/node"); err != nil {
		return fmt.Errorf("headscale upgrade: health-check after restart: %w", err)
	}
	return nil
}

// ── status subcommand ──────────────────────────────────────────────────────────

func newServerHeadscaleStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report Headscale service state and API reachability",
		Example: `  # Show Headscale service status and API reachability
  abysslink server headscale status

  # Machine-readable JSON output
  abysslink --json server headscale status`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			return headscaleStatusRunE(cmd.Context(), cc, p)
		},
	}
}

func headscaleStatusRunE(ctx context.Context, cc *cmdContext, p Printer) error {
	runner := cc.runner
	cfg := cc.cfg
	binPath := headscaleBinaryPath(cfg)

	// Get installed version.
	ver, err := headscaleInstalledVersion(ctx, runner, binPath)
	if err != nil {
		ver = "unknown"
	}

	// Check service state.
	serviceActive := headscaleServiceIsActive(ctx, runner)

	// Check API reachability.
	baseURL := cfg.Server.Headscale.ServerURL
	apiReachable := false
	if baseURL != "" {
		ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, reqErr := http.NewRequestWithContext(ctxTimeout, http.MethodGet, baseURL+"/api/v1/node", nil)
		if reqErr == nil {
			resp, doErr := http.DefaultClient.Do(req)
			if doErr == nil {
				_ = resp.Body.Close()
				apiReachable = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
			}
		}
	}

	type statusReport struct {
		Version      string `json:"version"`
		ServiceState string `json:"service_state"`
		APIReachable bool   `json:"api_reachable"`
		ServerURL    string `json:"server_url,omitempty"`
	}
	report := statusReport{
		Version:      ver,
		ServiceState: map[bool]string{true: "active", false: "inactive"}[serviceActive],
		APIReachable: apiReachable,
		ServerURL:    baseURL,
	}

	if cc.jsonOut {
		p.PrintJSON(report)
		return nil
	}

	printerInfo(p, styleBold.Render("Headscale status"))
	printerInfo(p, "")
	printerInfo(p, "  Version:       "+report.Version)
	printerInfo(p, "  Service:       "+report.ServiceState)
	printerInfo(p, "  API reachable: "+fmt.Sprintf("%v", report.APIReachable))
	if report.ServerURL != "" {
		printerInfo(p, "  Server URL:    "+report.ServerURL)
	}
	return nil
}

// ── backup subcommand ─────────────────────────────────────────────────────────

func newServerHeadscaleBackupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backup",
		Short: "Backup the Headscale SQLite database",
		Example: `  # Preview the backup (dry-run — no changes)
  abysslink server headscale backup

  # Execute the backup
  abysslink server headscale backup --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			return headscaleBackupRunE(cmd.Context(), cc, p)
		},
	}
}

func headscaleBackupRunE(ctx context.Context, cc *cmdContext, p Printer) error {
	dbPath := cc.cfg.Server.Headscale.DBPath
	if dbPath == "" {
		dbPath = "/var/lib/headscale/db.sqlite"
	}

	if cc.dryRun {
		printerInfo(p, fmt.Sprintf("[plan] would backup %s (re-run with --apply)", dbPath))
		return nil
	}

	slog.InfoContext(ctx, "headscale backup", "db_path", dbPath)

	// AUD-01: DB backup is the principal artifact — fail-closed if the keychain
	// is unavailable (cannot build a chain-recording *SignedAudit).
	sa, saErr := cmdSignedAudit(ctx, cc)
	if saErr != nil {
		return fmt.Errorf("headscale backup: %w", saErr)
	}
	backupPath, err := audit.BackupWithChain(ctx, dbPath, sa)
	if err != nil {
		return fmt.Errorf("headscale backup: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  database backed up → "+backupPath))
	return nil
}

// ── Helper functions ───────────────────────────────────────────────────────────

// doHeadscaleHealthCheck polls the given URL until it receives a response
// indicating the server is up (200, 401, or 403 — any response that is NOT a
// connection error). Retries every 2s for up to 30s (or context deadline).
// Fail-closed: returns error on timeout to prevent REST calls against a
// non-running server (T-12-04-10).
func doHeadscaleHealthCheck(ctx context.Context, url string) error {
	hcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Try immediately, then every 2s.
	for {
		req, err := http.NewRequestWithContext(hcCtx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("headscale health-check: build request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			// Any HTTP response (even 401/403) means the server is listening.
			switch resp.StatusCode {
			case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden:
				return nil
			}
			// Non-connection-error non-ready status: keep trying.
		}
		// err != nil means connection error (server not yet up) — keep retrying.

		select {
		case <-hcCtx.Done():
			return fmt.Errorf("headscale: health-check timed out after 30s — service may not have started")
		case <-ticker.C:
			// retry
		}
	}
}

// ensureAPIKey retrieves or bootstraps the Headscale API key.
// First install (no key in keychain): invokes runner with "apikeys create" (one-time
// bootstrap only — headscale binary invoked once to obtain the initial API key;
// no REST auth key exists yet; all subsequent admin ops use REST per D-08).
// Re-init (key in keychain but stale): uses REST POST /api/v1/apikey to rotate.
// The key value is never written to disk directly — only via keychain.
func ensureAPIKey(
	ctx context.Context,
	cfg *config.Config,
	runner shell.Runner,
	kc secrets.KeychainStore,
	binaryPath string,
	baseURL string,
) (string, error) {
	// Check keychain for existing key.
	existingKey, keychainErr := kc.Get(ctx, headscaleAPIKeyService, headscaleAPIKeyAccount)
	if keychainErr == nil && existingKey != "" {
		// Probe REST to see if the existing key is still valid.
		if probeAPIKey(ctx, baseURL, existingKey) {
			return existingKey, nil
		}
		// Key in keychain but REST probe failed — rotate via REST.
		return rotateAPIKeyREST(ctx, baseURL, existingKey, kc)
	}

	// First-time bootstrap only — headscale binary invoked once to obtain the initial
	// API key; no REST auth key exists yet; all subsequent admin ops use REST per D-08.
	res, err := runner.Run(ctx, binaryPath, "apikeys", "create", "--expiration", "90d")
	if err != nil {
		return "", fmt.Errorf("apikeys create: %w", err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("apikeys create exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stdout+res.Stderr))
	}

	apiKey := strings.TrimSpace(res.Stdout)
	if apiKey == "" {
		return "", fmt.Errorf("apikeys create returned empty key")
	}

	// Store in keychain immediately — never on disk or in audit log (T-12-04-02).
	if err := kc.Set(ctx, headscaleAPIKeyService, headscaleAPIKeyAccount, apiKey); err != nil {
		return "", fmt.Errorf("store API key in keychain: %w", err)
	}

	return apiKey, nil
}

// probeAPIKey checks whether apiKey is still valid by calling GET /api/v1/apikey.
// Returns true if HTTP 200 is received.
func probeAPIKey(ctx context.Context, baseURL, apiKey string) bool {
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctxTimeout, http.MethodGet, baseURL+"/api/v1/apikey", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// rotateAPIKeyREST uses the existing API key to mint a new one via REST POST /api/v1/apikey.
// Stores the new key in keychain. This is the steady-state re-init path (D-08).
func rotateAPIKeyREST(ctx context.Context, baseURL, oldKey string, kc secrets.KeychainStore) (string, error) {
	expiry := time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	body := map[string]string{"expiration": expiry}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/apikey", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("rotate API key: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+oldKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("rotate API key: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rotate API key: HTTP %d", resp.StatusCode)
	}

	var result struct {
		APIKey string `json:"apiKey"`
	}
	data, err := limitio.ReadLimited(resp.Body, limitio.MaxBackendBody)
	if err != nil {
		return "", fmt.Errorf("rotate API key: read response: %w", err)
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("rotate API key: decode response: %w", err)
	}
	if result.APIKey == "" {
		return "", fmt.Errorf("rotate API key: empty key in response")
	}

	// Store new key in keychain — never on disk (T-12-04-02).
	if err := kc.Set(ctx, headscaleAPIKeyService, headscaleAPIKeyAccount, result.APIKey); err != nil {
		return "", fmt.Errorf("rotate API key: store in keychain: %w", err)
	}
	return result.APIKey, nil
}

// ensureHeadscaleUser ensures the named user exists in Headscale via REST.
// GET /api/v1/user — if user found → return nil.
// POST /api/v1/user — if not found (409 Conflict = already exists = success). (D-13)
func ensureHeadscaleUser(ctx context.Context, baseURL, apiKey, userName string) error {
	// GET /api/v1/user — list all users.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/user", nil)
	if err != nil {
		return fmt.Errorf("user-ensure GET: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("user-ensure GET: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// A non-200 GET (e.g. 401 stale key) must surface here rather than being
		// masked by a later, less specific POST failure (WR-04).
		return fmt.Errorf("user-ensure GET: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Users []struct {
			Name string `json:"name"`
		} `json:"users"`
	}
	// A 200 body that fails to decode means we cannot reliably tell whether the
	// user exists; returning an error here avoids a spurious recreate attempt.
	userData, err := limitio.ReadLimited(resp.Body, limitio.MaxBackendBody)
	if err != nil {
		return fmt.Errorf("user-ensure GET: read response: %w", err)
	}
	if err := json.Unmarshal(userData, &result); err != nil {
		return fmt.Errorf("user-ensure GET: decode user list: %w", err)
	}
	for _, u := range result.Users {
		if u.Name == userName {
			// User already exists — nothing to do.
			return nil
		}
	}

	// User not found — create via POST /api/v1/user.
	createBody := map[string]string{"name": userName}
	bodyBytes, _ := json.Marshal(createBody)

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/user", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("user-ensure POST: build request: %w", err)
	}
	postReq.Header.Set("Authorization", "Bearer "+apiKey)
	postReq.Header.Set("Content-Type", "application/json")

	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		return fmt.Errorf("user-ensure POST: request: %w", err)
	}
	defer func() { _ = postResp.Body.Close() }()

	// 200 or 409 Conflict (already exists — idempotent, T-12-04-09) = success.
	if postResp.StatusCode != http.StatusOK && postResp.StatusCode != http.StatusConflict {
		return fmt.Errorf("user-ensure POST: HTTP %d", postResp.StatusCode)
	}
	return nil
}

// mintPreAuthKey calls POST /api/v1/preauthkey and returns the key string.
// The key has explicit expiry (D-11 / T-12-04-03 / issue #1579).
// NEVER log the returned key value — only route through Printer.
func mintPreAuthKey(ctx context.Context, baseURL, apiKey, userName string, expiry time.Duration) (string, error) {
	expiryTime := time.Now().UTC().Add(expiry)
	body := map[string]any{
		"user":       userName,
		"reusable":   false,
		"ephemeral":  true,
		"expiration": expiryTime.Format(time.RFC3339),
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/preauthkey", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("mint pre-auth key: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("mint pre-auth key: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mint pre-auth key: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(limitio.ReadSnippet(resp.Body)))
	}

	var result struct {
		PreAuthKey struct {
			Key string `json:"key"`
		} `json:"preAuthKey"`
	}
	pakData, err := limitio.ReadLimited(resp.Body, limitio.MaxBackendBody)
	if err != nil {
		return "", fmt.Errorf("mint pre-auth key: read response: %w", err)
	}
	if err := json.Unmarshal(pakData, &result); err != nil {
		return "", fmt.Errorf("mint pre-auth key: decode response: %w", err)
	}
	if result.PreAuthKey.Key == "" {
		return "", fmt.Errorf("mint pre-auth key: empty key in response")
	}
	return result.PreAuthKey.Key, nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// headscaleBinaryPath returns the configured binary path or the default.
func headscaleBinaryPath(cfg *config.Config) string {
	if p := cfg.Server.Headscale.BinaryPath; p != "" {
		return p
	}
	return "/usr/local/bin/headscale"
}

// headscaleConfigPath returns the configured config path or the default.
func headscaleConfigPath(cfg *config.Config) string {
	if p := cfg.Server.Headscale.ConfigPath; p != "" {
		return p
	}
	return "/etc/headscale/config.yaml"
}

// headscaleVersion returns the version installed by `init`. This is always the
// pinned compile-time default: init does not (yet) accept a version override.
// The `upgrade` command is the supported path for installing a different
// version via its --version flag. Taking no cfg parameter keeps that limitation
// explicit rather than implying a config key that is silently ignored (WR-06).
func headscaleVersion() string {
	return headscaleDefaultVersion
}

// headscaleUserName returns the configured headscale user name or "abysslink".
func headscaleUserName(cfg *config.Config) string {
	if u := cfg.Server.Headscale.User; u != "" {
		return u
	}
	return "abysslink"
}

// headscalePreAuthKeyExpiry returns the configured pre-auth key expiry or 1h.
func headscalePreAuthKeyExpiry(cfg *config.Config) time.Duration {
	if s := cfg.Server.Headscale.PreAuthKeyExpiry; s != "" {
		d, err := time.ParseDuration(s)
		// D-11: pre-auth keys MUST have a non-zero, future expiry. A non-positive
		// duration (e.g. "0s", "-5h") would mint an already-/never-expired key, so
		// reject it and fall back to the paranoid-safe default.
		if err == nil && d > 0 {
			return d
		}
	}
	return preAuthKeyExpiry
}

// checkHeadscaleVersionFloor runs the binary at tmpBinPath and checks that the
// reported version is >= headscaleMinVersion (v0.23.0). T-12-04-07.
func checkHeadscaleVersionFloor(ctx context.Context, runner shell.Runner, tmpBinPath string) error {
	res, err := runner.Run(ctx, tmpBinPath, "version")
	if err != nil {
		return fmt.Errorf("version check: %w", err)
	}
	// Parse version: "headscale version v0.28.0" or just "v0.28.0".
	reportedVer := parseVersionFromOutput(res.Stdout)
	if reportedVer == "" {
		return fmt.Errorf("version check: could not parse version from output: %q", res.Stdout)
	}
	if semverLT(reportedVer, headscaleMinVersion) {
		return fmt.Errorf("headscale: version %s is below minimum supported %s", reportedVer, headscaleMinVersion)
	}
	return nil
}

// headscaleInstalledVersion queries the installed binary for its version string.
func headscaleInstalledVersion(ctx context.Context, runner shell.Runner, binPath string) (string, error) {
	res, err := runner.Run(ctx, binPath, "version")
	if err != nil {
		return "", fmt.Errorf("get version: %w", err)
	}
	ver := parseVersionFromOutput(res.Stdout)
	if ver == "" {
		return "", fmt.Errorf("could not parse version from: %q", res.Stdout)
	}
	return ver, nil
}

// parseVersionFromOutput extracts the vX.Y.Z token from headscale version output.
func parseVersionFromOutput(output string) string {
	for _, token := range strings.Fields(output) {
		if strings.HasPrefix(token, "v") && strings.Contains(token, ".") {
			return token
		}
	}
	return ""
}

// semverLT returns true if version a is strictly less than b.
// Both a and b may have a leading "v" prefix.
// Only major.minor.patch comparison is performed (no pre-release suffixes).
func semverLT(a, b string) bool {
	aParts := semverParts(a)
	bParts := semverParts(b)
	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return true
		}
		if aParts[i] > bParts[i] {
			return false
		}
	}
	return false // equal
}

// semverParts returns [major, minor, patch] integers for a version string.
func semverParts(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	// Strip any pre-release suffix (e.g., "0.29.0-beta.2" → "0.29.0").
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, ".", 3)
	var result [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		n, _ := strconv.Atoi(parts[i])
		result[i] = n
	}
	return result
}

// headscaleServiceControl starts or stops the Headscale service via
// systemctl (Linux) or launchctl (macOS).
func headscaleServiceControl(ctx context.Context, runner shell.Runner, action string) error {
	switch runtime.GOOS {
	case "linux":
		_, err := runner.Run(ctx, "systemctl", action, "headscale")
		return err
	case "darwin":
		label := "net.abysslink.headscale"
		plist := "/Library/LaunchDaemons/net.abysslink.headscale.plist"
		switch action {
		case "stop":
			_, err := runner.Run(ctx, "launchctl", "unload", plist)
			return err
		case "start":
			_, err := runner.Run(ctx, "launchctl", "load", plist)
			return err
		default:
			_ = label
			return fmt.Errorf("unsupported launchctl action: %s", action)
		}
	default:
		return fmt.Errorf("headscale service control: unsupported OS %s", runtime.GOOS)
	}
}

// headscaleServiceIsActive returns true if the headscale service is running.
func headscaleServiceIsActive(ctx context.Context, runner shell.Runner) bool {
	switch runtime.GOOS {
	case "linux":
		res, err := runner.Run(ctx, "systemctl", "is-active", "headscale")
		return err == nil && strings.TrimSpace(res.Stdout) == "active"
	case "darwin":
		res, err := runner.Run(ctx, "launchctl", "list", "net.abysslink.headscale")
		return err == nil && res.ExitCode == 0
	default:
		return false
	}
}

// loadKeychainForInit constructs a secrets.KeychainStore for use during init.
// We import secrets via the context mechanism to avoid pulling in all of
// buildDeps overhead for a focused provisioning command.
func loadKeychainForInit(ctx context.Context, cc *cmdContext) (secrets.KeychainStore, error) {
	kc, err := secrets.NewStore(ctx, cc.runner)
	if err != nil {
		return nil, fmt.Errorf("keychain: %w", err)
	}
	return kc, nil
}

// newHumanPrinterStdout returns a human-readable Printer writing to os.Stdout.
// Used by headscaleInitRunE when a cobra.Command Printer is not yet available
// (the function is called directly in tests or wired via RunE).
func newHumanPrinterStdout() Printer {
	return NewHumanPrinterTo(os.Stdout, os.Stderr)
}
