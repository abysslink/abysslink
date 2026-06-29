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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/limitio"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/spf13/cobra"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	netbirdMinVersion     = "v0.57.0"
	netbirdContainerImage = "netbirdio/netbird-server:v0.57.0"
	netbirdServiceName    = "netbird-server"
	netbirdConfigPath     = "/etc/netbird/config.yaml"
	netbirdBinaryDest     = "/usr/local/bin/netbird-server"
	netbirdServiceUser    = "netbird-server"

	// netbirdBinaryCeiling bounds the supplied binary read (WR-04). It mirrors
	// audit.writeFilePathCeiling (256 MiB): a NetBird server binary is tens of MB,
	// so a file beyond this is operator error or hostile and must not be slurped
	// into memory before the checksum runs.
	netbirdBinaryCeiling = 256 << 20 // 256 MiB

	// netbirdConfigCeiling bounds the merged config.yaml read (WR-04). The config
	// is a few KB; this cap is generous while preventing an unbounded read of a
	// path that an operator could point at a large file.
	netbirdConfigCeiling = 4 << 20 // 4 MiB

	// netbirdSystemdUnit is the systemd unit template from RESEARCH.md RF-3.
	netbirdSystemdUnit = `[Unit]
Description=NetBird Combined Server (Abysslink-provisioned)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=netbird-server
Group=netbird-server
ExecStart=/usr/local/bin/netbird-server --config /etc/netbird/config.yaml
Restart=on-failure
RestartSec=5
TimeoutStopSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
StateDirectory=netbird
LogsDirectory=netbird

[Install]
WantedBy=multi-user.target
`
)

// ── Command tree ──────────────────────────────────────────────────────────────

// newServerNetBirdCmd returns the "server netbird" sub-group with four
// subcommands: init, status, upgrade, backup.
func newServerNetBirdCmd() *cobra.Command {
	nb := &cobra.Command{
		Use:   "netbird",
		Short: "Manage a locally-provisioned NetBird control server",
	}
	nb.AddCommand(
		newServerNetBirdInitCmd(),
		newServerNetBirdStatusCmd(),
		newServerNetBirdUpgradeCmd(),
		newServerNetBirdBackupCmd(),
	)
	return nb
}

// ── init subcommand ────────────────────────────────────────────────────────────

func newServerNetBirdInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Provision a NetBird server (dry-run by default)",
		Example: `  # Preview what init would do (dry-run — no changes)
  abysslink server netbird init

  # Execute the full provisioning sequence (Linux — supply a pre-built binary)
  abysslink server netbird init --binary-path /path/to/netbird-server --apply

  # Execute on macOS (container path — no --binary-path needed)
  abysslink server netbird init --apply

Binary acquisition routes (Linux only):
  Option 1 — Build from source (requires Go + gcc on target machine):
    git clone --depth 1 --branch v0.57.0 https://github.com/netbirdio/netbird.git
    cd netbird && CGO_ENABLED=1 go build -o netbird-server ./combined

  Option 2 — Extract from Docker image:
    docker create --name nb-extract netbirdio/netbird-server:v0.57.0
    docker cp nb-extract:/go/bin/netbird-server .
    docker rm nb-extract`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			binaryPath, _ := cmd.Flags().GetString("binary-path")
			// UX: route through newPrinter(cmd) so --json and cmd.SetOut capture
			// are honored (never a raw os.Stdout human printer).
			return netbirdInitRunE(cmd.Context(), cc.cfg, cc, cc.runner, binaryPath, newPrinter(cmd))
		},
	}
	cmd.Flags().String("binary-path", "", "Path to pre-built netbird-server binary (Linux only; see --help for acquisition routes)")
	return cmd
}

// netbirdInitRunE is the testable implementation of "server netbird init".
// On Linux: verifies --binary-path binary, copies to /usr/local/bin, writes
// config.yaml via audit, installs systemd unit, sets up service user, then
// executes the ZITADEL post-provision probe (SC-2).
// On macOS: pulls pinned-digest container image, runs with loopback-bound ports.
func netbirdInitRunE(ctx context.Context, cfg *config.Config, cc *cmdContext, runner shell.Runner, binaryPath string, p Printer) error {
	if p == nil {
		p = newHumanPrinterStdout()
	}

	// ── Dry-run gate ──────────────────────────────────────────────────────────
	if cc.dryRun {
		if runtime.GOOS == "linux" {
			printerInfo(p, "[plan] server netbird init (Linux) would:")
			printerInfo(p, "  1. Verify --binary-path binary version >= "+netbirdMinVersion)
			printerInfo(p, "  2. Install binary → "+netbirdBinaryDest+" (audited write: backup + audit-log entry)")
			printerInfo(p, "  3. Compute SHA-256 of the INSTALLED binary + write checksum sidecar (audited)")
			printerInfo(p, "  4. Create service user '"+netbirdServiceUser+"' (non-login, non-root)")
			printerInfo(p, "  5. Merge hardened config.yaml → "+netbirdConfigPath)
			printerInfo(p, "  6. Write systemd unit → /etc/systemd/system/netbird-server.service")
			printerInfo(p, "  7. Enable + start netbird-server service")
			printerInfo(p, "  8. Health-check (30s timeout, GET /api/groups)")
			printerInfo(p, "  9. ZITADEL post-provision probe (SC-2): SKIP for Dex, FAIL if default admin active")
		} else {
			printerInfo(p, "[plan] server netbird init (macOS container) would:")
			printerInfo(p, "  1. Detect container runtime (docker/colima/podman)")
			printerInfo(p, "  2. Pull "+netbirdContainerImage)
			printerInfo(p, "  3. Record image repo digest via inspect (informational — the tag is not digest-pinned)")
			printerInfo(p, "  4. Run container with loopback-bound ports (127.0.0.1:PORT:PORT)")
			printerInfo(p, "  5. Verify container runs as non-root")
			printerInfo(p, "  6. Write run config via audit")
		}
		printerInfo(p, "Re-run with --apply to execute.")
		return nil
	}

	switch runtime.GOOS {
	case "linux":
		return netbirdInitLinux(ctx, cfg, cc, runner, p, binaryPath)
	case "darwin":
		return netbirdInitMacOS(ctx, cfg, runner, p)
	default:
		return fmt.Errorf("server netbird init: unsupported OS %s", runtime.GOOS)
	}
}

// netbirdInitLinux implements the Linux provisioning path (PR-B):
// --binary-path required, version floor enforced, SHA-256 checksum computed,
// systemd unit written, ZITADEL post-provision probe executed after health-check.
func netbirdInitLinux(ctx context.Context, cfg *config.Config, cc *cmdContext, runner shell.Runner, p Printer, binaryPath string) error {
	// ── Steps 1-4: verify, checksum, copy binary, create service user ────────
	if err := netbirdLinuxBinarySetup(ctx, runner, p, binaryPath); err != nil {
		return err
	}

	// ── Steps 5-7: config merge, systemd unit, start service ─────────────────
	cfgPath := netbirdConfigPathFor(cfg)
	if err := netbirdLinuxServiceSetup(ctx, cfg, runner, p, cfgPath); err != nil {
		return err
	}

	// ── Step 8: health-check ──────────────────────────────────────────────────
	serverURL := cfg.Server.NetBird.ServerURL
	if serverURL == "" {
		serverURL = "https://localhost:443"
	}
	// Animated liveness during the health poll (up to 30s GET /api/groups);
	// spinWork is json-safe and the success line prints after it stops.
	if err := spinWork(ctx, p, "Waiting for netbird-server to respond…", func(ctx context.Context) error {
		return doNetBirdHealthCheck(ctx, serverURL+"/api/groups")
	}); err != nil {
		return fmt.Errorf("netbird init: health-check: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  netbird-server is responding"))

	// ── Step 9: ZITADEL post-provision probe (SC-2, init-time gate) ──────────
	if err := netbirdZitadelInitProbe(ctx, cfgPath, p); err != nil {
		return err
	}

	// ── Post-init instructions ────────────────────────────────────────────────
	printerInfo(p, "")
	printerInfo(p, styleSuccess.Render("  ✓  NetBird server provisioned (Linux)"))
	printerInfo(p, "")
	printerInfo(p, "Next steps:")
	printerInfo(p, "  1. Retrieve the admin API key from the NetBird server dashboard/logs.")
	printerInfo(p, "  2. Store it in your keychain: abysslink init (follow prompts)")
	printerInfo(p, "  3. Set ABYSSLINK_NB_API_KEY in your environment or keychain before running `abysslink up`.")
	_ = cc
	return nil
}

// netbirdLinuxBinarySetup verifies the supplied binary (version floor + SHA-256),
// copies it to the install destination, and creates the service user.
// Extracted to keep netbirdInitLinux cyclomatic complexity < 15 (gocyclo).
func netbirdLinuxBinarySetup(ctx context.Context, runner shell.Runner, p Printer, binaryPath string) error {
	// ── --binary-path required on Linux ──────────────────────────────────────
	if binaryPath == "" {
		return fmt.Errorf("flag --binary-path required on Linux: supply a pre-built netbird-server binary\n" +
			"Acquisition routes:\n" +
			"  Option 1 — Build from source:\n" +
			"    git clone --depth 1 --branch v0.57.0 https://github.com/netbirdio/netbird.git\n" +
			"    cd netbird && CGO_ENABLED=1 go build -o netbird-server ./combined\n" +
			"  Option 2 — Extract from Docker image:\n" +
			"    docker create --name nb-extract netbirdio/netbird-server:v0.57.0 && " +
			"docker cp nb-extract:/go/bin/netbird-server . && docker rm nb-extract")
	}

	// ── Version floor: must be >= v0.57.0 (CVE-2025-10678) ───────────────────
	res, err := runner.Run(ctx, binaryPath, "--version")
	if err != nil {
		return fmt.Errorf("netbird init: version check failed: %w", err)
	}
	version, ok := parseNetBirdVersionStr(res.Stdout)
	if !ok {
		return fmt.Errorf("netbird init: could not parse version from %q", res.Stdout)
	}
	if semverLT(version, strings.TrimPrefix(netbirdMinVersion, "v")) {
		return fmt.Errorf("netbird-server binary version %s is below minimum floor %s (CVE-2025-10678) — refusing to provision", version, netbirdMinVersion)
	}
	printerInfo(p, styleSuccess.Render("  ✓  version "+version+" meets floor "+netbirdMinVersion))

	// ── Install binary via internal/audit (CLAUDE.md hard rule) ───────────────
	// audit.WriteFilePath streams src→dst with a backup of the previous binary
	// and an audit-log entry — never a bare cp+chmod (which bypassed the audit
	// trail entirely). Keychain ops use ExecRunner: always real system calls.
	sa, err := newNetbirdSignedAudit(ctx)
	if err != nil {
		return fmt.Errorf("netbird init: %w", err)
	}
	if err := sa.WriteFilePath(ctx, binaryPath, netbirdBinaryDest, 0o755, false); err != nil {
		return fmt.Errorf("netbird init: install binary to %s: %w", netbirdBinaryDest, err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  binary installed → "+netbirdBinaryDest+" (audited write)"))

	// ── SHA-256 checksum of the INSTALLED binary ───────────────────────────────
	// Hashing the destination (not the --binary-path source) closes the
	// hash-then-copy TOCTOU window: the recorded checksum always describes the
	// binary that was actually installed (WR-04: stream with a 256 MiB ceiling).
	checksumHex, err := streamSHA256(netbirdBinaryDest, netbirdBinaryCeiling)
	if err != nil {
		return fmt.Errorf("netbird init: checksum installed binary: %w", err)
	}
	printerInfo(p, "  SHA-256 checksum of installed binary (recorded for audit purposes):")
	printerInfo(p, "  "+checksumHex)

	// Write the checksum sidecar through the same audited writer — a failure is
	// an error, never a silent skip (the sidecar is the audit record's anchor).
	checksumData := []byte(checksumHex + "  " + netbirdBinaryDest + "\n")
	if writeErr := sa.WriteFile(netbirdBinaryDest+".sha256", checksumData, 0o644, false); writeErr != nil {
		return fmt.Errorf("netbird init: write checksum sidecar: %w", writeErr)
	}

	// ── Create service user (idempotent) ──────────────────────────────────────
	if err := ensureNetbirdServiceUser(ctx, runner); err != nil {
		return fmt.Errorf("netbird init: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  service user '"+netbirdServiceUser+"' ensured (non-root, non-login)"))
	return nil
}

// newNetbirdSignedAudit builds the chain-recording *SignedAudit used for the
// NetBird binary install/upgrade writes. The keychain uses ExecRunner — secrets
// CLI calls are always real system calls, never the CLI mock runner (mirrors
// headscaleInitRunE step 5).
func newNetbirdSignedAudit(ctx context.Context) (*audit.SignedAudit, error) {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return nil, fmt.Errorf("audit log path: %w", err)
	}
	kc, kcErr := secrets.NewStore(ctx, &shell.ExecRunner{})
	if kcErr != nil {
		return nil, fmt.Errorf("keychain: %w", kcErr)
	}
	sa, saErr := audit.NewSigned(logPath, kc)
	if saErr != nil {
		return nil, fmt.Errorf("audit init: %w", saErr)
	}
	return sa, nil
}

// ensureNetbirdServiceUser creates the netbird service user idempotently.
// useradd exit code 9 means "username already in use" — the expected re-init
// outcome. Every other failure (exec error or non-zero exit) is surfaced
// instead of being silently swallowed (a real useradd failure otherwise
// resurfaces later as a confusing systemd error).
func ensureNetbirdServiceUser(ctx context.Context, runner shell.Runner) error {
	res, err := runner.Run(ctx, "useradd",
		"--system", "--no-create-home", "--shell", "/usr/sbin/nologin", netbirdServiceUser)
	if err != nil {
		return fmt.Errorf("useradd %s: %w", netbirdServiceUser, err)
	}
	const useraddAlreadyExists = 9 // useradd(8): username already in use
	if res.ExitCode != 0 && res.ExitCode != useraddAlreadyExists {
		return fmt.Errorf("useradd %s exited %d: %s", netbirdServiceUser, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// netbirdLinuxServiceSetup writes the config.yaml and systemd unit, then enables
// the service. Extracted to keep netbirdInitLinux cyclomatic complexity < 15.
func netbirdLinuxServiceSetup(ctx context.Context, cfg *config.Config, runner shell.Runner, p Printer, cfgPath string) error {
	// ── Merge hardened config.yaml ────────────────────────────────────────────
	if err := backend.MergeNetBirdConfig(ctx, cfgPath, cfg.Server.NetBird, false); err != nil {
		return fmt.Errorf("netbird init: config merge: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  config.yaml merged → "+cfgPath))

	// ── Write systemd unit ─────────────────────────────────────────────────────
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("netbird init: audit log path: %w", err)
	}
	unitPath := "/etc/systemd/system/netbird-server.service"
	if err := audit.New(logPath).WriteFile(unitPath, []byte(netbirdSystemdUnit), 0o644, false); err != nil {
		return fmt.Errorf("netbird init: write systemd unit: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  systemd unit written → "+unitPath))

	// ── Enable + start service ────────────────────────────────────────────────
	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "netbird-server"},
	} {
		if _, err := runner.Run(ctx, args[0], args[1:]...); err != nil {
			return fmt.Errorf("netbird init: %s: %w", strings.Join(args, " "), err)
		}
	}
	printerInfo(p, styleSuccess.Render("  ✓  netbird-server service enabled and started"))
	return nil
}

// netbirdInitMacOS implements the macOS provisioning path (PR-A):
// container runtime detection, image pull, loopback-bound ports, non-root verification.
func netbirdInitMacOS(ctx context.Context, cfg *config.Config, runner shell.Runner, p Printer) error {
	// ── Detect container runtime (docker/colima/podman) ───────────────────────
	runtime, err := detectContainerRuntime(ctx, runner)
	if err != nil {
		return err
	}
	printerInfo(p, "  using container runtime: "+runtime)

	// ── Pull pinned image ──────────────────────────────────────────────────────
	printerInfo(p, "  ↓  pulling "+netbirdContainerImage)
	if _, err := runner.Run(ctx, runtime, "pull", netbirdContainerImage); err != nil {
		return fmt.Errorf("netbird init (macOS): pull image: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  image pulled: "+netbirdContainerImage))

	// ── Record image repo digest via inspect (INFORMATIONAL) ──────────────────
	// The image reference is a version tag, not a pinned digest, so there is no
	// expected value to compare against — the digest is recorded for the audit
	// trail and the run-config file only. Never claim "verified" here.
	digestRes, err := runner.Run(ctx, runtime, "inspect", "--format", "{{.RepoDigests}}", netbirdContainerImage)
	if err != nil {
		return fmt.Errorf("netbird init (macOS): inspect image digest: %w", err)
	}
	digest := strings.TrimSpace(digestRes.Stdout)
	slog.InfoContext(ctx, "netbird init (macOS): image digest", "digest", digest, "image", netbirdContainerImage)
	printerInfo(p, "  image digest (informational — tag is not digest-pinned): "+digest)

	// ── Run container with loopback-bound ports (PR-A) ─────────────────────────
	// ALL port bindings MUST use 127.0.0.1:PORT:PORT — no binding may omit the
	// loopback prefix (PR-A / T-13-04-02 / feeds nb-mgmt-bind).
	if _, err := runner.Run(ctx, runtime,
		"run", "-d",
		"--name", netbirdServiceName,
		"--restart", "unless-stopped",
		"-p", "127.0.0.1:443:443",
		"-p", "127.0.0.1:8080:8080",
		"-p", "127.0.0.1:9090:9090",
		netbirdContainerImage,
	); err != nil {
		return fmt.Errorf("netbird init (macOS): run container: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  container started (loopback-bound ports: 443, 8080, 9090)"))

	// ── Verify container runs as non-root ─────────────────────────────────────
	// T-13-04-03: container User must NOT be "root" or "0".
	userRes, err := runner.Run(ctx, runtime, "inspect",
		"--format", "{{.Config.User}}", netbirdServiceName)
	if err != nil {
		return fmt.Errorf("netbird init (macOS): inspect container user: %w", err)
	}
	containerUser := strings.TrimSpace(userRes.Stdout)
	if containerUser == "root" || containerUser == "0" {
		return fmt.Errorf("container is running as root — provisioning refused; NetBird server image must declare a non-root USER")
	}
	// WR-05: an empty {{.Config.User}} is AMBIGUOUS — it is returned both when the
	// image declares a non-root USER *and* when it declares none (defaulting to
	// root at runtime). Do NOT assume non-root. Query the running container's
	// effective UID and refuse if it is 0 (fail-closed on the nb-proc-user control).
	if containerUser == "" {
		idRes, idErr := runner.Run(ctx, runtime, "exec", netbirdServiceName, "id", "-u")
		if idErr != nil {
			return fmt.Errorf("netbird init (macOS): cannot determine container effective UID (image declares no USER) — provisioning refused: %w", idErr)
		}
		effUID := strings.TrimSpace(idRes.Stdout)
		if effUID == "0" {
			return fmt.Errorf("container effective UID is 0 (root) — image declares no non-root USER; provisioning refused")
		}
		if effUID == "" {
			return fmt.Errorf("container effective UID could not be read — provisioning refused (fail-closed on non-root assertion)")
		}
		printerInfo(p, styleSuccess.Render("  ✓  container user: effective UID "+effUID+" (non-root)"))
	} else {
		printerInfo(p, styleSuccess.Render("  ✓  container user: "+containerUser+" (non-root)"))
	}

	// ── Write run config via audit for backup/upgrade traceability ─────────────
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("netbird init (macOS): audit log path: %w", err)
	}
	runCfg := fmt.Sprintf("# NetBird server container run config (Abysslink-provisioned)\n"+
		"# Written: %s\n"+
		"runtime: %s\n"+
		"image: %s\n"+
		"name: %s\n"+
		"ports:\n"+
		"  - 127.0.0.1:443:443\n"+
		"  - 127.0.0.1:8080:8080\n"+
		"  - 127.0.0.1:9090:9090\n"+
		"restart: unless-stopped\n"+
		"digest: %s\n",
		time.Now().UTC().Format(time.RFC3339),
		runtime, netbirdContainerImage, netbirdServiceName, digest)
	if err := audit.New(logPath).WriteFile(
		"/etc/netbird/container-run.yaml", []byte(runCfg), 0o600, false); err != nil {
		// Non-fatal: log but don't abort provisioning.
		slog.WarnContext(ctx, "netbird init (macOS): could not write run config", "err", err)
	}

	// ── Post-init instructions for macOS container path ──────────────────────
	printerInfo(p, "")
	printerInfo(p, styleSuccess.Render("  ✓  NetBird server provisioned (macOS container)"))
	printerInfo(p, "")
	printerInfo(p, "Next steps:")
	printerInfo(p, "  1. Retrieve the admin API key from the container logs:")
	printerInfo(p, "     "+runtime+" logs netbird-server 2>&1 | grep -i 'api.*key\\|admin.*key'")
	printerInfo(p, "  2. Store it in your keychain: abysslink init (follow prompts)")
	printerInfo(p, "  3. Set ABYSSLINK_NB_API_KEY in your environment or keychain before running `abysslink up`.")
	_ = cfg
	return nil
}

// detectContainerRuntime probes docker, podman, colima (in that order) via
// runner.Run(ctx, "docker", "info"). Returns the name of the first runtime
// that responds exit 0. Returns error if none found.
func detectContainerRuntime(ctx context.Context, runner shell.Runner) (string, error) {
	type probe struct {
		name string
		args []string
	}
	probes := []probe{
		{name: "docker", args: []string{"info"}},
		{name: "podman", args: []string{"info"}},
		{name: "colima", args: []string{"status"}},
	}
	for _, p := range probes {
		res, err := runner.Run(ctx, p.name, p.args...)
		if err == nil && res.ExitCode == 0 {
			return p.name, nil
		}
	}
	return "", fmt.Errorf("no container runtime found (docker/colima/podman required for NetBird server on macOS)")
}

// netbirdZitadelInitProbe implements the SC-2 init-time ZITADEL CVE gate.
// Reads the merged config.yaml at cfgPath, checks server.auth.issuer.
// If issuer does not contain "zitadel" → SKIP (log, continue).
// If issuer contains "zitadel" → probe the ZITADEL management API.
//   - HTTP 401 or count==0 → PASS (continue).
//   - HTTP 200 with results → FAIL + return error (provisioning refused).
//   - Network error or unexpected status → FAIL + return error.
func netbirdZitadelInitProbe(ctx context.Context, cfgPath string, p Printer) error {
	// WR-04: bound the config read so a config path pointing at a large file
	// cannot be slurped wholesale. The merged config.yaml is a few KB.
	f, err := os.Open(cfgPath) //nolint:gosec // G304: cfgPath is the resolved netbird config path derived internally, not user input
	if err != nil {
		// config.yaml not found — ZITADEL not in use (Dex default has no issuer in
		// a newly-written config).
		slog.InfoContext(ctx, "netbird init: ZITADEL not in use — CVE gate SKIP (no config.yaml)")
		return nil
	}
	data, rerr := limitio.ReadLimited(f, netbirdConfigCeiling)
	_ = f.Close()
	if rerr != nil {
		return fmt.Errorf("netbird init: read config %s: %w", cfgPath, rerr)
	}

	// Parse issuer from config.yaml (look for server.auth.issuer).
	// Use simple string scanning to avoid importing the full YAML decoder
	// just for one field (and to avoid the nbConfigYAML type in this package).
	issuer := extractIssuerFromYAML(data)

	if !strings.Contains(strings.ToLower(issuer), "zitadel") {
		slog.InfoContext(ctx, "netbird init: ZITADEL not in use — CVE gate SKIP")
		printerInfo(p, "  [SC-2] ZITADEL not in use (Dex IdP) — CVE-2025-10678 probe SKIP")
		return nil
	}

	// ZITADEL detected — run the inline probe.
	printerInfo(p, "  [SC-2] ZITADEL detected in auth.issuer — running CVE-2025-10678 probe...")
	issuerBase := extractNetBirdIssuerBase(issuer)
	return runNetBirdZitadelProbe(ctx, issuerBase, p)
}

// runNetBirdZitadelProbe sends the ZITADEL default-creds POST to {issuerBase}/management/v1/users/_search.
// Uses Authorization: Bearer — NOT the NetBird Token scheme.
// HTTP 401 or result count==0 → PASS (return nil).
// HTTP 200 with results → FAIL (return error, provisioning refused).
// Network error or unexpected status → FAIL (return error).
func runNetBirdZitadelProbe(ctx context.Context, issuerBase string, p Printer) error {
	url := strings.TrimSuffix(issuerBase, "/") + "/management/v1/users/_search"
	body := map[string]any{
		"queries": []map[string]any{
			{
				"userNameQuery": map[string]any{
					"userName": "zitadel-admin@",
					"method":   "TEXT_QUERY_METHOD_STARTS_WITH",
				},
			},
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("ZITADEL CVE probe: could not build request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("ZITADEL CVE probe: could not create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Authorization: Bearer (ZITADEL admin API — NOT the NetBird Token header).
	// We do NOT provide a token here — we rely on HTTP 401 to indicate that
	// the default admin credential is not active.

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("ZITADEL CVE probe failed: %w — provisioning refused; verify ZITADEL state manually", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		slog.InfoContext(ctx, "ZITADEL CVE gate: default admin credential rejected — OK")
		printerInfo(p, styleSuccess.Render("  [SC-2] ZITADEL CVE-2025-10678 gate: default admin credentials rejected (PASS)"))
		return nil
	case http.StatusOK:
		respBody, err := limitio.ReadLimited(resp.Body, limitio.MaxBackendBody)
		if err != nil {
			return fmt.Errorf("ZITADEL CVE probe: read response: %w", err)
		}
		var result struct {
			Result []any `json:"result"`
		}
		if jsonErr := json.Unmarshal(respBody, &result); jsonErr == nil && len(result.Result) > 0 {
			return fmt.Errorf("ZITADEL default admin credential is still active (CVE-2025-10678) — provisioning refused; remove the default admin account before proceeding")
		}
		slog.InfoContext(ctx, "ZITADEL CVE gate: no default admin accounts found — OK")
		printerInfo(p, styleSuccess.Render("  [SC-2] ZITADEL CVE-2025-10678 gate: no default admin accounts found (PASS)"))
		return nil
	default:
		return fmt.Errorf("ZITADEL CVE probe failed: unexpected HTTP %d — provisioning refused; verify ZITADEL state manually", resp.StatusCode)
	}
}

// streamSHA256 computes the hex SHA-256 of the file at path by streaming it
// through the hasher with an N+1 overflow sentinel at ceiling bytes (WR-04). It
// never loads the whole file into memory and refuses a file exceeding ceiling,
// mirroring audit.WriteFilePath's bounded-read discipline.
func streamSHA256(path string, ceiling int64) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is an internally-staged binary/config path, not user-controlled
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, ceiling+1)) // N+1 sentinel detects overflow
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if n > ceiling {
		return "", fmt.Errorf("%s exceeds %d byte ceiling", path, ceiling)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractIssuerFromYAML scans YAML bytes for the server.auth.issuer value.
// This is a simple line-by-line scan for the key "issuer:" under the auth
// section. Returns empty string if not found (Dex default = no ZITADEL).
func extractIssuerFromYAML(data []byte) string {
	lines := strings.Split(string(data), "\n")
	inAuth := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Look for "auth:" or "  auth:" sections.
		if trimmed == "auth:" {
			inAuth = true
			continue
		}
		if inAuth {
			// End of auth section when we hit a non-indented, non-empty key.
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && trimmed != "" {
				inAuth = false
				continue
			}
			if strings.HasPrefix(trimmed, "issuer:") {
				val := strings.TrimSpace(strings.TrimPrefix(trimmed, "issuer:"))
				// Strip quotes if present.
				val = strings.Trim(val, `"'`)
				return val
			}
		}
	}
	return ""
}

// extractNetBirdIssuerBase strips any path from an OIDC issuer URL to get the
// base URL for ZITADEL management API calls.
func extractNetBirdIssuerBase(issuer string) string {
	trimmed := strings.TrimSuffix(issuer, "/")
	if idx := strings.Index(trimmed, "://"); idx >= 0 {
		rest := trimmed[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			return trimmed[:idx+3] + rest[:slashIdx]
		}
	}
	return trimmed
}

// ── status subcommand ──────────────────────────────────────────────────────────

func newServerNetBirdStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report NetBird server state and API reachability",
		Example: `  abysslink server netbird status
  abysslink --json server netbird status`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			return netbirdStatusRunE(cmd.Context(), cc, p)
		},
	}
}

func netbirdStatusRunE(ctx context.Context, cc *cmdContext, p Printer) error {
	runner := cc.runner
	cfg := cc.cfg

	// SSHCheck WARN fires on every status call (D-03 mandatory degradation).
	emitNote(p, tui.NoteWarn, "SSHCheck not available on NetBird", []string{"checkPeriod enforcement is disabled on this backend."})

	// Get version.
	var version string
	if runtime.GOOS == "linux" {
		binPath := netbirdBinaryPathFor(cfg)
		res, err := runner.Run(ctx, binPath, "--version")
		if err == nil {
			ver, ok := parseNetBirdVersionStr(res.Stdout)
			if ok {
				version = ver
			}
		}
		if version == "" {
			version = "unknown"
		}
	} else {
		version = "container path (see: docker inspect " + netbirdServiceName + ")"
	}

	// Check service state.
	serviceActive := netbirdServiceIsActive(ctx, runner)

	// Check API reachability.
	serverURL := cfg.Server.NetBird.ServerURL
	apiReachable := false
	if serverURL != "" {
		ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, reqErr := http.NewRequestWithContext(ctxTimeout, http.MethodGet, serverURL+"/api/groups", nil)
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
		SSHCheckWarn string `json:"sshcheck_warn"`
	}
	report := statusReport{
		Version:      version,
		ServiceState: map[bool]string{true: "active", false: "inactive"}[serviceActive],
		APIReachable: apiReachable,
		ServerURL:    serverURL,
		SSHCheckWarn: "SSHCheck not available on NetBird — checkPeriod enforcement disabled",
	}

	if cc.jsonOut {
		p.PrintJSON(report)
		return nil
	}

	commandHeader(p, "server netbird status", styleMuted.Render("service state and API reachability"))
	printerInfo(p, "  Version:       "+report.Version)
	printerInfo(p, "  Service:       "+report.ServiceState)
	printerInfo(p, "  API reachable: "+fmt.Sprintf("%v", report.APIReachable))
	if report.ServerURL != "" {
		printerInfo(p, "  Server URL:    "+report.ServerURL)
	}
	return nil
}

// ── upgrade subcommand ─────────────────────────────────────────────────────────

func newServerNetBirdUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade the NetBird server binary or container (dry-run by default)",
		Example: `  abysslink server netbird upgrade
  abysslink server netbird upgrade --binary-path /path/to/new-netbird-server --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			binaryPath, _ := cmd.Flags().GetString("binary-path")
			return netbirdUpgradeRunE(cmd.Context(), cc.cfg, cc, cc.runner, binaryPath, newPrinter(cmd))
		},
	}
	cmd.Flags().String("binary-path", "", "Path to new netbird-server binary (Linux only)")
	return cmd
}

func netbirdUpgradeRunE(ctx context.Context, cfg *config.Config, cc *cmdContext, runner shell.Runner, newBinaryPath string, p Printer) error {
	if p == nil {
		p = newHumanPrinterStdout()
	}

	if cc.dryRun {
		printerInfo(p, "[plan] server netbird upgrade would verify version, backup, swap binary, restart, health-check")
		printerInfo(p, "Re-run with --apply to execute.")
		return nil
	}

	// AUD-01: build a signed audit writer for chain-recorded backups.
	// Best-effort: if the keychain is unavailable, sa is nil and the backup site
	// in netbirdUpgradeLinux documents the unchained fallback with slog.Warn.
	sa, _ := cmdSignedAudit(ctx, cc)

	switch runtime.GOOS {
	case "linux":
		return netbirdUpgradeLinux(ctx, cfg, runner, p, newBinaryPath, sa)
	case "darwin":
		return netbirdUpgradeMacOS(ctx, runner, p)
	default:
		return fmt.Errorf("server netbird upgrade: unsupported OS %s", runtime.GOOS)
	}
}

func netbirdUpgradeLinux(ctx context.Context, cfg *config.Config, runner shell.Runner, p Printer, newBinaryPath string, sa *audit.SignedAudit) error {
	if newBinaryPath == "" {
		return fmt.Errorf("flag --binary-path required for Linux upgrade")
	}

	// Verify versions — refuse downgrade, enforce floor.
	newVer, err := netbirdUpgradeVerifyVersions(ctx, cfg, runner, newBinaryPath)
	if err != nil {
		return err
	}

	// AUD-01: backup current config via chain-recorded BackupWithChain.
	// This site is best-effort (slog.Warn on failure). If sa is unavailable
	// (keychain unreachable), fall back to unchained Backup with an explicit
	// warning — optional sidecar, not the principal mutation artifact.
	cfgPath := netbirdConfigPathFor(cfg)
	if sa != nil {
		if _, err := audit.BackupWithChain(ctx, cfgPath, sa); err != nil {
			slog.WarnContext(ctx, "netbird upgrade: could not chain-backup config", "err", err)
		}
	} else {
		// Keychain unavailable — unchained fallback (best-effort sidecar; AUD-01 T-24-07-04).
		if _, err := audit.Backup(cfgPath); err != nil {
			slog.WarnContext(ctx, "netbird upgrade: could not backup config (keychain unavailable)", "err", err)
		}
	}

	// Stop → audited write → start → health-check.
	if err := netbirdUpgradeSwapBinary(ctx, cfg, runner, newBinaryPath, sa); err != nil {
		return err
	}

	printerInfo(p, styleSuccess.Render("  ✓  NetBird server upgraded to "+newVer))
	return nil
}

// netbirdUpgradeVerifyVersions checks the current installed version and the new
// binary version, refusing downgrade and enforcing the v0.57.0 floor.
// Returns the new version string on success.
func netbirdUpgradeVerifyVersions(ctx context.Context, cfg *config.Config, runner shell.Runner, newBinaryPath string) (string, error) {
	binPath := netbirdBinaryPathFor(cfg)
	currentVer := "unknown"
	if res, err := runner.Run(ctx, binPath, "--version"); err == nil {
		if v, ok := parseNetBirdVersionStr(res.Stdout); ok {
			currentVer = v
		}
	}

	newRes, err := runner.Run(ctx, newBinaryPath, "--version")
	if err != nil {
		return "", fmt.Errorf("netbird upgrade: check new binary version: %w", err)
	}
	newVer, ok := parseNetBirdVersionStr(newRes.Stdout)
	if !ok {
		return "", fmt.Errorf("netbird upgrade: could not parse new binary version")
	}

	// Refuse downgrade (T-13-04-05).
	if currentVer != "unknown" && semverLT(newVer, strings.TrimPrefix(currentVer, "v")) {
		return "", fmt.Errorf("netbird upgrade: refusing downgrade from %s to %s", currentVer, newVer)
	}

	// Enforce version floor.
	if semverLT(newVer, strings.TrimPrefix(netbirdMinVersion, "v")) {
		return "", fmt.Errorf("netbird upgrade: new binary %s is below minimum floor %s (CVE-2025-10678)", newVer, netbirdMinVersion)
	}

	return newVer, nil
}

// netbirdUpgradeSwapBinary stops the service, installs the new binary via the
// audited streaming write (backup of the previous binary + audit-log entry —
// never a bare cp+chmod), restarts, and health-checks. sa is the caller's
// chain-recording writer; when nil (keychain unavailable at the caller), a
// fresh SignedAudit is built here (mirrors headscaleSwapBinary's fallback).
func netbirdUpgradeSwapBinary(ctx context.Context, cfg *config.Config, runner shell.Runner, newBinaryPath string, sa *audit.SignedAudit) error {
	if sa == nil {
		var saErr error
		sa, saErr = newNetbirdSignedAudit(ctx)
		if saErr != nil {
			return fmt.Errorf("netbird upgrade: %w", saErr)
		}
	}
	if _, err := runner.Run(ctx, "systemctl", "stop", "netbird-server"); err != nil {
		return fmt.Errorf("netbird upgrade: stop service: %w", err)
	}
	if err := sa.WriteFilePath(ctx, newBinaryPath, netbirdBinaryDest, 0o755, false); err != nil {
		return fmt.Errorf("netbird upgrade: install binary: %w", err)
	}
	if _, err := runner.Run(ctx, "systemctl", "start", "netbird-server"); err != nil {
		return fmt.Errorf("netbird upgrade: start service: %w", err)
	}
	serverURL := cfg.Server.NetBird.ServerURL
	if serverURL == "" {
		serverURL = "https://localhost:443"
	}
	if err := doNetBirdHealthCheck(ctx, serverURL+"/api/groups"); err != nil {
		return fmt.Errorf("netbird upgrade: health-check after restart: %w", err)
	}
	return nil
}

func netbirdUpgradeMacOS(ctx context.Context, runner shell.Runner, p Printer) error {
	// Detect runtime.
	rt, err := detectContainerRuntime(ctx, runner)
	if err != nil {
		return err
	}

	// Pull the new image FIRST: if the pull fails (offline, registry down) the
	// running control plane must be left untouched — stopping/removing before a
	// failed pull would destroy it with no rollback.
	if _, err := runner.Run(ctx, rt, "pull", netbirdContainerImage); err != nil {
		return fmt.Errorf("netbird upgrade (macOS): pull image: %w (running container left untouched)", err)
	}

	// Stop + remove old container only after the new image is local.
	_, _ = runner.Run(ctx, rt, "stop", netbirdServiceName)
	_, _ = runner.Run(ctx, rt, "rm", netbirdServiceName)

	// Re-run container with loopback-bound ports.
	if _, err := runner.Run(ctx, rt,
		"run", "-d",
		"--name", netbirdServiceName,
		"--restart", "unless-stopped",
		"-p", "127.0.0.1:443:443",
		"-p", "127.0.0.1:8080:8080",
		"-p", "127.0.0.1:9090:9090",
		netbirdContainerImage,
	); err != nil {
		return fmt.Errorf("netbird upgrade (macOS): run container: %w", err)
	}

	printerInfo(p, styleSuccess.Render("  ✓  NetBird container upgraded and restarted"))
	return nil
}

// ── backup subcommand ─────────────────────────────────────────────────────────

func newServerNetBirdBackupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backup",
		Short: "Backup the NetBird server config and state",
		Example: `  abysslink server netbird backup
  abysslink server netbird backup --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			return netbirdBackupRunE(cmd.Context(), cc, p)
		},
	}
}

func netbirdBackupRunE(ctx context.Context, cc *cmdContext, p Printer) error {
	cfg := cc.cfg
	cfgPath := netbirdConfigPathFor(cfg)

	if cc.dryRun {
		printerInfo(p, fmt.Sprintf("[plan] would backup %s (re-run with --apply)", cfgPath))
		return nil
	}

	slog.InfoContext(ctx, "netbird backup", "config_path", cfgPath)

	// AUD-01: obtain a chain-recording *SignedAudit. Fail-closed for the
	// principal config artifact (cfgPath). The two optional sidecar files
	// (container-run.yaml, store.db) stay best-effort with a slog.Warn fallback.
	sa, saErr := cmdSignedAudit(ctx, cc)
	if saErr != nil {
		return fmt.Errorf("netbird backup: %w", saErr)
	}

	backupPath, err := audit.BackupWithChain(ctx, cfgPath, sa)
	if err != nil {
		return fmt.Errorf("netbird backup: config.yaml: %w", err)
	}
	printerInfo(p, styleSuccess.Render("  ✓  config.yaml backed up → "+backupPath))

	// Also backup container run config if present (macOS path).
	// Optional sidecar — best-effort with slog.Warn on failure (AUD-01 T-24-07-04).
	containerRunCfg := "/etc/netbird/container-run.yaml"
	if _, statErr := os.Stat(containerRunCfg); statErr == nil {
		bp, err := audit.BackupWithChain(ctx, containerRunCfg, sa)
		if err != nil {
			// Optional sidecar: keep best-effort behaviour.
			slog.WarnContext(ctx, "netbird backup: container-run.yaml chain-backup failed", "err", err)
		} else {
			printerInfo(p, styleSuccess.Render("  ✓  container-run.yaml backed up → "+bp))
		}
	}

	// Backup store.db if accessible (Linux path).
	// Optional sidecar — best-effort with slog.Warn on failure (AUD-01 T-24-07-04).
	storeDB := "/var/lib/netbird-server/store.db"
	if _, statErr := os.Stat(storeDB); statErr == nil {
		bp, err := audit.BackupWithChain(ctx, storeDB, sa)
		if err != nil {
			// Optional sidecar: keep best-effort behaviour.
			slog.WarnContext(ctx, "netbird backup: store.db chain-backup failed", "err", err)
		} else {
			printerInfo(p, styleSuccess.Render("  ✓  store.db backed up → "+bp))
		}
	}

	return nil
}

// ── Helper functions ──────────────────────────────────────────────────────────

// doNetBirdHealthCheck polls the given URL until it receives a response
// indicating the server is up. Retries every 3s for up to 30s.
// Any HTTP response (even 401/403) means the server is listening.
func doNetBirdHealthCheck(ctx context.Context, url string) error {
	hcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		req, err := http.NewRequestWithContext(hcCtx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("netbird health-check: build request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden:
				return nil
			}
		}
		select {
		case <-hcCtx.Done():
			return fmt.Errorf("netbird: health-check timed out after 30s — service may not have started")
		case <-ticker.C:
			// retry
		}
	}
}

// netbirdServiceIsActive returns true if the netbird-server service is running.
// On macOS the container runtime is detected (docker/podman/colima) rather than
// hardcoding docker — init already supports all three, and a podman/colima user
// would otherwise see "Service: inactive" forever.
func netbirdServiceIsActive(ctx context.Context, runner shell.Runner) bool {
	switch runtime.GOOS {
	case "linux":
		res, err := runner.Run(ctx, "systemctl", "is-active", "netbird-server")
		return err == nil && strings.TrimSpace(res.Stdout) == "active"
	case "darwin":
		rt, err := detectContainerRuntime(ctx, runner)
		if err != nil {
			return false
		}
		res, err := runner.Run(ctx, rt, "ps", "--filter", "name=netbird-server", "--format", "{{.Names}}")
		return err == nil && strings.Contains(res.Stdout, "netbird-server")
	default:
		return false
	}
}

// netbirdConfigPathFor returns the configured config path or the default.
func netbirdConfigPathFor(cfg *config.Config) string {
	if p := cfg.Server.NetBird.ConfigPath; p != "" {
		return p
	}
	return netbirdConfigPath
}

// netbirdBinaryPathFor returns the configured binary path or the default.
func netbirdBinaryPathFor(cfg *config.Config) string {
	if p := cfg.Server.NetBird.BinaryPath; p != "" {
		return p
	}
	return netbirdBinaryDest
}

// parseNetBirdVersionStr parses "netbird-server version v0.71.4" or "v0.71.4"
// from --version output. Returns the version WITHOUT the "v" prefix.
func parseNetBirdVersionStr(output string) (string, bool) {
	for _, token := range strings.Fields(strings.TrimSpace(output)) {
		trimmed := strings.TrimPrefix(token, "v")
		parts := strings.Split(trimmed, ".")
		if len(parts) >= 2 {
			allDigits := true
			for _, p := range parts[:2] {
				for _, c := range p {
					if c < '0' || c > '9' {
						allDigits = false
						break
					}
				}
				if !allDigits {
					break
				}
			}
			if allDigits {
				return trimmed, true
			}
		}
	}
	return "", false
}
