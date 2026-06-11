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

// Command abysslinkd is the Abysslink user-level daemon. It serves the notify
// Unix socket and runs the configured watchers.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"tailscale.com/client/local"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/gate"
	"github.com/abysslink/abysslink/internal/metrics"
	notifymod "github.com/abysslink/abysslink/internal/modules"
	notify "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/notifyv2"
	platformauto "github.com/abysslink/abysslink/internal/platform/auto"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/session"
	"github.com/abysslink/abysslink/internal/shell"
)

// directNotifier adapts the notify module's direct backend to daemon.Notifier.
// It deliberately uses SendDirect / SendDirectWithOptions (not Send) so
// deliveries never loop back into the daemon socket.
type directNotifier struct{ m *notify.Module }

// Compile assertion: directNotifier satisfies the widened daemon.Notifier
// (Send + SendNote).
var _ daemon.Notifier = directNotifier{}

func (d directNotifier) Send(ctx context.Context, title, body string) error {
	return d.m.SendDirect(ctx, title, body)
}

// SendNote delivers a pre-rendered v2 note via the module's direct backend on
// the same per-rig topic with the same keychain credentials (D-20: no
// transport changes beyond the X-Click leg).
func (d directNotifier) SendNote(ctx context.Context, n notifyv2.RenderedNote) error {
	return d.m.SendDirectWithOptions(ctx, n.Title, n.Body, notify.SendOptions{
		Priority: n.Priority,
		Tags:     n.Tags,
		Click:    n.Click,
	})
}

// version is the daemon build version. "dev" unless overridden at build time
// via -ldflags "-X main.version=...".
var version = "dev"

// usageText is the abysslinkd usage block printed for -h/--help and on
// argument errors.
const usageText = `abysslinkd — the Abysslink user-level daemon.

Serves the notify Unix socket and runs the configured watchers. It is
normally managed by ` + "`abysslink daemon start --apply`" + `, not run by hand.

Usage:
  abysslinkd [flags]

Flags:
  -h, --help     show this help and exit
      --version  print the daemon version and exit

Configuration is read from abysslink.yaml (XDG_CONFIG_HOME or
~/.config/abysslink/abysslink.yaml).
`

// parseArgs handles the daemon's command-line arguments BEFORE any side effect
// (config load, socket bind, tmux probes, ntfy POSTs). A packaging script or
// user probing `abysslinkd --help` / `--version` must never start a network
// daemon (UX review CRITICAL #1).
//
// Returns (exitCode, false) when the process should exit immediately with
// exitCode, or (0, true) when startup should proceed:
//   - -h/--help  → usage on out, exit 0
//   - --version  → version on out, exit 0
//   - unknown flags or positional args → error + usage on errOut, exit 2
func parseArgs(args []string, out, errOut io.Writer) (int, bool) {
	fs := flag.NewFlagSet("abysslinkd", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {} // suppress flag's default usage; printed explicitly below
	showVersion := fs.Bool("version", false, "print the daemon version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// -h/--help: usage to stdout, exit 0 (conventional help contract).
			_, _ = fmt.Fprint(out, usageText)
			return 0, false
		}
		// Unknown flag: flag already printed the error line to errOut.
		_, _ = fmt.Fprint(errOut, "\n"+usageText)
		return 2, false
	}
	if *showVersion {
		_, _ = fmt.Fprintf(out, "abysslinkd %s\n", version)
		return 0, false
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(errOut, "abysslinkd: unknown argument %q\n\n", fs.Arg(0))
		_, _ = fmt.Fprint(errOut, usageText)
		return 2, false
	}
	return 0, true
}

func main() {
	if code, proceed := parseArgs(os.Args[1:], os.Stdout, os.Stderr); !proceed {
		os.Exit(code)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Base/gated runner split (D-38, D-40): module/consumer execs flow through
	// the observe-only gate decorator; daemon-internal plumbing keeps the
	// ungated base runner — see the D-40 comment at daemon.NewServer below.
	base := &shell.ExecRunner{}
	gated := gate.New(base)

	cfg, err := config.Load(configPath())
	if err != nil {
		slog.Error("abysslinkd: invalid config — refusing to start", "err", err)
		os.Exit(1)
	}

	kc, kerr := secrets.NewStore(ctx, gated)
	if kerr != nil {
		slog.Warn("abysslinkd: keychain backend unavailable", "err", kerr)
		kc = nil
	}
	plat, perr := platformauto.New(gated)
	if perr != nil {
		slog.Error("abysslinkd: platform init failed", "err", perr)
		os.Exit(1)
	}

	nm := notify.New(notifymod.Deps{Cfg: cfg, Runner: gated, Keychain: kc, Platform: plat})
	// D-40: the daemon's internal watchers/probes (and the session registry in
	// plan 27-07) use the ungated base runner so the Phase 30 enforcing gate can
	// never deadlock the daemon on its own plumbing. The bypass is structural —
	// visible right here in the wiring — and not runtime-toggleable.
	srv := daemon.NewServer(directNotifier{m: nm}, base, cfg)
	srv.SetExecCounter(gated.Count)

	// Phase 28 content listener deps (BACK-06/BACK-07): the enrolled-device
	// store (bearer gate + /status devices block), the audit appender for
	// hash-only ack receipts, and the Tailscale TLS provider. A missing
	// dependency disables the content listener (fail closed, one honest
	// warning inside the daemon) — the unix socket keeps serving regardless.
	wireContentDeps(srv, cfg, kc)

	// tmux session registry (Phase 27, BACK-03/BACK-04). D-40: registry execs
	// (tmux -CC attach, list-panes, capture-pane) are daemon-internal plumbing
	// on the ungated PLAIN runner — never gated, so the Phase 30 enforcing
	// gate can never deadlock the daemon on its own plumbing. Run degrades
	// internally when tmux is missing or too old (D-26/D-27): there is no
	// startup failure path here, and GET /sessions reports the honest status.
	// The bridge turns registry transitions into heuristic-origin v2 Messages.
	if cfg.SessionRegistry.Enabled {
		reg := session.New(base, cfg)
		go func() { _ = reg.Run(ctx) }() // Run returns nil after ctx cancel
		srv.SetSessionRegistry(reg)
		go srv.ConsumeTransitions(ctx, reg.Events())
		slog.Info("abysslinkd: session registry enabled (degrades to honest status when tmux is unavailable)")
	} else {
		slog.Info("abysslinkd: session registry disabled by config; /sessions reports registry: disabled")
	}

	// Hourly tamper-evident anchor writer. When a keychain is available and the
	// signed-audit path is reachable, the daemon refreshes the external anchor
	// every hour so `doctor` can detect a stalled daemon or log truncation. The
	// goroutine exits cleanly on context cancellation (no leak) and never blocks
	// the daemon's shutdown path.
	startAnchorWriter(ctx, kc)

	// Opt-in Prometheus /metrics listener (OBS-02/OBS-05, default OFF). When
	// metrics are enabled, StartMetricsServer binds the tailnet IP and serves the
	// OBS-05 gauges; when disabled it returns immediately (no goroutine). The
	// backend client may be nil if the backend is not yet configured — it is
	// passed through unconditionally because the nil guard is the first statement
	// inside StartMetricsServer (T-18-16): no caller-side nil-check that would
	// skip wiring. The registry is a live in-memory sink when enabled, NoopRegistry
	// otherwise so every metrics call is nil-safe.
	// base (D-40): the metrics tailnet-IP binding is a daemon-internal probe.
	bc, bcErr := backend.New(cfg, base)
	if bcErr != nil {
		slog.Warn("abysslinkd: backend client unavailable; metrics binding degraded", "err", bcErr)
	}
	var reg metrics.Registry = metrics.NoopRegistry{}
	if cfg.Observability.Metrics.Enabled {
		reg = metrics.NewMemRegistry()
	}
	daemon.StartMetricsServer(ctx, cfg, reg, bc)

	// Daily fleet digest (OBS-08). Opt-in (default OFF). When enabled, fires at
	// the configured local hour (default 08:00), calls `abysslink status --json`
	// via the sibling CLI binary (never the daemon socket), and delivers an
	// opaque-rig-id summary on the dedicated digest ntfy topic. The goroutine
	// exits cleanly on ctx cancellation; a disabled digest launches no goroutine.
	// base (D-40): the digest scheduler is daemon-internal plumbing (it execs
	// the sibling CLI binary on a timer, like a watcher).
	daemon.StartDigestScheduler(ctx, cfg, directNotifier{m: nm}, base)

	// Opt-in browser dashboard (Phase 19, //go:build webui, default OFF). The
	// base build links a no-op stub (start_webui_stub.go); the webui build wires
	// the TLS+WhoIs server goroutine and prints the loud one-time security note
	// to stderr (cmd entrypoint, not library code — CLAUDE.md). startWebUI also
	// injects the notify-history ring into srv via SetRing so deliveries appear
	// in the /notify view. A disabled webui returns immediately (no goroutine).
	if logPath, lpErr := audit.DefaultLogPath(); lpErr == nil {
		startWebUI(ctx, cfg, srv, logPath)
	} else {
		startWebUI(ctx, cfg, srv, "")
	}

	if err := srv.Run(ctx); err != nil {
		slog.Error("abysslinkd: exited with error", "err", err)
		os.Exit(1)
	}
}

// wireContentDeps constructs the device store (device.DefaultPath + the
// daemon's audit writer + the platform keychain), the BACK-07 ack-receipt
// appender, and the TLS provider, and injects them into the daemon server.
// Any unresolvable dependency is logged and skipped — the daemon then keeps
// the content listener disabled (fail closed) while everything else runs.
func wireContentDeps(srv *daemon.Server, cfg *config.Config, kc secrets.KeychainStore) {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		slog.Warn("abysslinkd: audit log path unavailable; content listener stays disabled", "err", err)
		return
	}
	// One audit writer serves both roles: every devices.json mutation goes
	// through WriteFile (backup + audit entry + atomic write) and ack
	// receipts go through the same chain-aware Append the restore path uses.
	// kc may be nil (degraded keychain) — the writer then falls back to
	// chained-unsigned entries, keeping the chain walkable.
	var aud *audit.Audit
	if kc != nil {
		aud = audit.NewWithKeychain(logPath, kc)
	} else {
		aud = audit.New(logPath)
	}
	devPath, err := device.DefaultPath()
	if err != nil {
		slog.Warn("abysslinkd: device store path unavailable; content listener stays disabled", "err", err)
		return
	}
	srv.SetDeviceStore(device.New(devPath, aud, kc, nil))
	srv.SetAuditAppender(aud)
	srv.SetContentTLS(contentTLSProvider(cfg))
}

// contentTLSProvider returns the content listener's TLS provider: the
// Tailscale local client's GetCertificate — the same WEB-03 path the webui
// listener uses. On non-Tailscale backends GetCertificate cannot provision a
// certificate (#2137), so nil is returned and the daemon keeps the listener
// disabled (fail closed — never plaintext).
func contentTLSProvider(cfg *config.Config) daemon.ContentTLSProvider {
	if cfg.Backend.Type != "" && cfg.Backend.Type != "tailscale" {
		slog.Warn("abysslinkd: content listener TLS unavailable on this backend (GetCertificate is Tailscale-only, #2137)",
			"backend", cfg.Backend.Type)
		return nil
	}
	var lc local.Client // zero value uses the platform-default tailscaled socket
	return func(_ context.Context) (*tls.Config, error) {
		return &tls.Config{
			GetCertificate: lc.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}, nil
	}
}

// startAnchorWriter launches the hourly WriteAnchor goroutine when the signed
// audit path is reachable. Each WriteAnchor call runs under a 30s timeout
// derived from ctx (T-17-11: a stuck keychain must not wedge the daemon). On a
// nil keychain, an unresolvable log path, or an unreachable signed path the
// daemon continues in degraded mode (no signed anchoring); the doctor
// audit-keychain check surfaces the degradation.
func startAnchorWriter(ctx context.Context, kc secrets.KeychainStore) {
	if kc == nil {
		slog.Warn("abysslinkd: keychain unavailable; anchor writer disabled (degraded mode)")
		return
	}
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		slog.Error("abysslinkd: audit log path unavailable; anchor writer disabled", "err", err)
		return
	}
	if _, saErr := audit.NewSigned(logPath, kc); saErr != nil {
		slog.Warn("abysslinkd: signed audit unavailable; anchor writer disabled (degraded mode)", "err", saErr)
		return
	}

	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				writeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				// WR-06: the daemon does not hold the append flock, so use the
				// locked variant to serialise with concurrent cross-process CLI
				// appends and keep the anchor's EntryCount/LastHash consistent.
				if werr := audit.WriteAnchorLocked(writeCtx, logPath, kc); werr != nil {
					slog.Warn("abysslinkd: anchor write failed", "err", werr)
				}
				cancel()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// configPath returns the abysslink.yaml path under XDG_CONFIG_HOME.
func configPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "abysslink.yaml"
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "abysslink", "abysslink.yaml")
}
