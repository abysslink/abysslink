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
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/gate"
	"github.com/abysslink/abysslink/internal/metrics"
	notifymod "github.com/abysslink/abysslink/internal/modules"
	notify "github.com/abysslink/abysslink/internal/modules/notify"
	platformauto "github.com/abysslink/abysslink/internal/platform/auto"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

// directNotifier adapts the notify module's direct backend to daemon.Notifier.
// It deliberately uses SendDirect (not Send) so deliveries never loop back into
// the daemon socket.
type directNotifier struct{ m *notify.Module }

func (d directNotifier) Send(ctx context.Context, title, body string) error {
	return d.m.SendDirect(ctx, title, body)
}

func main() {
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
