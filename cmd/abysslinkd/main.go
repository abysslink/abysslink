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

	bbolt "go.etcd.io/bbolt"
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
	"github.com/abysslink/abysslink/internal/push"
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

	// D-14: emit experimental startup warnings when APNs or FCM is enabled.
	// These legs are interface-complete but ship disabled by default until the
	// v5 native app provides a receiver; operators enabling them accept the
	// experimental status.
	if cfg.Gateway.APNs.Enabled {
		slog.Warn("abysslinkd: APNs push leg is EXPERIMENTAL — disabled by default (D-14); ensure bundle_id is correct before relying on APNs delivery")
	}
	if cfg.Gateway.FCM.Enabled {
		slog.Warn("abysslinkd: FCM push leg is EXPERIMENTAL — disabled by default (D-14); ensure GCP service-account credentials are configured")
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

	// Backend client resolves this node's tailnet IP. The notify module needs it
	// to target ntfy at its tailnet-IP bind: ntfy binds the tailnet IP only, so a
	// nil backend forces a localhost fallback that fails under the secure binding
	// (connection refused -> the daemon returns 502 to notify clients). Built here
	// (before notify wiring) and reused by the metrics listener below. bc may be
	// nil when the backend is unconfigured -- every consumer is nil-safe (notify
	// falls back to localhost, metrics nil-guards internally).
	bc, bcErr := backend.New(cfg, base)
	if bcErr != nil {
		slog.Warn("abysslinkd: backend client unavailable; tailnet-IP-dependent features degraded", "err", bcErr)
	}

	nm := notify.New(notifymod.Deps{Cfg: cfg, Runner: gated, Keychain: kc, Platform: plat, Backend: bc})
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
	//
	// The audited device store is returned so the Phase 29 push retry goroutine
	// reuses the SAME handle for its dead-token prune (WR-04): a second store
	// over devices.json with a nil audit writer would write revocations outside
	// the backup+audit chain and create a concurrent-writer hazard. devStore is
	// nil when the device path/audit log is unavailable (content listener stays
	// disabled); the push prune path then degrades to a no-op.
	devStore := wireContentDeps(srv, cfg, kc)

	// Phase 29 push outbox (D-06 structural exemption):
	// The bbolt push-outbox file is daemon runtime state opened at the
	// composition root, NEVER through internal/audit.
	// Structural audit-mutation exemption D-06 (same shape as Phase 27 D-40
	// ungated-runner bypass): bbolt is a single-writer runtime file, not a
	// user-data mutation subject to backup+audit. The file is 0600 and lives
	// under XDG_STATE_HOME/abysslink/ alongside devices.json.
	//
	// kc (the platform keychain constructed at line 169 and already threaded
	// into wireContentDeps) is passed through so the always-on UnifiedPush leg
	// can attach Basic auth for the sovereign self-hosted ntfy default (CR-01).
	// NewUnifiedPushGateway tolerates a nil kc, so headless/no-auth setups are
	// unaffected. devStore (the audited handle from wireContentDeps) is reused
	// for the dead-token prune so revocations stay on the audit chain (WR-04).
	wirePushOutbox(ctx, cfg, srv, kc, devStore)

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
	// bc is the backend client constructed above (before notify wiring) and
	// reused here; StartMetricsServer nil-guards internally if it is nil.
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
//
// It returns the constructed *device.Store so the composition root can hand the
// SAME audited handle to the Phase 29 push retry goroutine (WR-04): the
// dead-token prune must go through this audited writer, not a second nil-audit
// store over the same devices.json. Returns nil on any wiring failure.
func wireContentDeps(srv *daemon.Server, cfg *config.Config, kc secrets.KeychainStore) *device.Store {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		slog.Warn("abysslinkd: audit log path unavailable; content listener stays disabled", "err", err)
		return nil
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
		return nil
	}
	devStore := device.New(devPath, aud, kc, nil)
	srv.SetDeviceStore(devStore)
	srv.SetAuditAppender(aud)
	srv.SetContentTLS(contentTLSProvider(cfg))
	return devStore
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

// dedupSweepInterval is the steady-state cadence for the push-outbox dedup
// sweep (D-07). Hourly in production; overridable by tests via startDedupSweeper.
const dedupSweepInterval = 1 * time.Hour

// startDedupSweeper launches the periodic push-outbox dedup sweep goroutine
// (D-07, T-29-01-5 / T-29-04-3). The 24h dedup TTL alone does not reclaim
// bbolt space: DedupSeen returning false on an expired key does NOT delete it —
// only SweepDedup does. Without a periodic sweep a long-uptime daemon
// accumulates expired dedup entries ("degenerate growth"), reclaimed only on
// restart. The startup sweep in wirePushOutbox handles the boot case; this
// ticker handles the steady state. It shares the outbox handle's lifetime:
// both this goroutine and the retry goroutine exit on ctx.Done(), and the
// retry goroutine owns the deferred bbolt close — so this sweeper must not
// outlive ctx. A sweep racing a closed DB returns an error (never a panic),
// which is logged and harmless on shutdown.
func startDedupSweeper(ctx context.Context, outbox *push.Outbox, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if sweepErr := outbox.SweepDedup(); sweepErr != nil {
					slog.Warn("abysslinkd: push dedup sweep failed", "err", sweepErr)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// xdgStateHome returns the XDG_STATE_HOME base directory, defaulting to
// ~/.local/state when the environment variable is unset. It is the canonical
// location for abysslinkd runtime state files (bbolt outbox, devices.json).
func xdgStateHome() string {
	if s := os.Getenv("XDG_STATE_HOME"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".local/state"
	}
	return filepath.Join(home, ".local", "state")
}

// pushDeviceStoreAdapter bridges daemon.DeviceStore (uses device.Record) to
// push.DeviceStore (uses push.DeviceRecord). It wraps device.Store so the push
// retry goroutine can call List and RevokeByID without importing internal/device.
type pushDeviceStoreAdapter struct{ s *device.Store }

// List returns all device records converted to push.DeviceRecord. Only active
// records with a push token are relevant for the retry goroutine; the adapter
// returns all so the runner can filter. ProviderToken = PushToken (the opaque
// push identity minted at enrollment).
//
// WR-03: Platform is set from push.PlatformUnifiedPush rather than a bare string
// literal. The current enrollment schema (device.Record) carries no
// platform-specific token, so every enrolled device IS a UnifiedPush endpoint;
// the v5 app enrollment will add APNs/FCM tokens to a separate field and this
// adapter will then carry the record's real platform.
func (a pushDeviceStoreAdapter) List() []push.DeviceRecord {
	records := a.s.List()
	out := make([]push.DeviceRecord, 0, len(records))
	for _, r := range records {
		out = append(out, push.DeviceRecord{
			ID:        r.ID,
			Platform:  push.PlatformUnifiedPush,
			PushToken: r.PushToken,
			Revoked:   r.Revoked,
		})
	}
	return out
}

// RevokeByID permanently revokes the device with the given ULID ID via the
// wrapped device.Store (dead-token prune, D-12). Forwards to Store.RevokeByID.
func (a pushDeviceStoreAdapter) RevokeByID(ctx context.Context, id string) error {
	return a.s.RevokeByID(ctx, id)
}

// wirePushOutbox opens the bbolt push-outbox database and starts the Phase 29
// push gateway retry goroutine. On any failure it logs and returns without
// wiring — the daemon continues in degraded mode without push delivery.
//
// Structural audit-mutation exemption D-06: the bbolt outbox is daemon runtime
// state opened at the composition root, never via internal/audit (same shape
// as D-40 ungated-runner bypass).
//
// kc is the platform keychain (may be nil in degraded mode); it is handed to
// the always-on UnifiedPush gateway so authenticated self-hosted ntfy
// endpoints receive Basic auth (CR-01). A nil kc degrades to no-auth POSTs,
// which is correct for headless/no-auth ntfy instances.
//
// devStore is the SAME audited *device.Store the content listener uses (from
// wireContentDeps). The retry goroutine's dead-token prune (RevokeByID) writes
// devices.json through this audited handle so revocations keep their
// backup+audit-chain entry (WR-04 / CLAUDE.md "audit + backup on every file
// mutation"). A nil devStore (degraded wiring) disables the prune — a no-op,
// not fatal — and never opens an unaudited second writer over devices.json.
func wirePushOutbox(ctx context.Context, cfg *config.Config, srv *daemon.Server, kc secrets.KeychainStore, devStore *device.Store) {
	outboxDir := filepath.Join(xdgStateHome(), "abysslink")
	if err := os.MkdirAll(outboxDir, 0o700); err != nil {
		slog.Warn("abysslinkd: push outbox dir creation failed; push disabled", "err", err)
		return
	}
	outboxPath := filepath.Join(outboxDir, "push_outbox.db")
	// Phase 29 push outbox — opened at the composition root, NEVER through
	// internal/audit. Structural audit-mutation exemption D-06 (same shape as
	// Phase 27 D-40 ungated-runner bypass).
	outboxDB, err := bbolt.Open(outboxPath, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		slog.Warn("abysslinkd: push outbox open failed; push disabled", "path", outboxPath, "err", err)
		return
	}
	outbox := push.NewOutbox(outboxDB)
	counters := &push.GatewayCounters{}

	// Sweep expired dedup entries at daemon start (D-07).
	if sweepErr := outbox.SweepDedup(); sweepErr != nil {
		slog.Warn("abysslinkd: push dedup sweep failed at startup", "err", sweepErr)
	}
	// D-07: also sweep hourly. The TTL alone never deletes expired keys —
	// only SweepDedup does — so the steady-state daemon needs a periodic sweep
	// to bound bbolt growth (T-29-01-5 / T-29-04-3).
	startDedupSweeper(ctx, outbox, dedupSweepInterval)

	// Build the gateway map. UnifiedPush is always registered (sovereign path,
	// D-18). APNs and FCM are registered only when enabled in config (D-14).
	// Keychain is nil-safe: NewUnifiedPushGateway degrades when kc is nil.
	gateways := make(map[string]push.Gateway)
	// CR-01: hand the daemon's keychain to the UnifiedPush leg so authenticated
	// self-hosted ntfy endpoints receive Basic auth. A nil kc still degrades to
	// no-auth POSTs (headless/no-auth ntfy); only the previously-broken
	// authenticated path is fixed.
	gateways["unifiedpush"] = push.NewUnifiedPushGateway(kc)

	// cfg.Gateway.APNs/FCM gates: disabled by default (D-14). The startup
	// warnings were already emitted above in main() after config load.
	//
	// WR-06: these legs are ENABLED-but-NOT-WIRED — the gateway is intentionally
	// omitted from the gateways map (credential resolution lands with the v5
	// receiver). The log honestly says "enabled but not yet wired" rather than
	// "registered", which would assert a capability that does not exist and
	// mislead an operator debugging why an enabled leg never delivers. If an
	// APNs/FCM entry is ever enqueued, processEntry drops it after
	// maxNoGatewayAttempts rather than rescheduling forever.
	if cfg.Gateway.APNs.Enabled {
		slog.Warn("abysslinkd: APNs push leg enabled but NOT yet wired (EXPERIMENTAL) — deliveries deferred until the v5 receiver; no APNs gateway is registered")
	}
	if cfg.Gateway.FCM.Enabled {
		slog.Warn("abysslinkd: FCM push leg enabled but NOT yet wired (EXPERIMENTAL) — deliveries deferred until the v5 receiver; no FCM gateway is registered")
	}

	// Inject the outbox and counters into the daemon Server (D-10 fan-out).
	srv.SetOutbox(outbox, counters)

	// WR-01: emit the push-creds-keychain doctor signal on GET /status. The
	// UnifiedPush leg attaches Basic auth from the keychain ("abysslink",
	// "ntfy-password"); when no keychain backend is available that auth path can
	// never be attached, so report "unavailable" — otherwise the auth path is
	// functional and we report "ok". (A no-auth ntfy setup is valid and still
	// "ok": the gateway degrades to unauthenticated POSTs by design, D-18.)
	if kc != nil {
		srv.SetGatewayCredsStatus("ok")
	} else {
		srv.SetGatewayCredsStatus("unavailable")
	}

	// Resolve the device store adapter for the retry goroutine. WR-04: REUSE the
	// single audited *device.Store the content listener already owns rather than
	// opening a second nil-audit handle over the same devices.json. A dead-token
	// prune (RevokeByID) therefore goes through the backup+audit chain, and one
	// store instance owns the file (no concurrent-writer hazard). A nil devStore
	// (degraded wiring) leaves the runner without a device store — dead-token
	// prune becomes a no-op, which is non-fatal.
	var pushStore push.DeviceStore
	if devStore != nil {
		pushStore = pushDeviceStoreAdapter{s: devStore}
	} else {
		slog.Warn("abysslinkd: push device store unavailable; dead-token prune disabled")
	}

	// Start the retry goroutine. It closes bbolt on daemon exit via the deferred
	// close registered by the daemon's shutdown path (not here — the goroutine
	// holds no close obligation; the DB handle ownership stays with wirePushOutbox's
	// caller via a deferred close in the goroutine itself to avoid a leak).
	go func() {
		defer func() { _ = outboxDB.Close() }()
		push.RunOutboxRetry(ctx, outbox, gateways, pushStore, counters)
	}()

	slog.Info("abysslinkd: push outbox started", "path", outboxPath)
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
