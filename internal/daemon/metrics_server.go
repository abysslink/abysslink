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

package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/metrics"
)

const (
	// defaultMetricsPort is the Prometheus exposition port used when
	// observability.metrics.port is unset (OBS-02).
	defaultMetricsPort = 9090
	// metricsContentType is the strict Prometheus text-exposition content type.
	// Prometheus 3.x scrapes fail silently without it (Pitfall 1).
	metricsContentType = "text/plain; version=0.0.4; charset=utf-8"
	// metricsShutdownTimeout bounds the graceful Shutdown so the listener port
	// closes within the 500ms OBS-05 criterion (Pitfall 3).
	metricsShutdownTimeout = 400 * time.Millisecond
	// metricsProbeInterval is how often the OBS-05 metrics are refreshed from
	// current daemon state.
	metricsProbeInterval = 60 * time.Second
)

// StartMetricsServer launches the opt-in Prometheus /metrics TCP listener bound
// to the tailnet IP resolved via backend.Client.IP. It returns immediately when
// metrics are disabled. The listener is shut down within metricsShutdownTimeout
// of ctx cancellation (restart-scoped disable — no SIGHUP hot-reload).
func StartMetricsServer(ctx context.Context, cfg *config.Config, reg metrics.Registry, b backend.Client) {
	if cfg == nil || !cfg.Observability.Metrics.Enabled {
		return
	}
	go func() {
		// BLOCKER 3 guard: a nil interface value would panic on b.IP(ctx).
		// This MUST be the first statement, before any method call on b
		// (CLAUDE.md: no panics in normal control flow).
		if b == nil {
			slog.Error("abysslinkd: metrics: no backend client; metrics listener disabled")
			return
		}

		addr, ok := resolveMetricsAddr(ctx, cfg, b)
		if !ok {
			// resolveMetricsAddr already logged the fail-closed reason. Never
			// fall back to a wildcard bind (OBS-03).
			return
		}

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			slog.Error("abysslinkd: metrics: listen", "addr", addr, "err", err)
			return
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", metricsHandler(reg))
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: readHeaderTO}

		go func() {
			if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
				slog.Error("abysslinkd: metrics: serve", "err", serveErr)
			}
		}()
		slog.Info("abysslinkd: metrics listening", "addr", addr)

		// Best-effort probe loop: seed the OBS-05 metrics immediately and refresh
		// them on every tick until shutdown.
		rigName := cfg.Tailnet.Hostname
		lockEnabled := cfg.Tailnet.Lock.Enabled
		updateOBS05 := func() {
			RegisterOBS05Metrics(reg, rigName, true, 0, 0, lockEnabled, time.Time{}, time.Now())
		}
		updateOBS05()

		ticker := time.NewTicker(metricsProbeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				updateOBS05()
			case <-ctx.Done():
				shutCtx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
				_ = srv.Shutdown(shutCtx)
				cancel()
				return
			}
		}
	}()
}

// resolveMetricsAddr determines the address the metrics listener binds, failing
// closed (ok == false) rather than ever binding a wildcard interface (OBS-03).
//
// Source-of-truth precedence:
//   - If observability.metrics.bind_addr is set, it is honored verbatim — but
//     only after rejecting unspecified hosts (0.0.0.0 / ::). A bind_addr that
//     carries its own port wins; a bare-host bind_addr is joined with the
//     configured/default port.
//   - Otherwise the tailnet IP from backend.Client.IP is used. An empty IP
//     (LocalClient.IP returns ("", nil) when the node has no Tailscale address)
//     or any unspecified/unparseable IP fails closed — never a wildcard bind.
func resolveMetricsAddr(ctx context.Context, cfg *config.Config, b backend.Client) (string, bool) {
	port := cfg.Observability.Metrics.Port
	if port <= 0 {
		port = defaultMetricsPort
	}

	if bindAddr := strings.TrimSpace(cfg.Observability.Metrics.BindAddr); bindAddr != "" {
		if config.IsUnspecifiedBindAddr(bindAddr) {
			slog.Error("abysslinkd: metrics: configured bind_addr is unspecified/wildcard; listener disabled (OBS-03)", "bind_addr", bindAddr)
			return "", false
		}
		// Honor an explicit host:port; otherwise treat bind_addr as a bare host
		// and apply the configured/default port.
		if _, _, err := net.SplitHostPort(bindAddr); err == nil {
			return bindAddr, true
		}
		host := strings.TrimSuffix(strings.TrimPrefix(bindAddr, "["), "]")
		return net.JoinHostPort(host, strconv.Itoa(port)), true
	}

	ip, err := b.IP(ctx)
	if err != nil {
		slog.Error("abysslinkd: metrics: resolve tailnet IP", "err", err)
		return "", false
	}
	if ip == "" {
		// Fail closed: an empty host would make net.Listen bind 0.0.0.0/:: (OBS-03).
		slog.Error("abysslinkd: metrics: empty tailnet IP; refusing wildcard bind, listener disabled")
		return "", false
	}
	// Defense in depth: reject any unspecified address that slipped through.
	if pa := net.ParseIP(ip); pa == nil || pa.IsUnspecified() {
		slog.Error("abysslinkd: metrics: non-tailnet/unspecified IP; listener disabled", "ip", ip)
		return "", false
	}
	return net.JoinHostPort(ip, strconv.Itoa(port)), true
}

// metricsHandler returns the GET /metrics HTTP handler. It sets the strict
// Prometheus content type and writes the registry snapshot in text-exposition
// format v0.0.4.
func metricsHandler(reg metrics.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", metricsContentType)
		writeMetrics(w, reg.Snapshot())
	}
}

// writeMetrics formats families as Prometheus text-exposition v0.0.4: a # HELP
// and # TYPE line per family, then one line per sample. Label values are escaped
// and label keys sorted for deterministic output. The body always ends in a
// trailing newline (per-sample writes guarantee it).
func writeMetrics(w io.Writer, families []metrics.MetricFamily) {
	for i := range families {
		fam := families[i]
		fmt.Fprintf(w, "# HELP %s %s\n", fam.Name, escapeHelp(fam.Help))
		fmt.Fprintf(w, "# TYPE %s %s\n", fam.Name, fam.Type)
		for _, s := range fam.Samples {
			if len(s.Labels) == 0 {
				fmt.Fprintf(w, "%s %g\n", fam.Name, s.Value)
				continue
			}
			fmt.Fprintf(w, "%s{%s} %g\n", fam.Name, formatLabels(s.Labels), s.Value)
		}
	}
}

// formatLabels renders a label map as a comma-separated key="value" list with
// keys sorted alphabetically and values escaped.
func formatLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(labels[k]))
		b.WriteByte('"')
	}
	return b.String()
}

// escapeLabelValue escapes a label value per the Prometheus text format: the
// three escapes are backslash, double-quote, and newline.
func escapeLabelValue(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeHelp escapes a HELP docstring per the Prometheus text format: only
// backslash and newline are escaped (double-quotes are literal in HELP lines).
func escapeHelp(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RegisterOBS05Metrics registers (or updates) the five OBS-05 named metrics in
// reg from current daemon/probe state. The rig label is always the opaque
// SHA-256 prefix (never the raw hostname). Counters are not used here — all five
// are gauges reflecting point-in-time posture.
func RegisterOBS05Metrics(
	reg metrics.Registry,
	rigName string,
	reachable bool,
	fatalCount, warnCount int,
	lockEnabled bool,
	certExpiry time.Time,
	lastSeen time.Time,
) {
	rig := metrics.OpaqueRigLabel(rigName)

	reg.Gauge("abysslink_rig_reachable",
		"1 if the rig is reachable via the tailnet, 0 otherwise",
		map[string]string{"rig": rig}).Set(boolToFloat(reachable))

	reg.Gauge("abysslink_doctor_findings",
		"count of doctor findings by severity",
		map[string]string{"severity": "fatal"}).Set(float64(fatalCount))
	reg.Gauge("abysslink_doctor_findings",
		"count of doctor findings by severity",
		map[string]string{"severity": "warn"}).Set(float64(warnCount))

	reg.Gauge("abysslink_lock_status",
		"1 if tailnet lock is enabled, 0 otherwise",
		nil).Set(boolToFloat(lockEnabled))

	certVal := 0.0
	if !certExpiry.IsZero() {
		certVal = time.Until(certExpiry).Seconds()
	}
	reg.Gauge("abysslink_cert_expiry_seconds",
		"seconds until TLS certificate expiry; negative if expired",
		nil).Set(certVal)

	lastSeenVal := 0.0
	if !lastSeen.IsZero() {
		lastSeenVal = float64(lastSeen.Unix())
	}
	reg.Gauge("abysslink_last_seen_timestamp",
		"unix timestamp of last successful daemon probe",
		map[string]string{"rig": rig}).Set(lastSeenVal)
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
