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

package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

// ntfyBaseURL is overridden in tests to point at httptest.Server.
var ntfyBaseURL = "" //nolint:gochecknoglobals // gochecknoglobals: package-level var is a test/injection seam for base URL override; intentional

// HealthProbe performs the ntfy reachability check used by Detect. It is a
// package-level seam so deterministic fixtures — notably the `up --dry-run`
// parity golden — do not depend on whether a live ntfy service happens to be
// listening on localhost (the probe is a real network dial that bypasses the
// injected shell.Runner). Returns nil when ntfy is reachable and healthy, a
// non-nil error otherwise. Overridden in tests; restore in cleanup.
var HealthProbe = defaultHealthProbe //nolint:gochecknoglobals // gochecknoglobals: package-level var is a test/injection seam for health-probe override; intentional

// defaultHealthProbe issues an HTTP GET against the ntfy health endpoint.
func defaultHealthProbe(ctx context.Context, url string) error {
	client := &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("notify detect: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ntfy health endpoint returned status %d", resp.StatusCode)
	}
	return nil
}

const (
	ntfyHealthPath = "/v1/health"
	ntfyMsgPath    = "/v1/message"
	httpTimeout    = 5 * time.Second

	keychainService = "abysslink"
	keychainAccount = "ntfy-password"
)

// Module implements the notify module.
type Module struct {
	runner   shell.Runner
	cfg      *config.Config
	keychain secrets.KeychainStore
	backend  backend.Client
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, keychain: d.Keychain, backend: d.Backend}
}

// baseURL resolves the ntfy base URL. Resolution order:
//  1. the test-override seam (ntfyBaseURL),
//  2. the backend-resolved tailnet IP + configured port (NET-02: ntfy binds the
//     tailnet IP only — native listen-http tailnetIP:port, docker
//     -p tailnetIP:port:80 — so localhost POSTs fail under the documented
//     secure binding),
//  3. localhost + configured port, ONLY as a last resort when no tailnet IP is
//     resolvable (backend down / not yet authenticated / nil in unit tests).
func (m *Module) baseURL(ctx context.Context) string {
	if ntfyBaseURL != "" {
		return ntfyBaseURL
	}
	port := 2586
	if m.cfg != nil {
		port = m.cfg.Modules.Ntfy.ListenPort()
	}
	if ip := m.tailnetIP(ctx); ip != "" {
		return fmt.Sprintf("http://%s:%d", ip, port)
	}
	return fmt.Sprintf("http://localhost:%d", port)
}

// tailnetIP best-effort resolves this node's tailnet IP from the backend — the
// same authoritative source the ntfy module uses to derive its bind address.
// Returns "" when the backend is unavailable; the caller then falls back to
// localhost (probe will fail honestly rather than panic).
func (m *Module) tailnetIP(ctx context.Context) string {
	if m.backend == nil {
		return ""
	}
	ip, err := m.backend.IP(ctx)
	if err != nil {
		return ""
	}
	return ip
}

// Name returns the module name.
func (m *Module) Name() string { return "notify" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"ntfy"} }

// Detect checks whether the ntfy backend is configured and running.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.cfg.Modules.Notify.Enabled {
		slog.Debug("notify module disabled, skipping detect")
		return nil, nil
	}

	// Probe the ntfy health endpoint via the HealthProbe seam. Context is passed
	// so the request is cancelled if the parent context times out or is cancelled.
	base := m.baseURL(ctx)
	if err := HealthProbe(ctx, base+ntfyHealthPath); err != nil {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ntfy_running",
			Severity: modules.SeverityWarning,
			Message:  fmt.Sprintf("ntfy service is not reachable at %s", base),
		})
		return findings, nil
	}

	slog.Debug("ntfy health check passed")
	return findings, nil
}

// Plan computes actions needed.
func (m *Module) Plan(ctx context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Notify.Enabled {
		return nil, nil
	}

	findings, err := m.Detect(ctx)
	if err != nil {
		return nil, err
	}

	var actions []modules.Action
	for _, f := range findings {
		if f.Check == "ntfy_running" {
			actions = append(actions, modules.Action{
				Module:      m.Name(),
				Description: "start ntfy service",
				Reversible:  false,
			})
		}
	}

	return actions, nil
}

// Apply starts the ntfy service via the OS-appropriate service manager.
func (m *Module) Apply(ctx context.Context) error {
	switch runtime.GOOS {
	case "darwin":
		res, err := m.runner.Run(ctx, "launchctl", "start", "dev.abysslink.ntfy")
		if err == nil && res.ExitCode == 0 {
			slog.Info("notify apply: started ntfy via launchctl")
			return nil
		} else if err != nil {
			slog.Warn("notify apply: launchctl start failed (ntfy server not supported on macOS)", "err", err)
			return nil
		}
		slog.Warn("notify apply: launchctl start ntfy skipped (ntfy server not supported on macOS)",
			"exit", res.ExitCode, "stderr", strings.TrimSpace(res.Stderr))
		return nil
	default: // linux
		res, err := m.runner.Run(ctx, "systemctl", "--user", "start", "ntfy")
		if err == nil && res.ExitCode == 0 {
			slog.Info("notify apply: started ntfy via systemctl")
			return nil
		} else if err != nil {
			return fmt.Errorf("notify apply: systemctl start ntfy: %w", err)
		}
		return fmt.Errorf("notify apply: systemctl start ntfy exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
}

// Verify sends a test HTTP request to ntfy health endpoint.
func (m *Module) Verify(ctx context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.cfg.Modules.Notify.Enabled {
		return nil, nil
	}

	client := &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.baseURL(ctx)+ntfyHealthPath, nil)
	if err != nil {
		return findings, fmt.Errorf("notify verify: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		sev := modules.SeverityFatal
		if runtime.GOOS == "darwin" {
			sev = modules.SeverityWarning
		}
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ntfy_health",
			Severity: sev,
			Message:  fmt.Sprintf("ntfy health check failed: %v", err),
		})
		return findings, nil
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup

	if resp.StatusCode != http.StatusOK {
		sev := modules.SeverityFatal
		if runtime.GOOS == "darwin" {
			sev = modules.SeverityWarning
		}
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ntfy_health",
			Severity: sev,
			Message:  fmt.Sprintf("ntfy health endpoint returned HTTP %d", resp.StatusCode),
		})
	}

	return findings, nil
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}

// SendOptions carries optional per-message ntfy delivery parameters (CLI-04).
// The zero value means "no overrides" — identical behavior to the historical
// two-argument Send.
type SendOptions struct {
	// Priority maps to the ntfy X-Priority header: 1-5 or the aliases
	// min|low|default|high|max|urgent. Empty = omit the header (server default).
	Priority string
	// Tags maps to the ntfy X-Tags header (comma-separated). Empty = omit.
	Tags string
	// Topic overrides the config default_topic (URL path segment). Empty =
	// use the configured default.
	Topic string
	// Click maps to the ntfy X-Click header; opens the URL on tap; empty =
	// omit the header (D-16: the dispatcher composes an ssh:// deep link).
	Click string
}

// validTopicRe constrains a topic override to the ntfy topic charset so a
// hostile value can never alter the request path ("../", query strings, etc.).
var validTopicRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Send sends a notification via the configured ntfy backend.
// It tries the abysslinkd Unix socket first (fast path, no process startup),
// then falls back to a direct ntfy POST when the daemon is not running.
func (m *Module) Send(ctx context.Context, title, body string) error {
	return m.SendWithOptions(ctx, title, body, SendOptions{})
}

// SendWithOptions is Send with per-message delivery options (CLI-04).
// When opts is the zero value the behavior is byte-identical to Send.
func (m *Module) SendWithOptions(ctx context.Context, title, body string, opts SendOptions) error {
	if !m.cfg.Modules.Notify.Enabled {
		slog.Debug("notify.Send: module disabled, skipping")
		return nil
	}

	// Fast path: hand off to a running abysslinkd over its Unix socket — but
	// only when no per-message options are set. The daemon's delivery backend
	// carries title+body only, so routing an option-bearing message through it
	// would silently drop priority/tags/topic (the CLI-04 bug, relocated).
	if opts == (SendOptions{}) {
		if err := daemon.NewClient().Send(ctx, daemon.NotifyRequest{
			Title: title,
			Body:  body,
			Topic: m.cfg.Modules.Notify.DefaultTopic,
		}); err == nil {
			slog.Debug("notify.Send: delivered via abysslinkd socket")
			return nil
		}
	}

	// Fall back to direct ntfy POST (always used when options are present).
	return m.SendDirectWithOptions(ctx, title, body, opts)
}

// SendDirect sends a notification directly to the ntfy HTTP API, bypassing the
// daemon socket. The daemon itself uses this as its delivery backend (calling
// the socket-aware Send from inside the daemon would loop).
func (m *Module) SendDirect(ctx context.Context, title, body string) error {
	return m.SendDirectWithOptions(ctx, title, body, SendOptions{})
}

// SendDirectWithOptions is SendDirect with per-message delivery options
// (priority, tags, topic override — CLI-04). ntfy semantics: X-Priority and
// X-Tags headers; the topic is the URL path segment.
func (m *Module) SendDirectWithOptions(ctx context.Context, title, body string, opts SendOptions) error {
	topic := opts.Topic
	if topic == "" {
		topic = m.cfg.Modules.Notify.DefaultTopic
	}
	if topic == "" {
		topic = "rig"
	}
	if !validTopicRe.MatchString(topic) {
		return fmt.Errorf("notify send: invalid topic %q: only [A-Za-z0-9_-] (max 64 chars) allowed", topic)
	}

	url := fmt.Sprintf("%s/%s", m.baseURL(ctx), topic)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify send: create request: %w", err)
	}
	req.Header.Set("X-Title", title)
	req.Header.Set("Content-Type", "text/plain")
	if opts.Priority != "" {
		req.Header.Set("X-Priority", opts.Priority)
	}
	if opts.Tags != "" {
		req.Header.Set("X-Tags", opts.Tags)
	}
	if opts.Click != "" {
		req.Header.Set("X-Click", opts.Click)
	}

	// Attach basic auth from keychain if credentials are configured.
	if m.keychain != nil {
		password, kerr := m.keychain.Get(ctx, keychainService, keychainAccount)
		switch {
		case kerr == nil && password != "":
			req.SetBasicAuth("admin", password)
		case kerr != nil && !errors.Is(kerr, secrets.ErrNotFound):
			// A genuine keychain failure (locked, backend error) is worth a log
			// line; absence of credentials is the normal unauthenticated path.
			slog.Warn("notify send: keychain read failed; sending without auth", "err", kerr)
		}
	}

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify send: POST to ntfy: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notify send: ntfy returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	slog.Info("notification sent", "title", title, "topic", topic)
	return nil
}
