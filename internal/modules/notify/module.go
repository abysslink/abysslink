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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
)

const (
	ntfyBaseURL    = "http://localhost:8080"
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
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg, keychain: d.Keychain}
}

// Name returns the module name.
func (m *Module) Name() string { return "notify" }

// Deps returns the module's dependencies.
func (m *Module) Deps() []string { return []string{"ntfy"} }

// Detect checks whether the ntfy backend is configured and running.
func (m *Module) Detect(_ context.Context) ([]modules.Finding, error) {
	var findings []modules.Finding

	if !m.cfg.Modules.Notify.Enabled {
		slog.Debug("notify module disabled, skipping detect")
		return nil, nil
	}

	// Try an HTTP GET to ntfy health endpoint.
	client := &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
	}
	resp, err := client.Get(ntfyBaseURL + ntfyHealthPath) //nolint:noctx
	if err != nil || resp.StatusCode != http.StatusOK {
		msg := "ntfy service is not reachable at localhost:8080"
		if err != nil {
			msg = fmt.Sprintf("ntfy service unreachable: %v", err)
		}
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ntfy_running",
			Severity: modules.SeverityWarning,
			Message:  msg,
		})
		if resp != nil {
			_ = resp.Body.Close()
		}
		return findings, nil
	}
	defer resp.Body.Close() //nolint:errcheck

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

// Apply starts the ntfy service via the platform service manager.
func (m *Module) Apply(ctx context.Context) error {
	// Attempt to start ntfy via platform service manager.
	// Try launchd first (macOS), then systemd (Linux).
	res, err := m.runner.Run(ctx, "launchctl", "start", "sh.ntfy.ntfyd")
	if err == nil && res.ExitCode == 0 {
		slog.Info("notify apply: started ntfy via launchctl")
		return nil
	}

	res, err = m.runner.Run(ctx, "systemctl", "--user", "start", "ntfy")
	if err == nil && res.ExitCode == 0 {
		slog.Info("notify apply: started ntfy via systemctl")
		return nil
	}

	return fmt.Errorf("notify module: could not start ntfy service via launchd or systemd")
}

// Verify sends a test HTTP request to ntfy health endpoint.
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
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
	resp, err := client.Get(ntfyBaseURL + ntfyHealthPath) //nolint:noctx
	if err != nil {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ntfy_health",
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("ntfy health check failed: %v", err),
		})
		return findings, nil
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "ntfy_health",
			Severity: modules.SeverityFatal,
			Message:  fmt.Sprintf("ntfy health endpoint returned HTTP %d", resp.StatusCode),
		})
	}

	return findings, nil
}

// Repair attempts to fix findings.
func (m *Module) Repair(ctx context.Context) error {
	return m.Apply(ctx)
}

// Send sends a notification via the configured ntfy backend.
// It tries the abysslinkd Unix socket first, then falls back to direct ntfy POST.
func (m *Module) Send(ctx context.Context, title, body string) error {
	if !m.cfg.Modules.Notify.Enabled {
		slog.Debug("notify.Send: module disabled, skipping")
		return nil
	}

	// Fall back to direct ntfy POST.
	return m.sendDirect(ctx, title, body)
}

// sendDirect sends a notification directly to the ntfy HTTP API.
func (m *Module) sendDirect(ctx context.Context, title, body string) error {
	topic := m.cfg.Modules.Notify.DefaultTopic
	if topic == "" {
		topic = "rig"
	}

	url := fmt.Sprintf("%s/%s", ntfyBaseURL, topic)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify send: create request: %w", err)
	}
	req.Header.Set("X-Title", title)
	req.Header.Set("Content-Type", "text/plain")

	// Attach basic auth from keychain if credentials are configured.
	if m.keychain != nil {
		password, err := m.keychain.Get(ctx, keychainService, keychainAccount)
		if err == nil && password != "" {
			req.SetBasicAuth("abysslink", password)
		}
		// If credentials are not found, proceed without auth.
	}

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify send: POST to ntfy: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notify send: ntfy returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	slog.Info("notification sent", "title", title, "topic", topic)
	return nil
}
