//go:build webui

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

package webui

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"tailscale.com/client/local"
)

// ErrAlreadyApplied is returned by Apply when the webui server is already
// running for this module instance.
var ErrAlreadyApplied = errors.New("webui: server already running")

// Module is the opt-in web-dashboard module. It satisfies modules.Module and is
// only ever compiled into a -tags webui build (WEB-01). The zero value is not
// usable; construct via New.
type Module struct {
	cfg *config.Config

	mu     sync.Mutex
	cancel context.CancelFunc // non-nil while the server goroutine is running

	// bind is the listener-factory seam. nil (production) resolves the tailnet
	// IP via the local tailscaled and TLS-listens on it; tests inject a stub so
	// Apply's synchronous bind error path is testable without a live tailscaled.
	bind func(ctx context.Context) (net.Listener, *local.Client, error)
}

// New constructs the webui Module from the shared module dependencies. Only the
// config is required; the listener wires its own Tailscale client at Apply time.
func New(d modules.Deps) *Module {
	return &Module{cfg: d.Cfg}
}

// Name returns the canonical module name used in YAML and logs.
func (m *Module) Name() string { return "webui" }

// Deps returns the modules this module depends on. The web UI needs Tailscale
// up (for WhoIs + GetCertificate), but it is wired by the daemon entrypoint
// rather than the apply graph, so no ordering dependency is declared here.
func (m *Module) Deps() []string { return nil }

// Detect reports findings about the current webui state. When the module is
// disabled (the default) it has nothing to report.
func (m *Module) Detect(ctx context.Context) ([]modules.Finding, error) {
	if !m.cfg.WebUI.Enabled {
		return nil, nil
	}
	return m.Verify(ctx)
}

// Plan computes the actions needed to reach the desired state. A disabled
// module plans nothing. dryRun is honored implicitly — Plan never mutates.
func (m *Module) Plan(_ context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.WebUI.Enabled {
		return nil, nil
	}
	return []modules.Action{{
		Module:      m.Name(),
		Description: "start the opt-in web dashboard (TLS + WhoIs + CSRF) over the tailnet",
		Reversible:  true,
	}}, nil
}

// Apply binds the web UI listener SYNCHRONOUSLY, then serves in a background
// goroutine bound to a cancellable context. Binding before returning means a
// bind/TLS failure (port in use, listen error, unresolvable tailnet IP) is
// returned as Apply's error instead of being lost as a goroutine log line —
// `abysslink up --apply` must not report a dashboard as started when it
// isn't (W9). It returns ErrAlreadyApplied if a server is already running for
// this instance. A disabled module is a no-op.
func (m *Module) Apply(ctx context.Context) error {
	if !m.cfg.WebUI.Enabled {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		return ErrAlreadyApplied
	}

	// Fail closed before binding: a non-Tailscale backend cannot provision the
	// MagicDNS certificate GetCertificate relies on (#2137).
	if f := m.tlsBackendFinding(); f != nil && f.Severity == modules.SeverityFatal {
		return errors.New(f.Message)
	}

	bind := m.bind
	if bind == nil {
		bind = m.bindProduction
	}

	srvCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	ln, lc, err := bind(srvCtx)
	if err != nil {
		cancel()
		return err
	}

	m.cancel = cancel
	go func() {
		// Only post-bind serve errors land here; bind errors were returned above.
		if err := serveWebUI(srvCtx, m.cfg, lc, ln, nil); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("webui: server exited", "err", err)
		}
	}()
	return nil
}

// bindProduction is the default listener factory: it resolves the tailnet IP
// from the platform tailscaled and TLS-listens on it (WEB-02/WEB-03).
func (m *Module) bindProduction(ctx context.Context) (net.Listener, *local.Client, error) {
	lc := &local.Client{} // zero value uses the platform-default tailscaled socket
	ln, err := bindWebUIListener(ctx, m.cfg, lc, localTailnetResolver{lc: lc})
	if err != nil {
		return nil, nil, err
	}
	return ln, lc, nil
}

// Stop terminates the background webui server started by Apply. Apply detaches
// the server goroutine from the caller's context (context.WithoutCancel), so
// without Stop nothing could ever cancel it (NET-20). Cancelling the stored
// context triggers the graceful shutdown path inside StartWebUIServer
// (ctx.Done → srv.Shutdown with a 5 s drain, then listener close).
//
// Stop is idempotent and safe to call when no server is running. Lifecycle
// owners (the daemon entrypoint in -tags webui builds) must call Stop on
// shutdown; after Stop returns, Apply may be called again to start a fresh
// server.
func (m *Module) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

// Verify runs the webui security posture checks. The load-bearing check in this
// plan is the TLS fail-closed probe (WEB-03): when the backend is not Tailscale,
// GetCertificate is unimplemented (Headscale/NetBird, #2137), so the dashboard
// must NOT bind — Verify emits a FATAL webui-tls finding and the listener is
// never created. A disabled module reports nothing.
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	if !m.cfg.WebUI.Enabled {
		return nil, nil
	}
	var findings []modules.Finding
	if f := m.tlsBackendFinding(); f != nil {
		findings = append(findings, *f)
	}
	return findings, nil
}

// Repair is a no-op for the web UI: there is nothing to auto-fix. A
// misconfigured backend (the only FATAL surfaced here) is a config decision the
// operator must make, not something Repair may silently change.
func (m *Module) Repair(_ context.Context) error { return nil }

// tlsBackendFinding returns the webui-tls finding for the configured backend, or
// nil when the module is disabled. A non-Tailscale backend yields a FATAL
// because GetCertificate cannot provision a cert there (#2137); Tailscale yields
// an OK at this layer (the eager cert probe lives at the daemon seam, Plan 04).
func (m *Module) tlsBackendFinding() *modules.Finding {
	const check = "webui-tls"
	if m.cfg.Backend.Type != "tailscale" {
		return &modules.Finding{
			Module:   m.Name(),
			Check:    check,
			Severity: modules.SeverityFatal,
			Message: "webui-tls: TLS is required but the configured backend " +
				m.cfg.Backend.Type + " cannot provision a Tailscale certificate — " +
				"the web UI is Tailscale-only and the listener will not bind (WEB-03, #2137)",
		}
	}
	return &modules.Finding{
		Module:   m.Name(),
		Check:    check,
		Severity: modules.SeverityOK,
		Message:  "webui-tls: backend is Tailscale; TLS cert provisioned via GetCertificate",
	}
}
