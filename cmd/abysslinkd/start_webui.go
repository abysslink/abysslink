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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/modules/webui"
)

// webuiNoteOnce guards the loud one-time security note so it prints exactly once
// per daemon lifetime regardless of how many times startWebUI is invoked.
var webuiNoteOnce sync.Once

// ringAdapter adapts *webui.NotifyRingBuffer to daemon.RingAdder. The daemon
// package cannot import webui (build-tag mismatch) and the ring's Add takes a
// webui.NotifyEvent, so this thin adapter bridges the two at the entrypoint —
// keeping the daemon package free of webui/SDK imports (T-19-08).
type ringAdapter struct{ ring *webui.NotifyRingBuffer }

func (a ringAdapter) AddEvent(title, topic, priority string, t time.Time) {
	a.ring.Add(webui.NotifyEvent{Time: t, Title: title, Topic: topic, Priority: priority})
}

// startWebUI launches the opt-in browser dashboard when webui.enabled is true.
// This is the //go:build webui implementation; the !webui build links the no-op
// stub in start_webui_stub.go.
//
// It prints the loud one-time security note to os.Stderr (acceptable here: this
// is the daemon entrypoint, not library code — CLAUDE.md restricts stdout/stderr
// to entrypoints/the Printer abstraction, and StartWebUIServer in the webui
// package itself emits only slog, T-19-22). The note prints exactly once via
// webuiNoteOnce. The webui server runs in a goroutine so a startup error never
// blocks the daemon's notify socket.
func startWebUI(ctx context.Context, cfg *config.Config, srv *daemon.Server, _ string) {
	if cfg == nil || !cfg.WebUI.Enabled {
		return
	}

	ring := webui.NewNotifyRingBuffer()
	srv.SetRing(ringAdapter{ring: ring})

	port := cfg.WebUI.Port
	if port <= 0 {
		port = 8443
	}
	webuiNoteOnce.Do(func() {
		hostname := cfg.Tailnet.Hostname
		if hostname == "" {
			hostname = "this-rig"
		}
		// The listener address is resolved to the tailnet IP inside
		// StartWebUIServer (WEB-02), so this entrypoint does not yet know the
		// concrete IP. Describe the binding rather than interpolating the raw
		// (often empty) bind_addr config field, which previously printed a
		// misleading trailing-blank "Bound to tailnet IP " (IN-01).
		bindDesc := "the tailnet IP only"
		if cfg.WebUI.BindAddr != "" {
			bindDesc = cfg.WebUI.BindAddr
		}
		fmt.Fprintf(os.Stderr,
			"ABYSSLINK WEB UI: enabled. Accessible at https://%s:%d/ over tailnet only. "+
				"Bound to %s. Read-only. Auth: Tailscale WhoIs. TLS: Tailscale cert. "+
				"This service is NOT accessible from the internet.\n",
			hostname, port, bindDesc)
	})

	go func() {
		if err := webui.StartWebUIServer(ctx, cfg, ring); err != nil && ctx.Err() == nil {
			slog.Error("abysslinkd: webui server exited with error", "err", err)
		}
	}()
}
