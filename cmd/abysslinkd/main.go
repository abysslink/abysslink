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

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
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

	runner := &shell.ExecRunner{}

	cfg, err := config.Load(configPath())
	if err != nil {
		cfg = config.Defaults()
	}

	kc, kerr := secrets.NewStore(ctx, runner)
	if kerr != nil {
		slog.Warn("abysslinkd: keychain backend unavailable", "err", kerr)
		kc = nil
	}
	plat, perr := platformauto.New(runner)
	if perr != nil {
		slog.Error("abysslinkd: platform init failed", "err", perr)
		os.Exit(1)
	}

	nm := notify.New(notifymod.Deps{Cfg: cfg, Runner: runner, Keychain: kc, Platform: plat})
	srv := daemon.NewServer(directNotifier{m: nm}, runner, cfg)

	if err := srv.Run(ctx); err != nil {
		slog.Error("abysslinkd: exited with error", "err", err)
		os.Exit(1)
	}
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
