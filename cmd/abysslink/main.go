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

// Command abysslink is the Abysslink CLI — automates a paranoid-by-default
// phone-to-laptop remote-control setup over Tailscale.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/abysslink/abysslink/internal/cli"
)

func main() {
	// Prevent git/brew from blocking on credential prompts. Layered defences:
	//
	//   GIT_TERMINAL_PROMPT=0        — git won't prompt on the terminal
	//   GIT_ASKPASS=/usr/bin/false   — askpass helper fails immediately
	//   GIT_CONFIG_COUNT/KEY_0/VALUE_0 — inject credential.helper= (empty) via
	//     git's env-based config interface (git 2.32+). An empty value CLEARS the
	//     credential helper list, so helpers like `gh auth git-credential` or
	//     osxkeychain are never invoked. Without this, `gh` or other helpers write
	//     their own terminal prompts that bypass GIT_TERMINAL_PROMPT entirely.
	//   HOMEBREW_NO_AUTO_UPDATE=1    — suppress brew's pre-install git tap refresh
	//   HOMEBREW_NO_INSTALL_UPGRADE=1 — suppress upgrade checks that also hit git
	_ = os.Setenv("GIT_TERMINAL_PROMPT", "0")
	_ = os.Setenv("GIT_ASKPASS", "/usr/bin/false")
	_ = os.Setenv("GIT_CONFIG_COUNT", "1")
	_ = os.Setenv("GIT_CONFIG_KEY_0", "credential.helper")
	_ = os.Setenv("GIT_CONFIG_VALUE_0", "")
	_ = os.Setenv("HOMEBREW_NO_AUTO_UPDATE", "1")
	_ = os.Setenv("HOMEBREW_NO_INSTALL_UPGRADE", "1")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	os.Exit(cli.Execute(ctx))
}
