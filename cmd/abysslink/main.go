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
	// Prevent any subprocess (brew, git, etc.) from blocking on interactive
	// credential or password prompts. Abysslink is not a git client; a prompt
	// means the operation failed and should surface an error, not hang.
	_ = os.Setenv("GIT_TERMINAL_PROMPT", "0")
	// Prevent Homebrew from auto-updating all taps before each install, which
	// spawns git fetches against GitHub and can block on credentials above.
	_ = os.Setenv("HOMEBREW_NO_AUTO_UPDATE", "1")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	os.Exit(cli.Execute(ctx))
}
