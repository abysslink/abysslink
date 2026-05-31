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

package backend

import (
	"fmt"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
)

// New resolves the backend adapter from cfg.Backend.Type and returns a Client.
// Unknown types return a non-nil error — the factory fails closed (T-11-04).
// config imports backend one-way: config does NOT import backend (Pitfall 2).
func New(cfg *config.Config, runner shell.Runner) (Client, error) {
	switch cfg.Backend.Type {
	case "tailscale", "":
		// "" is a defensive fallback; config.Load normalizes tailnet:→"tailscale".
		return newTailscaleAdapter(cfg, runner), nil
	default:
		return nil, fmt.Errorf("backend: unknown type %q", cfg.Backend.Type)
	}
}
