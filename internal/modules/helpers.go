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

package modules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/abysslink/abysslink/internal/shell"
)

// TailnetIP returns this node's primary IPv4 tailnet address via `tailscale ip`.
func TailnetIP(ctx context.Context, runner shell.Runner) (string, error) {
	res, err := runner.Run(ctx, "tailscale", "ip", "--4")
	if err != nil {
		return "", fmt.Errorf("tailscale ip: %w", err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("tailscale ip exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	ip := strings.TrimSpace(res.Stdout)
	if ip == "" {
		return "", fmt.Errorf("tailscale ip returned no address")
	}
	return ip, nil
}

// GenPassword returns a cryptographically random 32-hex-character password.
func GenPassword() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return hex.EncodeToString(b), nil
}
