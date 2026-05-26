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

package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/abysslink/abysslink/internal/shell"
)

// LockClient shells out to `tailscale lock` for Tailnet Lock operations.
// Tailnet Lock is CLI-only (no LocalAPI or HTTP API access).
type LockClient struct {
	runner shell.Runner
}

// NewLockClient returns a LockClient using the given shell runner.
func NewLockClient(runner shell.Runner) *LockClient {
	return &LockClient{runner: runner}
}

// Status returns the current Tailnet Lock status.
func (l *LockClient) Status(ctx context.Context) (*LockStatus, error) {
	res, err := l.runner.Run(ctx, "tailscale", "lock", "status", "--json")
	if err != nil {
		return nil, fmt.Errorf("tailscale lock status: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("tailscale lock status exited %d: %s", res.ExitCode, res.Stderr)
	}

	var ls LockStatus
	if err := json.Unmarshal([]byte(res.Stdout), &ls); err != nil {
		return nil, fmt.Errorf("tailscale lock status: parse JSON: %w", err)
	}
	return &ls, nil
}

// Init initializes Tailnet Lock. Captures disablement secrets from stdout.
// Secrets are returned in LockInitResult and never written to disk.
//
// disablementSecrets is the number of disablement secrets to generate (2–5 recommended).
// shareWithSupport adds --gen-disablement-for-support when true.
func (l *LockClient) Init(ctx context.Context, disablementSecrets int, shareWithSupport bool) (*LockInitResult, error) {
	args := []string{"lock", "init"}
	if disablementSecrets > 0 {
		args = append(args, "--gen-disablement="+strconv.Itoa(disablementSecrets))
	}
	if shareWithSupport {
		args = append(args, "--gen-disablement-for-support")
	}

	res, err := l.runner.Run(ctx, "tailscale", args...)
	if err != nil {
		return nil, fmt.Errorf("tailscale lock init: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("tailscale lock init exited %d: %s", res.ExitCode, res.Stderr)
	}

	result := &LockInitResult{}
	// Parse disablement secrets from output lines like:
	//   Disablement secret 1: tlsdis:xxxx
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disablement secret") {
			// Extract the secret value after the colon.
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				secret := strings.TrimSpace(parts[1])
				if secret != "" {
					result.DisablementSecrets = append(result.DisablementSecrets, secret)
				}
			}
		}
		// Also capture trusted key lines if present.
		if strings.HasPrefix(line, "Trusted key:") || strings.HasPrefix(line, "New trusted key:") {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[1])
				if key != "" {
					result.TrustedKeys = append(result.TrustedKeys, key)
				}
			}
		}
	}

	return result, nil
}

// Sign signs a node key into the lock.
func (l *LockClient) Sign(ctx context.Context, key string) error {
	res, err := l.runner.Run(ctx, "tailscale", "lock", "sign", key)
	if err != nil {
		return fmt.Errorf("tailscale lock sign: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("tailscale lock sign exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}
