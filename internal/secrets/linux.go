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

//go:build linux

package secrets

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/abysslink/abysslink/internal/shell"
)

const (
	backendSecretTool = "secret-tool"
	backendPass       = "pass"
)

// LinuxStore implements KeychainStore using either libsecret (`secret-tool`)
// or `pass` (the standard Unix password manager), whichever is available.
// Detection happens at construction time via an in-process PATH lookup; the
// chosen backend is used for all subsequent operations.
type LinuxStore struct {
	runner  shell.Runner
	backend string // "secret-tool" or "pass"
}

// lookPath probes PATH for a binary. It is exec.LookPath (an in-process PATH
// scan — no subprocess is spawned, so the "all external commands go through
// shell.Runner" rule is not implicated) rather than shelling out to `which`,
// which is not guaranteed to exist on minimal distros (R2-I8). A variable so
// tests can stub backend availability.
var lookPath = exec.LookPath

// NewLinuxStore detects the available keychain backend and returns a LinuxStore.
// Returns an error if neither secret-tool nor pass is found on PATH.
func NewLinuxStore(_ context.Context, runner shell.Runner) (*LinuxStore, error) {
	for _, b := range []string{backendSecretTool, backendPass} {
		if _, err := lookPath(b); err == nil {
			return &LinuxStore{runner: runner, backend: b}, nil
		}
	}
	return nil, fmt.Errorf("secrets(linux): no keychain backend found: install libsecret-tools (secret-tool) or pass")
}

// Backend returns the selected backend name ("secret-tool" or "pass").
func (s *LinuxStore) Backend() string { return s.backend }

// Set stores the secret using the selected backend.
// The secret is delivered via stdin, never argv.
func (s *LinuxStore) Set(ctx context.Context, service, account, secret string) error {
	switch s.backend {
	case backendSecretTool:
		return s.secretToolSet(ctx, service, account, secret)
	case backendPass:
		return s.passSet(ctx, service, account, secret)
	default:
		return fmt.Errorf("secrets(linux): unknown backend %q", s.backend)
	}
}

// Get retrieves the secret using the selected backend.
func (s *LinuxStore) Get(ctx context.Context, service, account string) (string, error) {
	switch s.backend {
	case backendSecretTool:
		return s.secretToolGet(ctx, service, account)
	case backendPass:
		return s.passGet(ctx, service, account)
	default:
		return "", fmt.Errorf("secrets(linux): unknown backend %q", s.backend)
	}
}

// Delete removes the secret using the selected backend.
func (s *LinuxStore) Delete(ctx context.Context, service, account string) error {
	switch s.backend {
	case backendSecretTool:
		return s.secretToolDelete(ctx, service, account)
	case backendPass:
		return s.passDelete(ctx, service, account)
	default:
		return fmt.Errorf("secrets(linux): unknown backend %q", s.backend)
	}
}

// --- secret-tool backend ---

// secretToolSet stores via `secret-tool store`, piping the secret to stdin.
// secret-tool reads the password from stdin when given no -p flag.
func (s *LinuxStore) secretToolSet(ctx context.Context, service, account, secret string) error {
	res, err := s.runner.RunWithStdin(ctx, strings.NewReader(secret),
		"secret-tool", "store",
		"--label", service,
		"service", service,
		"account", account,
	)
	if err != nil {
		return fmt.Errorf("secrets(linux/secret-tool): store: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("secrets(linux/secret-tool): store exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

func (s *LinuxStore) secretToolGet(ctx context.Context, service, account string) (string, error) {
	res, err := s.runner.Run(ctx, "secret-tool", "lookup",
		"service", service,
		"account", account,
	)
	if err != nil {
		return "", fmt.Errorf("secrets(linux/secret-tool): lookup: %w", err)
	}
	// CORE-02: `secret-tool lookup` exits non-zero BOTH when the secret is
	// absent (silently — no stderr output) AND when the secret service is
	// unreachable (dbus down, collection locked — with a diagnostic on
	// stderr). Only the genuinely-empty, silent failure maps to ErrNotFound;
	// anything with stderr output is "keychain unavailable" so callers fail
	// closed instead of treating a transient hiccup as an absent secret.
	if res.ExitCode != 0 {
		if strings.TrimSpace(res.Stderr) == "" && strings.TrimSpace(res.Stdout) == "" {
			return "", fmt.Errorf("secrets(linux/secret-tool): %w (service=%s account=%s)", ErrNotFound, service, account)
		}
		return "", fmt.Errorf("secrets(linux/secret-tool): keychain unavailable: lookup exited %d (service=%s account=%s): %s",
			res.ExitCode, service, account, strings.TrimSpace(res.Stderr))
	}
	return strings.TrimRight(res.Stdout, "\n"), nil
}

func (s *LinuxStore) secretToolDelete(ctx context.Context, service, account string) error {
	res, err := s.runner.Run(ctx, "secret-tool", "clear",
		"service", service,
		"account", account,
	)
	if err != nil {
		return fmt.Errorf("secrets(linux/secret-tool): clear: %w", err)
	}
	// secret-tool clear exits 0 even when no entry exists — nothing to special-case.
	if res.ExitCode != 0 {
		return fmt.Errorf("secrets(linux/secret-tool): clear exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// --- pass backend ---

// passKey returns the pass store path for a service+account pair.
func passKey(service, account string) string {
	return service + "/" + account
}

// passSet stores via `pass insert -f`, piping the secret twice (value + confirm).
// pass insert reads from stdin when not in batch mode; providing two identical
// lines satisfies the confirmation prompt.
func (s *LinuxStore) passSet(ctx context.Context, service, account, secret string) error {
	// pass insert reads value + confirmation as two stdin lines, so a newline
	// inside the secret desyncs the confirmation and truncates the stored
	// value (same class as CORE-01 on darwin). The error never echoes the value.
	if strings.ContainsAny(secret, "\n\r") {
		return fmt.Errorf("secrets(linux/pass): secret contains a newline; refusing to compose pass insert stdin")
	}
	// pass insert -f (force, no TTY required) reads password + confirmation from stdin.
	stdin := secret + "\n" + secret + "\n"
	res, err := s.runner.RunWithStdin(ctx, strings.NewReader(stdin),
		"pass", "insert", "-f", passKey(service, account),
	)
	if err != nil {
		return fmt.Errorf("secrets(linux/pass): insert: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("secrets(linux/pass): insert exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

func (s *LinuxStore) passGet(ctx context.Context, service, account string) (string, error) {
	res, err := s.runner.Run(ctx, "pass", "show", passKey(service, account))
	if err != nil {
		return "", fmt.Errorf("secrets(linux/pass): show: %w", err)
	}
	// CORE-02: `pass show` prints "<name> is not in the password store." for a
	// genuinely missing entry; every other non-zero exit (gpg decryption
	// failure, missing store, locked agent) is a distinct "keychain
	// unavailable" error so callers can fail closed.
	if res.ExitCode != 0 {
		if strings.Contains(res.Stderr, "is not in the password store") {
			return "", fmt.Errorf("secrets(linux/pass): %w (service=%s account=%s)", ErrNotFound, service, account)
		}
		return "", fmt.Errorf("secrets(linux/pass): keychain unavailable: show exited %d (service=%s account=%s): %s",
			res.ExitCode, service, account, strings.TrimSpace(res.Stderr))
	}
	// pass show outputs the password on the first line, possibly followed by metadata.
	first := strings.SplitN(res.Stdout, "\n", 2)[0]
	return first, nil
}

func (s *LinuxStore) passDelete(ctx context.Context, service, account string) error {
	res, err := s.runner.Run(ctx, "pass", "rm", "-f", passKey(service, account))
	if err != nil {
		return fmt.Errorf("secrets(linux/pass): rm: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("secrets(linux/pass): rm exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}
