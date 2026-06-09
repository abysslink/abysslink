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

//go:build darwin

package secrets

import (
	"context"
	"fmt"
	"strings"

	"github.com/abysslink/abysslink/internal/shell"
)

// DarwinStore implements KeychainStore using the macOS `security` CLI.
//
// Secrets are stored in the user's login keychain as generic passwords.
// The secret value is NEVER placed on argv; Set uses `security -i` interactive
// mode, piping the add-generic-password command over stdin so the value stays
// in the pipe — invisible to process-listing tools like `ps`.
type DarwinStore struct {
	runner shell.Runner
}

// NewDarwinStore returns a DarwinStore backed by the given Runner.
// Use shell.ExecRunner{} in production.
func NewDarwinStore(runner shell.Runner) *DarwinStore {
	return &DarwinStore{runner: runner}
}

// Set stores the secret in the macOS Keychain under service+account.
// It uses `security -i` interactive mode so the secret never appears on argv.
// The -U flag updates an existing entry if one is already present.
func (s *DarwinStore) Set(ctx context.Context, service, account, secret string) error {
	// CORE-01: `security -i` is a LINE-oriented command parser. shellQuote
	// escapes backslashes and double quotes but cannot neutralise control
	// characters — an embedded "\n" would terminate the add-generic-password
	// line early (truncating the stored secret) and inject a second keychain
	// command from attacker-influenced input. Reject all control bytes in
	// every field before composing the command line.
	if err := rejectControlChars("service", service); err != nil {
		return err
	}
	if err := rejectControlChars("account", account); err != nil {
		return err
	}
	if err := rejectControlChars("secret", secret); err != nil {
		return err
	}

	// security -i reads security commands from stdin, one per line.
	// The format mirrors the CLI subcommand syntax exactly.
	// We quote each argument with %q to handle spaces; security -i parses
	// double-quoted tokens, so Go's %q (which produces valid Go/JSON string
	// literals compatible with shell double-quote rules) is safe here.
	cmd := fmt.Sprintf("add-generic-password -U -a %s -s %s -w %s\n",
		shellQuote(account), shellQuote(service), shellQuote(secret))

	res, err := s.runner.RunWithStdin(ctx, strings.NewReader(cmd), "security", "-i")
	if err != nil {
		return fmt.Errorf("secrets(darwin): security -i: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("secrets(darwin): security -i exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// errSecItemNotFound is the `security` CLI exit code for errSecItemNotFound
// (-25300): the queried item does not exist in any searched keychain.
const errSecItemNotFound = 44

// Get retrieves the secret for service+account from the macOS Keychain.
// `security find-generic-password -w` prints only the password to stdout;
// no secret appears on argv.
//
// CORE-02: only exit code 44 (errSecItemNotFound) maps to ErrNotFound. Every
// other non-zero exit (keychain locked, access denied, user cancelled the
// prompt, ...) is a distinct "keychain unavailable" error so callers can fail
// closed instead of treating a transient keychain hiccup as an absent secret.
func (s *DarwinStore) Get(ctx context.Context, service, account string) (string, error) {
	res, err := s.runner.Run(ctx, "security",
		"find-generic-password",
		"-a", account,
		"-s", service,
		"-w",
	)
	if err != nil {
		return "", fmt.Errorf("secrets(darwin): security find-generic-password: %w", err)
	}
	if res.ExitCode == errSecItemNotFound {
		return "", fmt.Errorf("secrets(darwin): %w (service=%s account=%s)", ErrNotFound, service, account)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("secrets(darwin): keychain unavailable: security find-generic-password exited %d (service=%s account=%s): %s",
			res.ExitCode, service, account, strings.TrimSpace(res.Stderr))
	}
	return strings.TrimRight(res.Stdout, "\n"), nil
}

// Delete removes the keychain entry for service+account.
// No secret is involved in this operation.
func (s *DarwinStore) Delete(ctx context.Context, service, account string) error {
	res, err := s.runner.Run(ctx, "security",
		"delete-generic-password",
		"-a", account,
		"-s", service,
	)
	if err != nil {
		return fmt.Errorf("secrets(darwin): security delete-generic-password: %w", err)
	}
	// exit 44 means "item not found" — treat as success (idempotent delete)
	if res.ExitCode != 0 && res.ExitCode != 44 {
		return fmt.Errorf("secrets(darwin): delete exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// shellQuote wraps s in double quotes and escapes backslashes and double quotes
// within. This is sufficient for the security -i command parser which uses
// standard POSIX-style double-quote rules — PROVIDED the input contains no
// control characters. shellQuote cannot escape a newline for the line-oriented
// security -i parser; callers must run rejectControlChars first (CORE-01).
func shellQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// rejectControlChars returns an error when value contains any control byte
// (< 0x20) or DEL (0x7F). The security -i parser is line-oriented, so a "\n"
// (or "\r") cannot be escaped — it would split the composed command into two
// keychain commands and truncate the stored value (CORE-01). The remaining
// control characters have no legitimate use in service names, account names,
// or secrets, so they are rejected wholesale rather than enumerated.
// The error never echoes the offending value (it may be a secret).
func rejectControlChars(field, value string) error {
	for _, r := range value {
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("secrets(darwin): %s contains a control character (U+%04X); refusing to compose security -i command", field, r)
		}
	}
	return nil
}
