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

package secrets

import "context"

// KeychainStore persists and retrieves secrets without placing them on process argv.
// Implementations are platform-specific: DarwinStore uses the macOS Keychain via
// the `security` CLI, LinuxStore uses libsecret (secret-tool) or pass.
type KeychainStore interface {
	// Set stores the secret under the given service+account composite key.
	// The secret value is never placed on argv; implementations deliver it
	// via stdin or a platform keychain API.
	Set(ctx context.Context, service, account, secret string) error

	// Get retrieves the secret for the given service+account key.
	// Returns an error if the entry does not exist.
	Get(ctx context.Context, service, account string) (string, error)

	// Delete removes the secret for the given service+account key.
	// It is not an error to delete a key that does not exist.
	Delete(ctx context.Context, service, account string) error
}
