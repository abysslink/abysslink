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

// Package browser provides two URL-opening patterns: fire-and-forget (open URL
// via shell.Runner) and RFC 8252 loopback OAuth callback (127.0.0.1 +
// ephemeral port, PKCE, constant-time state validation, goroutine-leak-free
// shutdown).
//
// Security contracts:
//  1. The callback listener ALWAYS binds 127.0.0.1:0 — never 0.0.0.0.
//  2. State/nonce are compared with crypto/subtle.ConstantTimeCompare.
//  3. pkg/browser is NEVER imported here (it uses raw os/exec bypassing
//     shell.Runner — D-06 IMMUTABLE).
package browser
