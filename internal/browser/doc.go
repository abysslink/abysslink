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

// Package browser provides two browser-interaction patterns for abysslink:
//
//  1. Fire-and-forget URL opening: OpenURL routes through shell.Runner so
//     browser launch is testable without spawning a real browser. On headless
//     terminals the URL is printed instead (D-06, D-07, D-08 IMMUTABLE).
//
//  2. RFC 8252 loopback OAuth callback: ListenCallback starts an HTTP server on
//     127.0.0.1 with an ephemeral random free port, validates the OAuth state
//     parameter (constant-time compare) and PKCE code_verifier (S256), then
//     shuts the server down after receiving one callback or on context
//     cancellation (BRWS-02, D-03, D-05 IMMUTABLE).
//
// Implemented in Wave 3 of Phase 35. Wave 0 test stubs in browser_test.go
// define the contract that Wave 3 must satisfy.
package browser
