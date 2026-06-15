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

package push

import "sync/atomic"

// GatewayCounters holds the six gateway metrics exposed on GET /status (D-19).
// All fields are atomic.Int64 (value type — not pointer) for goroutine-safe
// increment / load without mutex overhead. The zero value is ready for use.
//
// Counter semantics:
//   - Queued: outbox entries enqueued by the dispatch fan-out.
//   - Sent: Send calls issued by the retry goroutine (attempted deliveries).
//   - ProviderAccepted: provider returned nil (HTTP 2xx / APNS OK).
//   - PrunedTokens: dead-token entries removed (ErrDeadToken — D-12).
//   - CeilingDropped: dispatches skipped by the per-device ceiling (D-05).
//   - BackoffPending: transient errors that scheduled a retry (D-08).
//
// No device token, bearer, or push credential is ever stored here (D-17 / T-29-04-4).
type GatewayCounters struct {
	Queued           atomic.Int64
	Sent             atomic.Int64
	ProviderAccepted atomic.Int64
	PrunedTokens     atomic.Int64
	CeilingDropped   atomic.Int64
	BackoffPending   atomic.Int64
}
