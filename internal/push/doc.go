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

// Package push implements the platform-dispatching push Gateway and the
// persistent bbolt outbox.
//
// Audit-mutation exemption (D-06, Phase 29): the push outbox database
// (push_outbox.db) is daemon runtime state — a binary bbolt file tracking
// retry backoff, duplicate suppression, and per-device wake ceilings. It is
// NOT a file mutation subject to the internal/audit trail. The bbolt handle
// is opened at the daemon composition root (cmd/abysslinkd/main.go) and
// passed into this package — never via internal/audit. This is the same
// structural exemption shape as Phase 27 D-40 (ungated-runner bypass for
// daemon-internal plumbing), documented here so the architecture is visible
// at the package boundary.
//
// Provider tokens (device tokens) are a secret-class value. They MUST NOT
// appear in slog output, audit log entries, or any observable surface (D-17).
package push
