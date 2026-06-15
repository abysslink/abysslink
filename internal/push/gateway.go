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

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/abysslink/abysslink/internal/notifyv2"
)

// Push platform identifiers (the gateway-map keys and OutboxEntry.Platform
// values). Exported so the daemon fan-out path and the device-store adapter
// carry the real platform from one named constant rather than scattered string
// literals (WR-03). The current enrollment schema mints only PlatformUnifiedPush
// tokens; PlatformAPNs/PlatformFCM exist for the v5 receiver legs.
const (
	PlatformUnifiedPush = "unifiedpush"
	PlatformAPNs        = "apns"
	PlatformFCM         = "fcm"
)

// Wake is the unit of work the Gateway dispatches to a provider.
// It carries routing metadata only — never body content (D-17 / opaque-wake invariant).
// The ProviderToken field is secret-class: it must never appear in logs, audit
// entries, or any observable surface.
type Wake struct {
	// DeviceID is the routing key identifying the enrolled device.
	// Used as the bbolt outbox key prefix (D-09). Never logged directly.
	DeviceID string
	// Platform identifies the delivery leg: "apns" | "fcm" | "unifiedpush".
	Platform string
	// ProviderToken is the raw provider token (APNs device token hex, FCM
	// registration token, or UnifiedPush endpoint URL). Secret-class: never log.
	ProviderToken string
	// Msg is the v2 notification message (routing metadata only).
	Msg notifyv2.Message
	// CollapseID is the pre-computed hash(session_id‖kind) per D-13.
	CollapseID string
}

// Gateway dispatches a Wake to one provider leg.
// Implementations: APNsGateway, FCMGateway, UnifiedPushGateway.
// Send returns ErrDeadToken when the provider confirms the device token is
// permanently unregistered; callers must prune the token from the enrollment
// store and drop queued outbox entries.
type Gateway interface {
	Send(ctx context.Context, w Wake) error
}

// ErrDeadToken is returned by a Gateway when the provider confirms the
// device token is permanently unregistered (APNs HTTP/2 status 410 /
// FCM error status UNREGISTERED). The caller must prune the token from
// the enrollment store and drop queued outbox entries (D-12).
var ErrDeadToken = errors.New("push: dead token — device unregistered")

// CollapseID returns the provider collapse-id for a wake (D-13).
//
// Collapse policy:
//   - approval_request always gets a unique collapse-id (the msg_id ULID) so
//     concurrent approvals never merge into one notification (D-13 / D-09).
//   - All other kinds: hex(sha256(session_id ‖ 0x00 ‖ kind)[:16]) — 32 hex
//     chars, deterministic per (session, kind), within APNs 64-byte limit.
func CollapseID(msgID, sessionID string, kind notifyv2.Kind) string {
	if kind == notifyv2.KindApprovalRequest {
		// ULID is globally unique; approval_request never collapses (D-13).
		return msgID
	}
	// hash(session_id ‖ \x00 ‖ kind) truncated to 16 bytes = 32 hex chars.
	// The \x00 separator prevents collisions between session IDs that are
	// prefixes of each other + different kind strings.
	h := sha256.Sum256([]byte(sessionID + "\x00" + string(kind)))
	return hex.EncodeToString(h[:16]) // 32 hex chars — within APNs 64-byte limit
}
