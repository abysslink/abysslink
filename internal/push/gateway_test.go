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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/abysslink/abysslink/internal/notifyv2"
)

// TestCollapseID verifies the D-13 collapse-id policy:
//   - approval_request always returns the msgID unchanged (never collapses)
//   - same session+kind always returns the same 32-hex string
//   - two different kinds for the same session return different collapse IDs
func TestCollapseID(t *testing.T) {
	t.Run("approval_request returns msgID unchanged", func(t *testing.T) {
		msgID := "01J7G3QNS5BWT0GNSAB02HAQ4X"
		sessionID := "session-abc"
		got := CollapseID(msgID, sessionID, notifyv2.KindApprovalRequest)
		assert.Equal(t, msgID, got, "approval_request collapse-id must equal msgID")
	})

	t.Run("same session+kind always produces the same collapse-id", func(t *testing.T) {
		sessionID := "session-xyz"
		kind := notifyv2.KindNeedsInput
		msgID1 := "01J7G3QNS5BWT0GNSAB02HAQ4X"
		msgID2 := "01J7G3QNS5BWT0GNSAB02HAQ4Y"
		got1 := CollapseID(msgID1, sessionID, kind)
		got2 := CollapseID(msgID2, sessionID, kind)
		assert.Equal(t, got1, got2, "same session+kind must produce same collapse-id regardless of msgID")
	})

	t.Run("different kinds for the same session produce different collapse IDs", func(t *testing.T) {
		sessionID := "session-xyz"
		msgID := "01J7G3QNS5BWT0GNSAB02HAQ4X"
		id1 := CollapseID(msgID, sessionID, notifyv2.KindNeedsInput)
		id2 := CollapseID(msgID, sessionID, notifyv2.KindCommandDone)
		assert.NotEqual(t, id1, id2, "different kinds must produce different collapse-ids")
	})

	t.Run("different sessions with the same kind produce different collapse IDs", func(t *testing.T) {
		kind := notifyv2.KindCommandDone
		msgID := "01J7G3QNS5BWT0GNSAB02HAQ4X"
		id1 := CollapseID(msgID, "session-A", kind)
		id2 := CollapseID(msgID, "session-B", kind)
		assert.NotEqual(t, id1, id2, "different sessions must produce different collapse-ids")
	})

	t.Run("non-approval-request returns 32 hex chars", func(t *testing.T) {
		got := CollapseID("some-msg-id", "session-123", notifyv2.KindWatchFired)
		assert.Len(t, got, 32, "collapse-id must be 32 hex chars (16 bytes hex-encoded)")
	})

	t.Run("all non-approval kinds produce consistent 32-hex collapse-ids", func(t *testing.T) {
		kinds := []notifyv2.Kind{
			notifyv2.KindNeedsInput,
			notifyv2.KindCommandDone,
			notifyv2.KindWatchFired,
			notifyv2.KindAgentStopped,
		}
		msgID := "01J7G3QNS5BWT0GNSAB02HAQ4X"
		sessionID := "s"
		for _, kind := range kinds {
			got := CollapseID(msgID, sessionID, kind)
			assert.Len(t, got, 32, "kind %q must produce 32 hex chars", kind)
			// Deterministic on repeat.
			got2 := CollapseID(msgID, sessionID, kind)
			assert.Equal(t, got, got2, "kind %q must produce deterministic collapse-id", kind)
		}
	})
}

// TestCollapseIDApnsLimit verifies the result is within APNs 64-byte limit (RESEARCH Pitfall 5).
func TestCollapseIDApnsLimit(t *testing.T) {
	result := CollapseID("msg", "session", notifyv2.KindCommandDone)
	assert.LessOrEqual(t, len(result), 64, "collapse-id must be ≤ 64 bytes (APNs limit)")
	assert.Equal(t, 32, len(result), "collapse-id must be exactly 32 hex chars (16 bytes encoded)")
}

// TestCollapseIDApprovalRequestAlwaysUnique verifies that two different
// approval_request messages never share a collapse-id (D-13).
func TestCollapseIDApprovalRequestAlwaysUnique(t *testing.T) {
	sessionID := "same-session"
	msgID1 := notifyv2.NewMsgID()
	msgID2 := notifyv2.NewMsgID()
	id1 := CollapseID(msgID1, sessionID, notifyv2.KindApprovalRequest)
	id2 := CollapseID(msgID2, sessionID, notifyv2.KindApprovalRequest)
	assert.NotEqual(t, id1, id2, "concurrent approval_request wakes must have distinct collapse-ids")
	assert.Equal(t, msgID1, id1, "approval_request collapse-id must equal msgID1")
	assert.Equal(t, msgID2, id2, "approval_request collapse-id must equal msgID2")
}
