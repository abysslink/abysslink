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

package approve

import (
	"errors"
	"strings"
)

// TierLevel classifies an approval request's sensitivity (D-05/D-08).
// In-code constants; YAML may only tighten via extraCritical, never loosen.
type TierLevel int

const (
	// TierBenign passes through with no gate required.
	TierBenign TierLevel = 0
	// TierSensitive requires any approver: phone or TTY.
	TierSensitive TierLevel = 1
	// TierCritical is TTY-only in v4; phone path in v5 via device-bound key.
	TierCritical TierLevel = 2
)

// CriticalPatterns is the immutable in-code set of action-name substrings that
// force TierCritical regardless of caller declaration (D-06/D-08). YAML's
// approval.extra_critical is APPENDED to this via the extraCritical argument
// to Tier(); it can never remove an entry. The Tier() function always checks
// CriticalPatterns first.
var CriticalPatterns = []string{
	"panic-revoke",
	"kill-switch-disarm",
	"destructive-apply",
}

// ErrCriticalTierTTYOnly is returned by Registry.Open when the resolved tier
// is TierCritical. Critical-tier actions are TTY-only in v4; the phone path
// (device-bound strong approval) is a v5 capability (D-07).
var ErrCriticalTierTTYOnly = errors.New(
	"approve: critical tier is TTY-only in v4; device-bound strong approval is v5 (D-07)",
)

// Tier resolves the effective TierLevel for an action. It checks CriticalPatterns
// (strings.Contains) against actionName, then extraCritical; returns TierCritical
// if any match. Otherwise it returns declared. The in-code patterns are ALWAYS
// checked regardless of extraCritical contents — a caller can never downgrade a
// critical action by omitting extra_critical (D-06/D-08).
func Tier(declared TierLevel, actionName string, extraCritical []string) TierLevel {
	for _, pat := range CriticalPatterns {
		if strings.Contains(actionName, pat) {
			return TierCritical
		}
	}
	for _, pat := range extraCritical {
		if strings.Contains(actionName, pat) {
			return TierCritical
		}
	}
	return declared
}
