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

package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
)

// ntfyTopicEntropyHexFloor is the minimum length, in hex characters, of a rig
// ntfy topic's random suffix. 32 hex chars == 16 bytes == 128 bits — the same
// entropy enrollRigDeriveTopic generates. When ntfy.sh is the delivery target
// the topic IS the credential, so a short (e.g. 32-bit) suffix over a guessable
// rig name is brute-forceable (B9 / T-32-16).
const ntfyTopicEntropyHexFloor = 32

// ntfyTopicSuffix extracts the random component after the "abysslink-<name>-"
// prefix of a derived rig topic. It returns ("", false) when topic does not
// have the abysslink-derived shape (a custom operator-chosen topic is out of
// scope for the entropy floor — we never rewrite a topic we did not generate).
func ntfyTopicSuffix(topic string) (string, bool) {
	if !strings.HasPrefix(topic, "abysslink-") {
		return "", false
	}
	// Shape: abysslink-<name>-<suffix>. The suffix is the final '-' segment.
	idx := strings.LastIndex(topic, "-")
	if idx < 0 || idx == len(topic)-1 {
		return "", false
	}
	// Require at least the "abysslink-<name>-" structure: there must be a name
	// segment between the leading "abysslink-" and the suffix.
	if idx < len("abysslink-") {
		return "", false
	}
	return topic[idx+1:], true
}

// ntfyTopicHasFloorEntropy reports whether topic carries at least the ≥128-bit
// (≥32 hex char) random suffix the entropy floor requires. A topic without the
// abysslink-derived shape returns false (it does not meet the floor and will be
// handled by the caller — for derived topics that means regeneration; custom
// topics are left untouched by the Write path via ntfyTopicSuffix's ok flag).
func ntfyTopicHasFloorEntropy(topic string) bool {
	suffix, ok := ntfyTopicSuffix(topic)
	if !ok {
		return false
	}
	if len(suffix) < ntfyTopicEntropyHexFloor {
		return false
	}
	// The suffix must be hex (the generated form); a non-hex tail of sufficient
	// length is not the credential-grade random component we require.
	if _, err := hex.DecodeString(suffix); err != nil {
		return false
	}
	return true
}

// regenNtfyTopicSuffix returns topic with its random suffix replaced by a fresh
// 16-byte (128-bit) hex value, preserving the "abysslink-<name>-" prefix. It is
// used to rotate a below-floor topic on write.
func regenNtfyTopicSuffix(topic string) (string, error) {
	suffix, ok := ntfyTopicSuffix(topic)
	if !ok {
		return "", fmt.Errorf("config: topic %q has no abysslink-derived suffix to rotate", topic)
	}
	prefix := strings.TrimSuffix(topic, suffix)
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("config: ntfy topic entropy: %w", err)
	}
	return prefix + hex.EncodeToString(buf), nil
}

// enforceNtfyTopicEntropyFloor scans cfg's rig ntfy topics and regenerates any
// abysslink-derived topic that falls below the entropy floor (B9 / T-32-16). An
// above-floor topic is left byte-identical; a custom (non-derived) topic is left
// untouched. Each rotation emits a slog.Warn naming the rig — never the raw
// topic credential — so the operator knows a topic was rotated for entropy on
// this persist. Regeneration never blanks a topic.
//
// This runs inside config.Write, the single persistence chokepoint, so a live
// topic is only rotated when config is being written anyway (the operator's next
// --apply), never silently mid-session.
func enforceNtfyTopicEntropyFloor(cfg *Config) error {
	for i := range cfg.Rigs {
		topic := cfg.Rigs[i].NtfyTopic
		// Only derived topics are in scope; a custom topic (no abysslink- shape)
		// is the operator's deliberate choice and is left alone.
		if _, derived := ntfyTopicSuffix(topic); !derived {
			continue
		}
		if ntfyTopicHasFloorEntropy(topic) {
			continue
		}
		rotated, err := regenNtfyTopicSuffix(topic)
		if err != nil {
			return err
		}
		cfg.Rigs[i].NtfyTopic = rotated
		slog.Warn("ntfy topic below the 128-bit entropy floor was rotated on config write",
			"rig", cfg.Rigs[i].Name)
	}
	return nil
}
