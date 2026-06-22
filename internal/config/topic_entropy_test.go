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

package config_test

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/config"
)

// writeTestConfig builds a minimal config with the given rig topics and persists
// it via config.Write, returning the reloaded config. XDG_STATE_HOME is pointed
// at the test temp dir so the audit log lands there.
func writeTestConfig(t *testing.T, topics []string) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	cfgPath := filepath.Join(dir, "abysslink.yaml")

	cfg := config.Defaults()
	cfg.Identity.Email = "you@example.com"
	cfg.Identity.UnixUser = "you"
	cfg.Tailnet.Hostname = "mac-dev"
	for i, tp := range topics {
		cfg.Rigs = append(cfg.Rigs, config.RigConfig{
			Name:      "rig" + string(rune('a'+i)),
			Hostname:  "rig" + string(rune('a'+i)) + ".ts.net",
			NtfyTopic: tp,
			Backend:   "tailscale",
		})
	}
	require.NoError(t, config.Write(cfgPath, cfg))

	loaded, err := config.Load(cfgPath)
	require.NoError(t, err)
	return loaded, cfgPath
}

// TestWriteRegeneratesBelowFloorTopic verifies B9 (T-32-16): config.Write
// regenerates a below-floor rig topic to a ≥128-bit suffix, leaves an
// above-floor topic byte-identical, and never blanks a topic.
func TestWriteRegeneratesBelowFloorTopic(t *testing.T) {
	above := "abysslink-riga-0123456789abcdef0123456789abcdef" // 32 hex chars
	below := "abysslink-rigb-deadbeef"                         // 8 hex chars

	loaded, _ := writeTestConfig(t, []string{above, below})
	require.Len(t, loaded.Rigs, 2)

	// Above-floor topic is preserved byte-identical.
	assert.Equal(t, above, loaded.Rigs[0].NtfyTopic, "above-floor topic must not change")

	// Below-floor topic was rotated to a fresh ≥128-bit suffix.
	got := loaded.Rigs[1].NtfyTopic
	assert.NotEqual(t, below, got, "below-floor topic must be regenerated")
	assert.NotEmpty(t, got, "regeneration must never blank a topic")
	assert.True(t, strings.HasPrefix(got, "abysslink-rigb-"), "regen must preserve the abysslink-<name>- prefix shape, got %q", got)
	suffix := strings.TrimPrefix(got, "abysslink-rigb-")
	assert.GreaterOrEqual(t, len(suffix), 32, "regenerated suffix must carry ≥128 bits (≥32 hex chars)")
}

// TestWriteRegenerationWarns asserts the rotation emits a slog warning naming
// the rig (and does not log the raw new topic credential).
func TestWriteRegenerationWarns(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_, _ = writeTestConfig(t, []string{"abysslink-riga-deadbeef"})

	logged := buf.String()
	assert.Contains(t, logged, "riga", "warning must name the rotated rig")
	assert.NotContains(t, logged, "deadbeef", "warning must not log the old/new raw topic credential")
}
