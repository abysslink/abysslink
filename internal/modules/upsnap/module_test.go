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

package upsnap

import (
	"context"
	"net"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enabledCfg returns a config with the upsnap module enabled.
func enabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Upsnap.Enabled = true
	return cfg
}

// enabledCfgWithMAC returns an enabled config with one rig carrying a MAC.
func enabledCfgWithMAC() *config.Config {
	cfg := enabledCfg()
	cfg.Rigs = []config.RigConfig{{Name: "rig1", MAC: "aa:bb:cc:dd:ee:ff"}}
	return cfg
}

// disabledCfg returns a config with the upsnap module disabled (default).
func disabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Upsnap.Enabled = false
	return cfg
}

// TestBuildMagicPacket verifies the hand-rolled 102-byte packet layout.
func TestBuildMagicPacket(t *testing.T) {
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	require.NoError(t, err)

	pkt, err := BuildMagicPacket(mac)
	require.NoError(t, err)
	require.Len(t, pkt, 102, "magic packet must be exactly 102 bytes")

	// Bytes 0-5 must be 0xFF.
	for i := range 6 {
		assert.Equal(t, byte(0xFF), pkt[i], "byte %d must be 0xFF", i)
	}

	// Bytes 6-101 must be 16 repetitions of the 6-byte MAC.
	for rep := range 16 {
		off := 6 + rep*6
		assert.Equal(t, []byte(mac), pkt[off:off+6], "repetition %d must equal the MAC", rep)
	}
}

// TestBuildMagicPacket_InvalidMAC verifies a non-6-byte MAC returns an error.
func TestBuildMagicPacket_InvalidMAC(t *testing.T) {
	// A 4-byte hardware address (not a valid EUI-48).
	_, err := BuildMagicPacket(net.HardwareAddr{0x01, 0x02, 0x03, 0x04})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid MAC address length")
}

// TestModule_Detect_Disabled verifies a disabled module returns no findings
// and makes no runner calls.
func TestModule_Detect_Disabled(t *testing.T) {
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: disabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.True(t, r.Done(), "no runner calls expected when disabled")
}

// TestModule_Detect_NoRigMAC verifies an enabled module with no rig MAC emits a
// wol-no-rig-mac WARN.
func TestModule_Detect_NoRigMAC(t *testing.T) {
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: enabledCfg(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "wol-no-rig-mac", findings[0].Check)
	assert.Equal(t, modules.SeverityWarning, findings[0].Severity)
}

// TestModule_Detect_WithRigMAC verifies an enabled module with a rig MAC emits
// no findings (WoL is configured and ready).
func TestModule_Detect_WithRigMAC(t *testing.T) {
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: enabledCfgWithMAC(), Runner: r})
	findings, err := m.Detect(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestModule_Plan_Disabled verifies Plan returns nil when disabled.
func TestModule_Plan_Disabled(t *testing.T) {
	m := New(modules.Deps{Cfg: disabledCfg(), Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	assert.Nil(t, actions)
}

// TestModule_Plan_Enabled verifies Plan returns the WoL-ready action.
func TestModule_Plan_Enabled(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledCfgWithMAC(), Runner: shell.NewMockRunner()})
	actions, err := m.Plan(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Description, "WoL")
}

// TestModule_Apply_Noop verifies Apply never mutates and never errors.
func TestModule_Apply_Noop(t *testing.T) {
	m := New(modules.Deps{Cfg: enabledCfgWithMAC(), Runner: shell.NewMockRunner()})
	require.NoError(t, m.Apply(context.Background()))
}
