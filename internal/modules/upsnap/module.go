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
	"fmt"
	"log/slog"
	"net"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// magicPacketLen is the fixed Wake-on-LAN magic-packet size: a 6-byte 0xFF
// sync stream followed by 16 repetitions of the 6-byte target MAC.
const magicPacketLen = 6 + 16*6 // 102

// macLen is the byte length of an IEEE 802 MAC address (EUI-48).
const macLen = 6

// Module implements the optional Wake-on-LAN module.
//
// In v3 the upsnap module is the WoL enablement module. It no longer manages a
// running UpSnap service: its job is to (1) detect that WoL is configured
// (module enabled + at least one rig carries a mac: field) and (2) surface
// structural doctor findings. The actual UDP magic-packet send is the CLI
// command's responsibility (cmd_wol.go), gated behind --apply, so the mutation
// gate lives in exactly one place.
type Module struct {
	runner shell.Runner
	cfg    *config.Config
}

// New returns a new Module.
func New(d modules.Deps) *Module {
	return &Module{runner: d.Runner, cfg: d.Cfg}
}

// Name returns the canonical module name.
func (m *Module) Name() string { return "upsnap" }

// Deps returns this module's dependencies.
func (m *Module) Deps() []string { return []string{"tailscale"} }

// Detect reports the WoL configuration state. When the module is disabled it
// returns no findings. When enabled it emits a WARN if no rig has a usable
// mac: field, because WoL cannot wake anything without a target MAC.
func (m *Module) Detect(_ context.Context) ([]modules.Finding, error) {
	if !m.cfg.Modules.Upsnap.Enabled {
		slog.Debug("upsnap module disabled, skipping detect")
		return nil, nil
	}

	var findings []modules.Finding

	if !m.hasRigWithMAC() {
		findings = append(findings, modules.Finding{
			Module:   m.Name(),
			Check:    "wol-no-rig-mac",
			Severity: modules.SeverityWarning,
			Message:  "no rig has a mac: field set — add mac: <MAC> to a rig in abysslink.yaml to enable WoL",
		})
	}

	return findings, nil
}

// hasRigWithMAC reports whether any configured rig carries a parseable MAC.
func (m *Module) hasRigWithMAC() bool {
	for _, rig := range m.cfg.Rigs {
		if rig.MAC == "" {
			continue
		}
		if _, err := net.ParseMAC(rig.MAC); err == nil {
			return true
		}
	}
	return false
}

// Plan reports that WoL is ready. WoL is a manual per-command action, so there
// is no converge-time work to do; Plan returns a single informational action.
func (m *Module) Plan(_ context.Context, _ bool) ([]modules.Action, error) {
	if !m.cfg.Modules.Upsnap.Enabled {
		return nil, nil
	}
	return []modules.Action{{
		Module:      m.Name(),
		Description: "WoL (Wake-on-LAN) ready — run `abysslink wol <rig> --apply` to wake a rig",
		Reversible:  false,
	}}, nil
}

// Apply is a no-op: WoL is a manual per-command action triggered by
// `abysslink wol <rig> --apply`, not a converge-time mutation.
func (m *Module) Apply(_ context.Context) error {
	return nil
}

// Verify is a no-op for the upsnap module — all checks run in Detect.
// Pitfall 4 (Doctor double-emission): do NOT call Detect here — runner.Doctor
// calls both Detect and Verify, so re-running Detect would double-emit every
// Detect finding per doctor pass (NET-18). Verify adds no new information
// beyond Detect; returning nil avoids the duplication (mirrors ssh/ntfy).
func (m *Module) Verify(_ context.Context) ([]modules.Finding, error) {
	return nil, nil
}

// Repair re-runs Detect (WoL has no converge-time remediation).
func (m *Module) Repair(ctx context.Context) error {
	_, err := m.Detect(ctx)
	return err
}

// BuildMagicPacket constructs the hand-rolled 102-byte Wake-on-LAN magic
// packet for mac: 6 bytes of 0xFF followed by 16 repetitions of the 6-byte
// MAC. It returns an error when mac is not exactly 6 bytes (EUI-48). Pure
// stdlib; no external dependency. The caller (cmd_wol.go) is responsible for
// the UDP broadcast send and the --apply gate.
func BuildMagicPacket(mac net.HardwareAddr) ([]byte, error) {
	if len(mac) != macLen {
		return nil, fmt.Errorf("upsnap: invalid MAC address length %d (expected %d)", len(mac), macLen)
	}
	pkt := make([]byte, magicPacketLen)
	for i := range 6 {
		pkt[i] = 0xFF
	}
	for i := range 16 {
		copy(pkt[6+i*macLen:], mac)
	}
	return pkt, nil
}
