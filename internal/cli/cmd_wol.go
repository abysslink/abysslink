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

package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules/upsnap"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// wolBroadcastAddr is the UDP destination for the Wake-on-LAN magic packet.
// Port 9 (discard) is the conventional WoL port; the limited-broadcast address
// 255.255.255.255 stays LAN-local by OS routing and never traverses the
// internet (upsnap-no-public doctor check documents this invariant).
const wolBroadcastAddr = "255.255.255.255:9"

// wolSendFunc sends the magic packet over UDP. It is a package-level test seam:
// the production implementation dials the broadcast address; tests override it
// with a counter to assert that dry-run sends ZERO packets (HARD FLOOR,
// T-21-01-01). It is reset by tests via t.Cleanup.
var wolSendFunc = sendMagicPacketUDP //nolint:gochecknoglobals // gochecknoglobals: package-level var is a test/injection seam for the UDP send path; intentional

// wolAuditFunc records the WoL send in the audit log. It is a package-level
// test seam so unit tests can assert the audit entry is written exactly once on
// --apply (and never on dry-run) without touching the real audit log on disk.
var wolAuditFunc = recordWolAudit //nolint:gochecknoglobals // gochecknoglobals: package-level var is a test/injection seam for the audit append; intentional

// newWolCmd returns the `abysslink wol <rig>` command. WoL is a mutation, so the
// HARD FLOOR applies: without --apply the command prints a dry-run summary and
// sends ZERO UDP packets and writes NO audit entry. With --apply it builds the
// hand-rolled magic packet, records an audit entry (rig name + MAC), and sends
// the packet to the LAN broadcast address.
func newWolCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wol <rig>",
		Short: "Wake a rig over the LAN (Wake-on-LAN)",
		Long: `Send a Wake-on-LAN magic packet to an enrolled rig.

The rig's MAC address is read from its mac: field in abysslink.yaml — never from
the command line. Without --apply this prints a dry-run summary and sends nothing.
With --apply it broadcasts the magic packet on the local network and records an
audit entry containing the rig name and MAC.`,
		Example: `  # Dry-run (default): show what would be sent, send nothing
  abysslink wol laptop

  # Actually send the magic packet
  abysslink wol laptop --apply`,
		Args: cobra.ExactArgs(1),
	}

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		cc, err := loadCmdContext(c)
		if err != nil {
			return err
		}
		p := newPrinter(c)
		rigName := args[0]

		rig, ok := lookupRig(cc.cfg.Rigs, rigName)
		if !ok {
			return fmt.Errorf("wol: rig %q not found in abysslink.yaml", rigName)
		}
		if rig.MAC == "" {
			return fmt.Errorf("wol: rig %s: no mac address configured — add mac: <MAC> to the rig in abysslink.yaml", rigName)
		}
		mac, err := net.ParseMAC(rig.MAC)
		if err != nil {
			// Do not echo the raw MAC value in the error (keep messages clean and
			// avoid leaking malformed config content verbatim).
			return fmt.Errorf("wol: rig %s: invalid MAC address: %w", rigName, err)
		}

		// HARD FLOOR (T-21-01-01): dry-run sends zero packets and writes no audit.
		if !cc.apply {
			p.Print(fmt.Sprintf("DRY RUN: would send WoL magic packet to %s (MAC %s)", rigName, mac.String()))
			return nil
		}

		// --apply: build the packet, record the audit entry FIRST (audit-then-act),
		// then broadcast.
		pkt, err := upsnap.BuildMagicPacket(mac)
		if err != nil {
			return fmt.Errorf("wol: build magic packet: %w", err)
		}

		if err := wolAuditFunc(ctx, cc, rigName, mac.String()); err != nil {
			return fmt.Errorf("wol: audit: %w", err)
		}

		if err := wolSendFunc(ctx, cc.runner, pkt); err != nil {
			return fmt.Errorf("wol: send magic packet to %s: %w", rigName, err)
		}

		p.Print(fmt.Sprintf("Sent WoL magic packet to %s (MAC %s)", rigName, mac.String()))
		return nil
	}

	return cmd
}

// lookupRig finds a rig by name in the configured fleet.
func lookupRig(rigs []config.RigConfig, name string) (config.RigConfig, bool) {
	for _, r := range rigs {
		if r.Name == name {
			return r, true
		}
	}
	return config.RigConfig{}, false
}

// sendMagicPacketUDP broadcasts pkt to the LAN WoL address. net.Dial to a
// broadcast address lets the OS set SO_BROADCAST; the send stays LAN-local. The
// runner argument is accepted to keep the seam signature uniform with the
// project's shell.Runner convention even though a raw UDP socket needs no
// subprocess.
func sendMagicPacketUDP(ctx context.Context, _ shell.Runner, pkt []byte) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp4", wolBroadcastAddr)
	if err != nil {
		return fmt.Errorf("dial udp broadcast: %w", err)
	}
	defer conn.Close() //nolint:errcheck // best-effort cleanup on a UDP conn
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("write magic packet: %w", err)
	}
	return nil
}

// recordWolAudit records a WoL send in the RESOLVED audit log via the
// chain-correct writer (W-02 correction). When a keychain is available it
// extends the signed HMAC chain (audit.NewSigned — never injects an unsigned
// entry into a signed chain); otherwise it appends to the unsigned legacy log
// (audit.New). The target carries "<rig>:<MAC>" and the DiffHash is
// sha256(rig:MAC); the UDP payload is never recorded. The MAC is a hardware
// identifier, not a secret, so recording it is acceptable (T-21-01-03).
//
// It uses WriteFile-free Append (not a fake WriteFile sentinel path), so the
// real audit writer never attempts a filesystem write to a bogus path.
func recordWolAudit(ctx context.Context, cc *cmdContext, rigName, macStr string) error {
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("audit log path: %w", err)
	}

	kc, kerr := secrets.NewStore(ctx, cc.runner)
	if kerr != nil {
		kc = nil
	}

	target := rigName + ":" + macStr
	diff := sha256.Sum256([]byte(target))

	if kc != nil {
		sa, saErr := audit.NewSigned(logPath, kc)
		if saErr != nil {
			return fmt.Errorf("signed audit writer: %w", saErr)
		}
		return sa.Append(ctx, audit.SignInput{Title: "wol", DiffHash: diff}, target, false)
	}
	return audit.New(logPath).Append("wol", target, []byte(target), false)
}
