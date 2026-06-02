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
	"errors"
	"log/slog"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/shell"
)

// RigReachability is a tri-state for a rig's network reachability. "unknown"
// (RigUnknown) is the HONEST value when a datum genuinely could not be probed —
// it must never be silently promoted to "online" (WR-05: no fabricated
// all-clear). The web-UI dashboard maps these to dot-online/-offline/-unknown.
type RigReachability int

// RigReachability values.
const (
	RigUnknown RigReachability = iota // could not determine — render honestly as unknown / N/A
	RigOffline                        // probed and not reachable
	RigOnline                         // probed and reachable
)

// LockState is a tri-state for a rig's Tailnet Lock posture. LockNA means the
// datum is unavailable for this rig (e.g. a remote rig whose lock posture we do
// not collect), rendered as N/A rather than a misleading "Locked"/"Unlocked".
type LockState int

// LockState values.
const (
	LockNA       LockState = iota // unavailable — render N/A
	LockUnlocked                  // Tailnet Lock disabled
	LockLocked                    // Tailnet Lock enabled
)

// RigStatus is one rig's posture in the fleet-status snapshot. It is a neutral
// transport struct (no HTML/CSS) so the web-UI adapter projects it to its own
// presentation row without this package importing the webui package. LastSeen
// is a relative human string ("2m ago") or "" when unknown.
type RigStatus struct {
	Name       string
	Reachable  RigReachability
	Lock       LockState
	LastSeen   string
	CertDays   int  // days until TLS cert expiry; <0 or HasCert=false means unknown/N/A
	HasCert    bool // false means cert expiry is unknown (render N/A, not "0d")
	IsLocalRig bool // true for the rig this daemon runs on
}

// CollectFleetStatus returns the live fleet-status snapshot: the count of
// reachable rigs (online), the total enrolled rig count (total), and a per-rig
// detail slice. It is the single source of truth the abysslinkd web-UI
// dashboard renders (B3), so it reflects REAL reachability — never a hardcoded
// stub.
//
// The local rig (the one this daemon runs on) is always row 0: its reachability
// is the backend's own IP resolution (a daemon that answers is reachable on its
// tailnet IP), and its lock posture is read authoritatively from config.
//
// Remote rigs come from cfg.Rigs. Their reachability is probed with a short
// per-rig SSH fan-out (`abysslink status`), bounded by perRigTimeout, run
// concurrently. A rig that does not answer is RigOffline; a probe that could not
// run at all leaves the rig RigUnknown. Remote lock posture is NOT collected
// here (it would require a second remote round-trip), so remote rigs report
// LockNA — rendered honestly as N/A, never a fabricated "Locked".
//
// online counts only RigOnline rigs (RigUnknown is NOT counted as online,
// WR-05). The function respects ctx cancellation and never panics.
func CollectFleetStatus(ctx context.Context, cfg *config.Config, runner shell.Runner) (online, total int, rigs []RigStatus) {
	if cfg == nil {
		cfg = config.Defaults()
	}
	if runner == nil {
		runner = &shell.ExecRunner{}
	}

	cc := &cmdContext{cfg: cfg, runner: runner, dryRun: true}

	// Local rig (row 0).
	local := localRigStatus(ctx, cc)
	rigs = append(rigs, local)

	// Remote rigs from the fleet config. Skip any entry that names the local rig
	// (IN-03): if an operator lists the daemon's own host in cfg.Rigs it would
	// otherwise appear twice — once authoritatively as row 0, once as a remote
	// SSH probe — and double-count in total.
	remotes := filterOutLocalRig(cfg.Rigs, cfg.Tailnet.Hostname)
	rigs = append(rigs, remoteRigStatuses(ctx, runner, remotes)...)

	total = len(rigs)
	for _, r := range rigs {
		if r.Reachable == RigOnline {
			online++
		}
	}
	return online, total, rigs
}

// localRigStatus builds the local rig's posture: reachable iff the backend
// resolves a tailnet IP (the daemon is up and on the tailnet), lock from config.
//
// The local reachability probe is wrapped in a panic-recover that degrades to
// RigUnknown, mirroring the daemon's resolveReachable (internal/daemon/
// server.go): LocalClient.IP dereferences Status.Self without a nil guard
// (internal/tailscale/local.go) and can panic when Status returns (nil, nil)
// — tailscaled absent (CI, or a not-yet-started daemon). A panic here would
// otherwise propagate through webuiStatusProvider → buildStatusData and crash
// the in-flight dashboard render, violating CollectFleetStatus' "never panics"
// contract. A recovered panic is fail-honest: RigUnknown (NOT online, NOT a
// fabricated offline), logged via slog (CLAUDE.md: library code logs, never
// prints). The two posture paths are thus symmetric — /status and the
// dashboard status view both degrade to honest-unknown when tailscaled is gone.
func localRigStatus(ctx context.Context, cc *cmdContext) (rs RigStatus) {
	name := cc.cfg.Tailnet.Hostname
	if name == "" {
		name = "this-rig"
	}

	lock := LockUnlocked
	if cc.cfg.Tailnet.Lock.Enabled {
		lock = LockLocked
	}

	reach := RigUnknown
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("fleet-status: local reachability probe panicked; reporting unknown", "recovered", r)
			rs = RigStatus{
				Name:       name,
				Reachable:  RigUnknown, // fail-honest: not online, not a fabricated offline.
				Lock:       lock,
				LastSeen:   "now",
				HasCert:    false,
				IsLocalRig: true,
			}
		}
	}()

	if b, err := cc.backend(); err == nil && b != nil {
		if ip, ipErr := b.IP(ctx); ipErr == nil && ip != "" {
			reach = RigOnline
		} else if ipErr != nil {
			// Backend present but IP unresolved: the node is not on the tailnet.
			reach = RigOffline
		}
	} else if err != nil {
		slog.Warn("fleet-status: local backend unavailable", "err", err)
	}

	return RigStatus{
		Name:       name,
		Reachable:  reach,
		Lock:       lock,
		LastSeen:   "now",
		HasCert:    false, // local cert expiry is not probed here (render N/A).
		IsLocalRig: true,
	}
}

// filterOutLocalRig drops any cfg.Rigs entry whose name or hostname matches the
// local rig's hostname (IN-03), so the daemon's own host is not probed remotely
// in addition to being reported authoritatively as row 0. An empty localHost
// (hostname unset) matches nothing — every entry is kept.
func filterOutLocalRig(rigs []config.RigConfig, localHost string) []config.RigConfig {
	if localHost == "" || len(rigs) == 0 {
		return rigs
	}
	out := make([]config.RigConfig, 0, len(rigs))
	for _, rc := range rigs {
		if rc.Name == localHost || rc.Hostname == localHost {
			continue
		}
		out = append(out, rc)
	}
	return out
}

// remoteRigStatuses probes every enrolled remote rig's reachability with a
// bounded concurrent SSH fan-out. Lock/cert posture is not collected remotely
// (rendered N/A). A fan-out construction error (e.g. an invalid rig name)
// leaves every remote rig RigUnknown rather than dropping it from the table.
//
// Per-rig outcomes are mapped honestly (WR-05): a rig that answered with a
// non-zero exit, or timed out (context.DeadlineExceeded), is RigOffline; a
// transport failure where the probe could NOT run at all (ssh missing, DNS/auth
// failure) is RigUnknown, never a fabricated "offline".
func remoteRigStatuses(ctx context.Context, runner shell.Runner, rigConfigs []config.RigConfig) []RigStatus {
	if len(rigConfigs) == 0 {
		return nil
	}

	const perRigTimeout = 5 * time.Second
	results, err := fleet.FanOut(ctx, runner, rigConfigs, perRigTimeout, false, []string{"status"})
	if err != nil {
		// Non-strict fan-out only returns an error for a pre-flight validation
		// failure; fall back to all-unknown so the rigs still appear honestly.
		slog.Warn("fleet-status: remote fan-out failed", "err", err)
		out := make([]RigStatus, 0, len(rigConfigs))
		for _, rc := range rigConfigs {
			out = append(out, RigStatus{Name: rc.Name, Reachable: RigUnknown, Lock: LockNA, LastSeen: relativeLastSeen(rc.LastSeen)})
		}
		return out
	}

	out := make([]RigStatus, 0, len(results))
	for _, res := range results {
		// Distinguish "probed-and-offline" from "probe-could-not-run" (WR-05:
		// never fabricate a definite negative). FanOut sets Reachable=false for
		// BOTH a remote that answered with a non-zero exit (an honest offline,
		// Err==nil) and a transport failure where the probe never ran (Err!=nil:
		// ssh binary missing, DNS/auth failure). A deadline-exceeded is an honest
		// timeout → offline; any OTHER transport error means the probe could not
		// complete → RigUnknown, not a fabricated "offline".
		reach := RigOffline
		switch {
		case res.Reachable:
			reach = RigOnline
		case res.Err != nil && !errors.Is(res.Err, context.DeadlineExceeded):
			reach = RigUnknown // probe could not run — honest unknown, never definitive offline.
		}
		out = append(out, RigStatus{
			Name:      res.Rig.Name,
			Reachable: reach,
			Lock:      LockNA, // remote lock posture not collected (render N/A, WR-05).
			LastSeen:  relativeLastSeen(res.Rig.LastSeen),
		})
	}
	return out
}

// relativeLastSeen renders an RFC3339 last-seen timestamp as a coarse relative
// string ("2m ago", "3h ago", "5d ago"). An empty or unparseable value yields ""
// (the caller renders nothing rather than a fabricated time).
func relativeLastSeen(ts string) string {
	if ts == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return formatAgo(int(d/time.Minute), "m")
	case d < 24*time.Hour:
		return formatAgo(int(d/time.Hour), "h")
	default:
		return formatAgo(int(d/(24*time.Hour)), "d")
	}
}

// formatAgo formats "<n><unit> ago" without importing fmt for a single call site.
func formatAgo(n int, unit string) string {
	return intToString(n) + unit + " ago"
}

// intToString converts a small non-negative int to its decimal string. Kept
// local to avoid pulling fmt for hot-path-free formatting; n is bounded by
// realistic rig ages so allocation is negligible.
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
