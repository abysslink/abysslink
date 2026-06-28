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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// statusReport is the JSON-serialisable status summary.
// RigName is populated only on fleet fan-out results (rig_name field, FLEET-02).
//
// WakeSent/AckReceived/ContentStore/Devices are the BACK-07/DEVC-04 fields
// passed through from abysslinkd's GET /status. They are optional — an older
// daemon (or an unreachable one) simply omits them, never errors. Devices is
// also populated from the local device store when the daemon is unreachable
// (CLI-side fallback so a daemon-less setup still shows enrollment state).
type statusReport struct {
	RigName      string `json:"rig_name,omitempty"` // populated by --all-rigs fan-out
	Tailscale    string `json:"tailscale"`
	TailscaleIP  string `json:"tailscale_ip,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	TailscaleSSH string `json:"tailscale_ssh"`
	TailnetLock  string `json:"tailnet_lock"`
	Ntfy         string `json:"ntfy"`
	DiskEncrypt  string `json:"disk_encrypt"`
	Timestamp    string `json:"timestamp"`

	// BACK-07: notification wake/ack counters from the daemon (nil = unknown).
	WakeSent    *uint64 `json:"wake_sent,omitempty"`
	AckReceived *uint64 `json:"ack_received,omitempty"`
	// ContentStore is passed through verbatim (raw JSON) — its shape belongs
	// to the daemon; the CLI renders it best-effort and never validates it.
	ContentStore json.RawMessage `json:"content_store,omitempty"`
	// Devices is the enrolled-device summary (DEVC-04).
	Devices []statusDeviceEntry `json:"devices,omitempty"`
}

// statusDeviceEntry is one device row in the status output. Mirrors the
// daemon's /status devices element {name,last_seen,stale,revoked}; last_seen
// is RFC3339 or empty for "never".
type statusDeviceEntry struct {
	Name     string `json:"name"`
	LastSeen string `json:"last_seen,omitempty"`
	Stale    bool   `json:"stale,omitempty"`
	Revoked  bool   `json:"revoked,omitempty"`
}

// statusDaemonExtras is the subset of abysslinkd's GET /status response the
// CLI consumes for BACK-07/DEVC-04. Every field is optional: an older daemon
// that does not emit them decodes to nils, and unknown extra fields in the
// response are ignored — the CLI must keep working against both daemon
// generations (defensive decode).
type statusDaemonExtras struct {
	WakeSent     *uint64             `json:"wake_sent,omitempty"`
	AckReceived  *uint64             `json:"ack_received,omitempty"`
	ContentStore json.RawMessage     `json:"content_store,omitempty"`
	Devices      []statusDeviceEntry `json:"devices,omitempty"`
	// GatewayCredsStatus is populated by the daemon's /status handler when the
	// push gateway is wired (Phase 29 / PUSH-06). Values: "ok" (creds loaded),
	// "unavailable" (creds missing/inaccessible), or "" (older daemon, field absent).
	// The push-creds-keychain doctor check reads this field.
	GatewayCredsStatus string `json:"gateway_creds_status,omitempty"`
}

// statusNow is a clock seam so tests can pin the timestamp to a fixed instant,
// making the golden byte-stable (the panel writes time.Now().UTC() otherwise).
// Restore in t.Cleanup — same pattern as fetchDaemonStatus / newRunner seams.
var statusNow = func() time.Time { return time.Now() } //nolint:gochecknoglobals // test seam, mirrors fetchDaemonStatus

// fetchDaemonStatus GETs /status from the local abysslinkd over its Unix
// socket and decodes the BACK-07/DEVC-04 fields. A package var so tests can
// inject canned daemon responses (same seam pattern as newRunner). Any error
// means "daemon unreachable" to the caller — never fatal for `status`.
var fetchDaemonStatus = func(ctx context.Context) (*statusDaemonExtras, error) { //nolint:gochecknoglobals // test seam, mirrors newRunner
	sp := daemon.SocketPath()
	if sp == "" {
		return nil, errors.New("status: daemon socket path unavailable")
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sp)
			},
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/status", nil)
	if err != nil {
		return nil, fmt.Errorf("status: build daemon request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("status: daemon unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: daemon /status returned HTTP %d", resp.StatusCode)
	}
	var ex statusDaemonExtras
	if err := json.NewDecoder(resp.Body).Decode(&ex); err != nil {
		return nil, fmt.Errorf("status: decode daemon /status: %w", err)
	}
	return &ex, nil
}

// applyStatusExtras merges the daemon's BACK-07/DEVC-04 fields into rep.
// Daemon reachable: pass the fields through (absent fields stay omitted — an
// older daemon must not break `status`). Daemon unreachable: keep the current
// behavior for the counters (omitted) and fall back to reading the device
// list straight from the local device store, so enrollment state is visible
// even when abysslinkd is not running (DEVC-04 CLI-side fallback).
func applyStatusExtras(rep *statusReport, extras *statusDaemonExtras, fetchErr error) {
	if fetchErr != nil || extras == nil {
		rep.Devices = localDeviceEntries()
		return
	}
	rep.WakeSent = extras.WakeSent
	rep.AckReceived = extras.AckReceived
	rep.ContentStore = extras.ContentStore
	rep.Devices = extras.Devices
}

// localDeviceEntries reads the enrolled-device list directly from the local
// device store (read-only — List/Stale never write). Any failure, including a
// missing store file, yields nil so the section is simply omitted.
func localDeviceEntries() []statusDeviceEntry {
	path, err := deviceStorePath()
	if err != nil {
		return nil
	}
	st := device.New(path, nil, nil, nil) // read-only: no audit writer or keychain needed
	recs := st.List()
	if len(recs) == 0 {
		return nil
	}
	staleIDs := make(map[string]bool)
	for _, r := range st.Stale(deviceStaleWindow) {
		staleIDs[r.ID] = true
	}
	out := make([]statusDeviceEntry, 0, len(recs))
	for _, r := range recs {
		e := statusDeviceEntry{Name: r.Name, Stale: staleIDs[r.ID], Revoked: r.Revoked}
		if !r.LastSeen.IsZero() {
			e.LastSeen = r.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, e)
	}
	return out
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "One-screen health summary of the Tailscale setup",
		Example: `  # Human-readable dashboard
  abysslink status

  # Machine-readable JSON object (ANSI-free)
  abysslink --json status`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}

			p := newPrinter(cmd)

			// Fresh machine: no config exists yet. Say so instead of rendering
			// a green dashboard built from Defaults (U10).
			if cc.cfgMissing {
				printStatusNotInitialised(p, cc.jsonOut)
				return nil
			}

			// Read persistent fan-out flags (registered in Plan 03 / root.go).
			strict, _ := cmd.Flags().GetBool("strict")

			// --rig X (single rig) / --all-rigs (every enrolled rig) fan-out
			// branch: aggregate per-rig results (CLI-05).
			rt, rigErr := resolveRigTargets(cmd, cc.cfg.Rigs)
			if rigErr != nil {
				return rigErr
			}
			if rt.fanOut {
				// --all-rigs with zero enrolled rigs must say so, not silently
				// degrade to local-only output (U3).
				if len(rt.rigs) == 0 {
					printStatusNoRigs(p, cc.jsonOut)
					return nil
				}
				return statusRigs(ctx, cc, p, strict, rt.rigs)
			}

			r := cc.runner
			b, bErr := cc.backend()
			if bErr != nil {
				return fmt.Errorf("status: %w", bErr)
			}

			var tsRunning string // set below: running/stopped on success, "unknown" on query error
			tsIP := ""
			hostname := ""

			st, tsErr := b.Status(ctx)
			if tsErr == nil {
				if st.BackendState == backend.StateRunning {
					tsRunning = "running"
				} else {
					tsRunning = strings.ToLower(string(st.BackendState))
				}
				if st.Self != nil {
					hostname = st.Self.HostName
					if len(st.Self.TailscaleIPs) > 0 {
						tsIP = st.Self.TailscaleIPs[0].String()
					}
				}
			} else {
				// Distinguish a failed query (tailscaled unreachable / RPC error)
				// from a confirmed-stopped backend: "not running" must mean we
				// actually asked and it was down, not that we never got an answer (T-043).
				tsRunning = "unknown"
				slog.Debug("status: tailscale backend query failed", "err", tsErr)
			}

			tsSSH := "disabled"
			if cc.cfg.Tailnet.SSH {
				tsSSH = "enabled"
			}

			lockStatus := "disabled"
			if cc.cfg.Tailnet.Lock.Enabled {
				lockStatus = "enabled"
			}

			ntfyStatus := "disabled"
			if cc.cfg.Modules.Ntfy.Enabled {
				ntfyStatus = "enabled"
			}

			diskEncrypt := diskEncryptionStatus(ctx, r)

			now := statusNow()
			rep := statusReport{
				Tailscale:    tsRunning,
				TailscaleIP:  tsIP,
				Hostname:     hostname,
				TailscaleSSH: tsSSH,
				TailnetLock:  lockStatus,
				Ntfy:         ntfyStatus,
				DiskEncrypt:  diskEncrypt,
				// RFC3339 UTC — the same format the fleet fan-out rows use, so
				// JSON consumers parse exactly one timestamp format (U5).
				Timestamp: now.UTC().Format(time.RFC3339),
			}

			// BACK-07/DEVC-04: merge the daemon's wake/ack counters, content
			// store state, and device list — defensively (an older or
			// unreachable daemon degrades to omission + local-store fallback,
			// never an error).
			extras, exErr := fetchDaemonStatus(ctx)
			applyStatusExtras(&rep, extras, exErr)

			if cc.jsonOut {
				// Emit a typed, ANSI-free record via PrintJSON (T-10-18).
				p.PrintJSON(rep)
				return nil
			}

			printStatusPanel(p, rep)
			renderStatusExtras(p, rep, now)
			return nil
		},
	}
}

// printStatusNotInitialised renders the "not initialised — run init" banner
// for a machine with no abysslink.yaml (U10). JSON mode emits a structured
// record so scripts can detect the state.
func printStatusNotInitialised(p Printer, jsonOut bool) {
	if jsonOut {
		p.PrintJSON(map[string]string{
			"status": "not-initialised",
			"hint":   "run `abysslink init` to create abysslink.yaml",
		})
		return
	}
	printerInfo(p, "")
	printerInfo(p, "  "+iconWarnStr()+"  "+styleWarn.Render("Abysslink is not initialised on this machine."))
	printerInfo(p, "  "+styleMuted.Render("Run ")+styleCode.Render("abysslink init")+styleMuted.Render(" to set it up."))
	printerInfo(p, "")
}

// printStatusNoRigs renders the empty-fleet notice for --all-rigs (U3). JSON
// mode emits [] so list consumers get a stable empty-list encoding.
func printStatusNoRigs(p Printer, jsonOut bool) {
	if jsonOut {
		p.PrintJSON([]statusReport{})
		return
	}
	printerInfo(p, "  No rigs enrolled — enroll one with "+styleCode.Render("abysslink rig add")+".")
}

// statusRigs fans out `abysslink status --json` to the targeted rigs only
// (every enrolled rig under --all-rigs, a single rig under --rig, CLI-05).
func statusRigs(ctx context.Context, cc *cmdContext, p Printer, strict bool, rigs []config.RigConfig) error {
	const perRigTimeout = 10 * time.Second

	// Animated liveness during the fan-out (10s/rig); spinWork is json-safe so
	// the --json aggregate + exit code are unaffected.
	var results []fleet.RigResult
	var fanErr error
	_ = spinWork(ctx, p, "Querying rigs…", func(ctx context.Context) error {
		results, fanErr = fleet.FanOut(ctx, cc.runner, rigs, perRigTimeout, strict, []string{"status", "--json"})
		return nil
	})

	var aggregate []statusReport
	for _, r := range results {
		if !r.Reachable {
			// UNREACHABLE is a result value, not a fatal error (SC-2 / FLEET-02).
			aggregate = append(aggregate, statusReport{
				RigName:   r.Rig.Name,
				Tailscale: "UNREACHABLE",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}
		var rep statusReport
		if err := json.Unmarshal([]byte(r.Stdout), &rep); err != nil {
			// Degraded-but-reachable: surface with a DEGRADED marker so the user
			// knows the rig responded but its output could not be decoded.
			aggregate = append(aggregate, statusReport{
				RigName:   r.Rig.Name,
				Tailscale: "DEGRADED",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}
		rep.RigName = r.Rig.Name
		aggregate = append(aggregate, rep)
	}

	if cc.jsonOut {
		// ANSI-free JSON array (UX-04).
		p.PrintJSON(aggregate)
	} else {
		printStatusAllRigsTable(p, aggregate)
	}

	// Fan-out error is non-nil only under --strict (one or more rigs unreachable).
	if fanErr != nil {
		return &exitError{code: exitCodeFatal}
	}
	return nil
}

// printStatusAllRigsTable renders a human-readable table of per-rig status rows.
func printStatusAllRigsTable(p Printer, rows []statusReport) {
	printerInfo(p, styleTitle.Render("Fleet Status")+"\n")
	header := fmt.Sprintf("  %-20s %-14s %-12s %-10s", "RIG", "TAILSCALE", "DISK", "NTFY")
	printerInfo(p, styleMuted.Render(header))
	for _, r := range rows {
		disk := r.DiskEncrypt
		if disk == "" {
			disk = "-"
		}
		ntfy := r.Ntfy
		if ntfy == "" {
			ntfy = "-"
		}
		printerInfo(p, fmt.Sprintf("  %-20s %-14s %-12s %-10s", truncCell(r.RigName, 20), r.Tailscale, disk, ntfy))
	}
	printerInfo(p, "")
}

// luksDevice is a minimal lsblk JSON device entry used by diskEncryptionStatus.
type luksDevice struct {
	Type     string       `json:"type"`
	Children []luksDevice `json:"children"`
}

// hasLUKSType recursively checks whether any device in the tree has type "crypt".
func hasLUKSType(devs []luksDevice) bool {
	for _, d := range devs {
		if strings.EqualFold(d.Type, "crypt") {
			return true
		}
		if hasLUKSType(d.Children) {
			return true
		}
	}
	return false
}

// diskEncryptionStatus queries the OS for actual disk encryption state.
// Returns "encrypted", "unencrypted", or "unknown".
func diskEncryptionStatus(ctx context.Context, r shell.Runner) string {
	switch runtime.GOOS {
	case "darwin":
		res, err := r.Run(ctx, "fdesetup", "status")
		if err != nil || res.ExitCode != 0 {
			return "unknown"
		}
		if strings.HasPrefix(strings.TrimSpace(res.Stdout), "FileVault is On") {
			return "encrypted"
		}
		return "unencrypted"
	case "linux":
		// Use -J -o NAME,TYPE (no MOUNTPOINT) to match platform/linux and avoid
		// false positives from device names or mount paths containing "crypt".
		res, err := r.Run(ctx, "lsblk", "-J", "-o", "NAME,TYPE")
		if err != nil || res.ExitCode != 0 {
			return "unknown"
		}
		var out struct {
			Blockdevices []luksDevice `json:"blockdevices"`
		}
		if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
			return "unknown"
		}
		if hasLUKSType(out.Blockdevices) {
			return "encrypted"
		}
		return "unencrypted"
	default:
		return "unknown"
	}
}

// statusRowState classifies a status panel row for icon rendering.
type statusRowState int

const (
	rowOK      statusRowState = iota // green — feature healthy/enabled
	rowBad                           // red — feature expected but failing
	rowNeutral                       // muted — feature deliberately disabled (U4)
)

// statusRow renders one row of the status panel.
func statusRow(label, value string, state statusRowState) string {
	var icon string
	switch state {
	case rowOK:
		icon = iconOKStr()
	case rowNeutral:
		icon = iconNeutralStr()
	default:
		icon = iconFatalStr()
	}
	lbl := styleMuted.Render(fmt.Sprintf("%-18s", label))
	return fmt.Sprintf("  %s  %s  %s", icon, lbl, styleBold.Render(value))
}

// statusRowStateFor maps a status value to its row state. "disabled" is a
// deliberate user choice and renders neutral, never as a red failure (U4).
func statusRowStateFor(s string) statusRowState {
	switch s {
	case "running", "enabled", "encrypted":
		return rowOK
	case "disabled":
		return rowNeutral
	default:
		return rowBad
	}
}

// printStatusPanel renders the styled status box.
func printStatusPanel(p Printer, rep statusReport) {

	hostnameLabel := rep.Tailscale
	if rep.Hostname != "" || rep.TailscaleIP != "" {
		parts := []string{}
		if rep.Hostname != "" {
			parts = append(parts, rep.Hostname)
		}
		if rep.TailscaleIP != "" {
			parts = append(parts, styleMuted.Render(rep.TailscaleIP))
		}
		hostnameLabel += "  " + styleMuted.Render("("+strings.Join(parts, " · ")+")")
	}

	var sb strings.Builder
	sb.WriteString(styleTitle.Render("Abysslink Status"))
	sb.WriteString("\n\n")
	for _, row := range []string{
		statusRow("Tailscale", hostnameLabel, statusRowStateFor(rep.Tailscale)),
		statusRow("Tailscale SSH", rep.TailscaleSSH, statusRowStateFor(rep.TailscaleSSH)),
		statusRow("Tailnet Lock", rep.TailnetLock, statusRowStateFor(rep.TailnetLock)),
		statusRow("ntfy", rep.Ntfy, statusRowStateFor(rep.Ntfy)),
		statusRow("Disk Encryption", rep.DiskEncrypt, statusRowStateFor(rep.DiskEncrypt)),
	} {
		sb.WriteString(row)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(styleMuted.Render(rep.Timestamp))

	printerInfo(p, styleStatusBox.Render(strings.TrimRight(sb.String(), "\n")))
	printerInfo(p, "")
}

// renderStatusExtras prints the human-readable BACK-07/DEVC-04 section under
// the status panel: notification wake/ack counters, content store state, and
// the device list with stale (⚠) and revoked flags. Every sub-section is
// omitted when its data is absent (older daemon / nothing enrolled).
func renderStatusExtras(p Printer, rep statusReport, now time.Time) {
	printed := false
	if rep.WakeSent != nil || rep.AckReceived != nil {
		printerInfo(p, fmt.Sprintf("  notifications: %d wakes sent · %d acks received",
			derefUint64(rep.WakeSent), derefUint64(rep.AckReceived)))
		printed = true
	}
	if cs := contentStoreLabel(rep.ContentStore); cs != "" {
		printerInfo(p, "  content store: "+cs)
		printed = true
	}
	if len(rep.Devices) > 0 {
		printerInfo(p, "  devices:")
		for _, d := range rep.Devices {
			printerInfo(p, "    "+statusDeviceLine(d, now))
		}
		printed = true
	}
	if printed {
		printerInfo(p, "")
	}
}

// derefUint64 returns *v, or 0 for nil.
func derefUint64(v *uint64) uint64 {
	if v == nil {
		return 0
	}
	return *v
}

// contentStoreLabel renders the daemon's content_store field best-effort: a
// JSON string is shown bare; any other shape is shown as raw compact JSON.
func contentStoreLabel(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// statusDeviceLine renders one device row: revoked wins over stale; stale rows
// are flagged with ⚠ and the time since last check-in (DEVC-04).
func statusDeviceLine(d statusDeviceEntry, now time.Time) string {
	switch {
	case d.Revoked:
		return d.Name + "  " + styleMuted.Render("revoked")
	case d.Stale && d.LastSeen == "":
		return d.Name + "  " + styleWarn.Render("⚠ stale — never checked in")
	case d.Stale:
		return d.Name + "  " + styleWarn.Render("⚠ stale — last seen "+lastSeenLabel(d.LastSeen, now))
	default:
		return d.Name + "  " + styleMuted.Render("last seen "+lastSeenLabel(d.LastSeen, now))
	}
}

// lastSeenLabel humanizes an RFC3339 last-seen stamp relative to now; an
// empty stamp is "never" and an unparseable one is shown verbatim (defensive:
// the value comes from the daemon, not from this process).
func lastSeenLabel(lastSeen string, now time.Time) string {
	if lastSeen == "" {
		return "never"
	}
	t, err := time.Parse(time.RFC3339, lastSeen)
	if err != nil {
		return lastSeen
	}
	return humanizeSince(now, t)
}

// humanizeSince renders the elapsed time since t as "just now" / "Nm ago" /
// "Nh ago" / "Nd ago".
func humanizeSince(now, t time.Time) string {
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
