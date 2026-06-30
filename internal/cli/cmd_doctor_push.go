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
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/device"
	"github.com/abysslink/abysslink/internal/modules"
)

// pushGatewayModule groups every push-gateway doctor finding under one heading
// in the doctor render.
const pushGatewayModule = "push-gateway"

// pushStaleDuration is the threshold after which a device's push token is
// considered potentially stale. Mirrors D-12: 30 days.
const pushStaleDuration = 30 * 24 * time.Hour

// pushOKFinding builds a SeverityOK push-gateway finding.
func pushOKFinding(check, msg string) modules.Finding {
	return modules.Finding{Module: pushGatewayModule, Check: check, Severity: modules.SeverityOK, Message: msg}
}

// pushWarnFinding builds a SeverityWarning push-gateway finding.
func pushWarnFinding(check, msg string) modules.Finding {
	return modules.Finding{Module: pushGatewayModule, Check: check, Severity: modules.SeverityWarning, Message: msg}
}

// pushFatalFinding builds a SeverityFatal push-gateway finding.
func pushFatalFinding(check, msg string) modules.Finding {
	return modules.Finding{Module: pushGatewayModule, Check: check, Severity: modules.SeverityFatal, Message: msg}
}

// pushDeviceRecord is the minimal device record shape the push doctor checks
// need. It is a projection of device.Record to keep the push checks free of
// the full device.Record schema — only routing metadata (ID, Name, Platform,
// LastSeen, Revoked) and the ProviderToken (URL parse only, never logged; D-17)
// are needed.
type pushDeviceRecord struct {
	ID            string
	Name          string
	Platform      string // "unifiedpush" | "apns" | "fcm" — currently always "unifiedpush"
	ProviderToken string // secret-class: parsed for URL host only, never logged (D-17)
	LastSeen      time.Time
	Revoked       bool
}

// readPushDeviceRecords is a package-level var so tests can inject a stub
// device list without touching the real device store (same seam pattern as
// fetchDaemonStatus and deviceStorePath). The default implementation reads
// from the local device store via localDeviceEntries / device.New.
//
//nolint:gochecknoglobals // test seam, mirrors fetchDaemonStatus
var readPushDeviceRecords = func() []pushDeviceRecord {
	path, err := deviceStorePath()
	if err != nil {
		return nil
	}
	// Read-only: no audit writer or keychain needed.
	st := device.New(path, nil, nil, nil)
	recs := st.List()
	if len(recs) == 0 {
		return nil
	}
	out := make([]pushDeviceRecord, 0, len(recs))
	for _, r := range recs {
		// D-17: ProviderToken is read for URL parsing only; never logged.
		platform := r.Kind
		if platform == "" {
			platform = "unifiedpush" // Phase 28/29 default — all enrolled devices use UnifiedPush
		}
		out = append(out, pushDeviceRecord{
			ID:            r.ID,
			Name:          r.Name,
			Platform:      platform,
			ProviderToken: r.PushToken, // secret-class; treated as URL only in checks
			LastSeen:      r.LastSeen,
			Revoked:       r.Revoked,
		})
	}
	return out
}

// isPublicNtfyEndpoint returns true when the UnifiedPush endpoint URL routes
// through ntfy.sh or any subdomain (D-15 direction 1). It parses only the
// URL host — the full URL (ProviderToken) is never logged.
func isPublicNtfyEndpoint(endpointURL string) bool {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return false
	}
	host := u.Hostname() // strips port
	return strings.EqualFold(host, "ntfy.sh") || strings.HasSuffix(strings.ToLower(host), ".ntfy.sh")
}

// isPublicBind returns true when addr indicates a non-tailnet binding.
// Tailnet IPs are 100.x.x.x (CGNAT) or MagicDNS .ts.net hostnames.
// The fd7a: prefix covers the Tailscale IPv6 CGNAT range.
// This is a heuristic sufficient for a doctor WARN/FATAL gate (D-16).
func isPublicBind(addr string) bool {
	if strings.HasPrefix(addr, "0.0.0.0") {
		return true
	}
	if strings.HasPrefix(addr, "100.") {
		return false
	}
	if strings.HasPrefix(addr, "[fd7a:") || strings.Contains(addr, ".ts.net") {
		return false
	}
	// Any other non-empty address is non-tailnet: public IP, loopback via
	// localhost/127.x, LAN IP, etc. Loopback is also not tailnet-only and
	// should be flagged so the operator knows to bind the tailnet IP.
	return addr != ""
}

// fileCredPath returns the creds file path from cfg if any gateway leg is
// configured with creds_source: file, plus which leg uses it. Returns ("", "")
// when neither leg uses file creds.
func fileCredPath(cfg *config.Config) (path, leg string) {
	if cfg.Gateway.APNs.KeySource == "file" && cfg.Gateway.APNs.CredFilePath != "" {
		return cfg.Gateway.APNs.CredFilePath, "apns"
	}
	if cfg.Gateway.FCM.CredsSource == "file" && cfg.Gateway.FCM.CredFilePath != "" {
		return cfg.Gateway.FCM.CredFilePath, "fcm"
	}
	return "", ""
}

// userHomeDirFn is a package-level var so tests can inject a fake home
// directory for the cloud-sync location check without requiring the macOS
// sandbox to allow writes to ~/Library/Mobile Documents/.
//
//nolint:gochecknoglobals // test seam, mirrors fetchDaemonStatus
var userHomeDirFn = os.UserHomeDir

// cloudSyncedPrefixes returns the known cloud-synced directory prefixes
// relative to the user's home directory (D-04).
func cloudSyncedPrefixes(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, "Library", "Mobile Documents"), // iCloud Drive
		filepath.Join(homeDir, "Dropbox"),
		filepath.Join(homeDir, "OneDrive"),
		filepath.Join(homeDir, ".dropbox"),
	}
}

// checkCredsFilePerms checks that the given file exists and has mode 0600.
// Returns a FATAL finding on any failure, or an OK finding on success.
func checkCredsFilePerms(path string) modules.Finding {
	info, err := os.Stat(path)
	if err != nil {
		return pushFatalFinding("push-creds-file-perms",
			fmt.Sprintf("gateway creds file not found at %s", path))
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		return pushFatalFinding("push-creds-file-perms",
			fmt.Sprintf("gateway creds file mode is %04o — must be 0600 (chmod 600 %s)", perm, path))
	}
	if perm&0o044 != 0 {
		return pushFatalFinding("push-creds-file-perms",
			fmt.Sprintf("gateway creds file is group/world-readable (mode %04o) — chmod 600 %s", perm, path))
	}
	return pushOKFinding("push-creds-file-perms", "gateway creds file permissions OK (0600)")
}

// checkCredsFileLocation checks that the given path is not inside a known
// cloud-synced directory (D-04). Returns a FATAL finding if it is.
func checkCredsFileLocation(path string) modules.Finding {
	homeDir, err := userHomeDirFn()
	if err != nil {
		// If we cannot determine home dir, report OK rather than false-FATAL.
		return pushOKFinding("push-creds-file-location", "gateway creds file location OK")
	}
	for _, prefix := range cloudSyncedPrefixes(homeDir) {
		// Use filepath.Rel to check containment safely (boundary-aware).
		rel, rerr := filepath.Rel(prefix, path)
		if rerr == nil && !strings.HasPrefix(rel, "..") {
			return pushFatalFinding("push-creds-file-location",
				fmt.Sprintf("gateway creds file is in a cloud-synced directory (%s) — credentials may be uploaded to cloud; move to ~/.local/state/abysslink/", path))
		}
	}
	return pushOKFinding("push-creds-file-location", "gateway creds file location OK")
}

// contentStoreBind returns the string value of the daemon's content_store field
// for the bind check. Returns "" if not set.
func contentStoreBind(extras *statusDaemonExtras) string {
	if extras == nil || len(extras.ContentStore) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(extras.ContentStore, &s); err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(s, "listening on "))
}

// pushCredsKeychainFinding converts the daemon's gateway_creds_status field
// into a push-creds-keychain finding (check 1). daemonErr non-nil → WARN
// (daemon unreachable); status "ok" → OK; "unavailable" → WARN; "" (older
// daemon) → OK with an honest "unknown" label.
func pushCredsKeychainFinding(extras *statusDaemonExtras, daemonErr error) modules.Finding {
	if daemonErr != nil || extras == nil {
		return pushWarnFinding("push-creds-keychain",
			"abysslinkd not reachable — cannot verify gateway creds from daemon context (start it: abysslink daemon enable --apply)")
	}
	switch extras.GatewayCredsStatus {
	case "ok":
		return pushOKFinding("push-creds-keychain", "gateway credentials loaded successfully")
	case "unavailable":
		return pushWarnFinding("push-creds-keychain",
			"gateway credentials are not loaded in daemon context — push delivery will fail (check creds_source configuration)")
	default:
		return pushOKFinding("push-creds-keychain",
			"gateway-creds-unknown: daemon reachable but did not report creds status (older daemon)")
	}
}

// pushContentStoreBindFinding converts the daemon's content_store field into a
// push-contentstore-bind finding (check 10). FATAL when bound to a public
// address; OK when bound to a tailnet address; WARN when daemon unreachable.
func pushContentStoreBindFinding(extras *statusDaemonExtras, daemonErr error) modules.Finding {
	if daemonErr != nil || extras == nil {
		return pushWarnFinding("push-contentstore-bind",
			"abysslinkd not reachable — cannot verify content-store bind address (start it: abysslink daemon enable --apply)")
	}
	bindLabel := contentStoreBind(extras)
	if bindLabel == "" {
		return pushOKFinding("push-contentstore-bind",
			"content-store bind address unknown (daemon did not report; older daemon or content store disabled)")
	}
	// A content store that fail-closed and disabled itself (BACK-06: it could not
	// confirm its bind address is the tailnet IP, so it refused to bind anywhere)
	// reports a "disabled: <reason>" STATUS string, not a bind address. That is
	// the SAFE state — nothing is exposed — so it must not be mistaken for a
	// public bind: feeding the status string to isPublicBind would FATAL it
	// (every non-tailnet non-empty string reads as public). The advisory lives in
	// the separate content-store-disabled check; here it is simply not an
	// exposure. Fixes the false "bound to a public address (disabled: …)" FATAL.
	if strings.HasPrefix(bindLabel, "disabled") {
		return pushOKFinding("push-contentstore-bind",
			"content store is disabled (not bound to any address) — no public exposure; see the content-store check to enable it")
	}
	if isPublicBind(bindLabel) {
		return pushFatalFinding("push-contentstore-bind",
			fmt.Sprintf("content store is bound to a public address (%s) — MUST bind to the tailnet IP only; restart abysslinkd with correct content_store.bind_addr", bindLabel))
	}
	return pushOKFinding("push-contentstore-bind",
		fmt.Sprintf("content store is bound to the tailnet address (%s) — OK", bindLabel))
}

// pushDeviceFindings returns the device-store–derived findings: push-stale-tokens
// (check 7) and push-unifiedpush-ntfysh (check 8). Both read from devRecs;
// neither logs ProviderToken (D-17).
func pushDeviceFindings(devRecs []pushDeviceRecord) []modules.Finding {
	var findings []modules.Finding
	now := time.Now()
	cutoff := now.Add(-pushStaleDuration)

	var staleFound, ntfyShFound bool
	for _, r := range devRecs {
		if r.Revoked {
			continue
		}
		// Check 7: stale token.
		if !r.LastSeen.IsZero() && r.LastSeen.Before(cutoff) {
			findings = append(findings, pushWarnFinding("push-stale-tokens",
				fmt.Sprintf("device %s last seen %s ago — push token may be stale; re-enroll or revoke: abysslink enroll phone --revoke %s",
					r.Name, humanizeSince(now, r.LastSeen), r.Name)))
			staleFound = true
		}
		// Check 8: ntfy.sh endpoint — D-17: URL host only, token never logged.
		if !ntfyShFound && r.Platform == "unifiedpush" && isPublicNtfyEndpoint(r.ProviderToken) {
			findings = append(findings, pushWarnFinding("push-unifiedpush-ntfysh",
				fmt.Sprintf("UnifiedPush endpoint for device %q routes through ntfy.sh (a third party) — wake titles are visible to ntfy.sh; use a self-hosted ntfy server for sovereignty", r.Name)))
			ntfyShFound = true
		}
	}
	if !staleFound {
		findings = append(findings, pushOKFinding("push-stale-tokens", "no stale device push tokens"))
	}
	if !ntfyShFound {
		findings = append(findings, pushOKFinding("push-unifiedpush-ntfysh",
			"UnifiedPush endpoints are self-hosted (sovereign)"))
	}
	return findings
}

// pushConfigFindings returns the config-derived findings: push-creds-file-perms
// (check 2), push-creds-file-location (check 3), push-apns-experimental (check 4),
// push-fcm-experimental (check 5), push-apns-bundle-missing (check 6), and
// push-ios-unifiedpush-gap (check 9). None requires a daemon round-trip.
func pushConfigFindings(cfg *config.Config) []modules.Finding {
	var findings []modules.Finding

	// Checks 2 & 3: file-based creds (only when configured).
	if credPath, _ := fileCredPath(cfg); credPath != "" {
		findings = append(findings, checkCredsFilePerms(credPath))
		findings = append(findings, checkCredsFileLocation(credPath))
	}

	// Check 4: APNs experimental flag.
	if cfg.Gateway.APNs.Enabled {
		findings = append(findings, pushWarnFinding("push-apns-experimental",
			"APNs push leg is enabled and experimental — the v5 mobile app receiver has not yet shipped; deliveries will fail without the NSE installed"))
	} else {
		findings = append(findings, pushOKFinding("push-apns-experimental",
			"APNs leg is disabled (default — experimental until v5 app ships)"))
	}

	// Check 5: FCM experimental flag.
	if cfg.Gateway.FCM.Enabled {
		findings = append(findings, pushWarnFinding("push-fcm-experimental",
			"FCM push leg is enabled and experimental — the v5 mobile app receiver has not yet shipped; deliveries will fail without the FCM receiver installed"))
	} else {
		findings = append(findings, pushOKFinding("push-fcm-experimental",
			"FCM leg is disabled (default — experimental until v5 app ships)"))
	}

	// Check 6: bundle_id required when APNs enabled (runtime gate, schema also rejects).
	if cfg.Gateway.APNs.Enabled && cfg.Gateway.APNs.BundleID == "" {
		findings = append(findings, pushFatalFinding("push-apns-bundle-missing",
			"APNs is enabled but notify.gateway.apns.bundle_id is empty — set it to your app's bundle identifier (e.g. dev.abysslink.app)"))
	}

	// Check 9: iOS UnifiedPush gap (D-15 direction 2).
	if cfg.Gateway.UnifiedPush.Enabled && !cfg.Gateway.APNs.Enabled {
		findings = append(findings, pushWarnFinding("push-ios-unifiedpush-gap",
			"UnifiedPush (sovereign path) does NOT cover iOS — iOS requires the APNs leg (or ntfy.sh relay). Enable notify.gateway.apns if you need iOS wake delivery."))
	}

	return findings
}

// pushGatewayDoctorFindings runs the 10 push-gateway doctor checks and returns
// their findings. It is called from collectDoctorFindings after
// contentStoreDoctorFindings. The checks are:
//
//  1. push-creds-keychain — queries daemon via unix socket for gateway_creds_status
//  2. push-creds-file-perms — FATAL when creds file mode != 0600 (D-04)
//  3. push-creds-file-location — FATAL when creds in cloud-synced dir (D-04)
//  4. push-apns-experimental — WARN when APNs leg enabled (D-14)
//  5. push-fcm-experimental — WARN when FCM leg enabled (D-14)
//  6. push-apns-bundle-missing — FATAL when APNs enabled + bundle_id empty (Q1)
//  7. push-stale-tokens — WARN when any device last_seen > 30 days (D-12)
//  8. push-unifiedpush-ntfysh — WARN when UP endpoint routes via ntfy.sh (D-15)
//  9. push-ios-unifiedpush-gap — WARN when UP enabled but APNs not (D-15)
//  10. push-contentstore-bind — FATAL when content store bound to public IP (D-16)
func pushGatewayDoctorFindings(ctx context.Context, cfg *config.Config) []modules.Finding {
	// Single daemon round-trip shared by checks 1 and 10.
	extras, daemonErr := fetchDaemonStatus(ctx)

	var findings []modules.Finding
	findings = append(findings, pushCredsKeychainFinding(extras, daemonErr))    // check 1
	findings = append(findings, pushConfigFindings(cfg)...)                     // checks 2–6 + 9
	findings = append(findings, pushDeviceFindings(readPushDeviceRecords())...) // checks 7–8
	findings = append(findings, pushContentStoreBindFinding(extras, daemonErr)) // check 10
	return findings
}
