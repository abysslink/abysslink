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
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"gopkg.in/yaml.v3"
)

// safeHostnamePat mirrors fleet.safeHostname (internal/fleet/fanout.go:38).
// Defined here to avoid config→fleet→config import cycle (RESEARCH.md Pitfall 4).
// Any change to this pattern MUST also be applied in internal/fleet/fanout.go:38.
var safeHostnamePat = regexp.MustCompile(`^[a-z0-9][a-z0-9\-.]{0,252}[a-z0-9]$`)

// safeUnixUserPat is the POSIX-portable username shape (useradd's default
// NAME_REGEX): lowercase letter or underscore first, then up to 31 letters,
// digits, underscores, or hyphens. identity.unix_user is interpolated into the
// hardened sshd drop-in (`AllowUsers %s`) and the tailnet ACL users array, so
// anything outside this charset — especially whitespace or newlines — would
// inject extra sshd directives or AllowUsers entries (security review W3).
var safeUnixUserPat = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidateUnixUser checks a UNIX username against the POSIX-portable pattern
// used by validateIdentity. It is exported so argv/file-render call sites
// (e.g. the ssh module's sshd drop-in writer) can re-check the value as a
// defense-in-depth guard, mirroring the ValidateHostname pattern.
//
// Unlike ValidateHostname, an empty string is rejected: every caller of this
// helper is about to interpolate the value somewhere a blank would be unsafe.
func ValidateUnixUser(user string) error {
	if !safeUnixUserPat.MatchString(user) {
		return fmt.Errorf("unix user %q is not a safe username — "+
			"must match %s (lowercase letters, digits, _ and -, no whitespace)",
			user, safeUnixUserPat.String())
	}
	return nil
}

// Config is the top-level abysslink.yaml structure.
type Config struct {
	Version    int         `yaml:"version"`
	Backend    Backend     `yaml:"backend"`
	Server     Server      `yaml:"server"`
	Rig        Rig         `yaml:"rig"`
	Rigs       []RigConfig `yaml:"rigs"`
	Identity   Identity    `yaml:"identity"`
	Tailnet    Tailnet     `yaml:"tailnet"`
	Mobile     Mobile      `yaml:"mobile"`
	Modules    Modules     `yaml:"modules"`
	ClaudeCode ClaudeCode  `yaml:"claudecode"`
	Power      Power       `yaml:"power"`
	Hardening  Hardening   `yaml:"hardening"`

	Observability Observability `yaml:"observability"`

	WebUI WebUIConfig `yaml:"webui"`

	SessionRegistry SessionRegistry `yaml:"session_registry"`

	ContentStore ContentStoreConfig `yaml:"content_store"`

	// Gateway holds the Phase 29 push-gateway configuration
	// (notify.gateway.* per SPEC §12). APNs and FCM default disabled (D-14);
	// UnifiedPush defaults enabled (D-18 sovereign path).
	Gateway GatewayConfig `yaml:"gateway"`
}

// Content-store defaults and bounds (Phase 28, BACK-06). The TTL bounds are a
// hard floor/ceiling enforced by ValidateContentStore: below 30s a phone on a
// flaky link cannot fetch before expiry; above 3600s bodies linger in daemon
// memory far past their usefulness.
const (
	// DefaultContentStorePort is the tailnet HTTPS content listener port used
	// when content_store.port is unset.
	DefaultContentStorePort = 2587
	// DefaultContentTTLSeconds is the token lifetime when content_store.ttl_seconds is unset.
	DefaultContentTTLSeconds = 600
	// MinContentTTLSeconds is the ttl_seconds floor.
	MinContentTTLSeconds = 30
	// MaxContentTTLSeconds is the ttl_seconds ceiling.
	MaxContentTTLSeconds = 3600

	// DefaultEnrollTTLSeconds is the first-contact bootstrap-token lifetime when
	// content_store.enroll_ttl_seconds is unset (BACK-09). It is SEPARATE from
	// and independent of the content TTL: the operator and phone are co-located
	// and scan immediately, so the default is short.
	DefaultEnrollTTLSeconds = 300
	// MinEnrollTTLSeconds is the enroll_ttl_seconds floor.
	MinEnrollTTLSeconds = 30
	// MaxEnrollTTLSeconds is the enroll_ttl_seconds ceiling.
	MaxEnrollTTLSeconds = 900
)

// ContentStoreConfig configures the Phase 28 tailnet-only HTTPS content store
// served by abysslinkd (BACK-06): token-keyed, TTL'd, memory-first bodies
// fetched by enrolled devices at GET /content/{token}.
//
// BindAddr, when set, MUST be a literal IP and is additionally required at
// runtime to equal the backend-resolved tailnet IP (the same fail-closed floor
// as observability.metrics.bind_addr, OBS-03) — never 0.0.0.0 or ::. An empty
// BindAddr binds the resolved tailnet IP directly.
type ContentStoreConfig struct {
	// Enabled defaults to true (set in Defaults). Setting it false disables
	// the content listener; wakes then carry only the fallback title (BACK-08).
	Enabled bool `yaml:"enabled"`
	// Port is the HTTPS listen port. Zero means DefaultContentStorePort (2587).
	Port int `yaml:"port,omitempty"`
	// TTLSeconds is the content-token lifetime. Zero means
	// DefaultContentTTLSeconds (600); non-zero values are clamped to
	// [30, 3600] by validation (rejected, not silently clamped).
	TTLSeconds int `yaml:"ttl_seconds,omitempty"`
	// EnrollTTLSeconds is the first-contact bootstrap-token lifetime (BACK-09).
	// Zero means DefaultEnrollTTLSeconds (300); non-zero values are clamped to
	// [30, 900] by validation (rejected, not silently clamped). It is SEPARATE
	// from and independent of TTLSeconds (the content TTL).
	EnrollTTLSeconds int `yaml:"enroll_ttl_seconds,omitempty"`
	// BindAddr optionally pins the bind IP. Must be a literal, non-wildcard
	// IP; at runtime it must equal the backend-resolved tailnet IP.
	BindAddr string `yaml:"bind_addr,omitempty"`
}

// EffectivePort returns the configured content-store port or the default 2587.
func (c ContentStoreConfig) EffectivePort() int {
	if c.Port > 0 {
		return c.Port
	}
	return DefaultContentStorePort
}

// EffectiveTTL returns the configured token TTL or the default 600s. Values
// outside the validated [30s, 3600s] range cannot reach here through Load
// (ValidateContentStore rejects them), but a programmatically-built config is
// still clamped defensively so the store never mints unbounded tokens.
func (c ContentStoreConfig) EffectiveTTL() time.Duration {
	if c.TTLSeconds == 0 {
		return DefaultContentTTLSeconds * time.Second
	}
	ttl := c.TTLSeconds
	if ttl < MinContentTTLSeconds {
		ttl = MinContentTTLSeconds
	}
	if ttl > MaxContentTTLSeconds {
		ttl = MaxContentTTLSeconds
	}
	return time.Duration(ttl) * time.Second
}

// EffectiveEnrollTTL returns the configured first-contact bootstrap-token TTL
// or the default 300s. Values outside the validated [30s, 900s] range cannot
// reach here through Load (ValidateContentStore rejects them), but a
// programmatically-built config is still clamped defensively so the store never
// mints an unbounded bootstrap token. It is independent of EffectiveTTL.
func (c ContentStoreConfig) EffectiveEnrollTTL() time.Duration {
	if c.EnrollTTLSeconds == 0 {
		return DefaultEnrollTTLSeconds * time.Second
	}
	ttl := c.EnrollTTLSeconds
	if ttl < MinEnrollTTLSeconds {
		ttl = MinEnrollTTLSeconds
	}
	if ttl > MaxEnrollTTLSeconds {
		ttl = MaxEnrollTTLSeconds
	}
	return time.Duration(ttl) * time.Second
}

// GatewayConfig holds the push-gateway configuration block (SPEC §12,
// notify.gateway.*). APNs and FCM are experimental and disabled by default
// (D-14); UnifiedPush/ntfy is the sovereign default-on path (D-18).
type GatewayConfig struct {
	APNs        APNsGatewayConfig        `yaml:"apns"`
	FCM         FCMGatewayConfig         `yaml:"fcm"`
	UnifiedPush UnifiedPushGatewayConfig `yaml:"unifiedpush"`
}

// APNsGatewayConfig configures the Apple Push Notification Service leg.
// APNs is EXPERIMENTAL and disabled by default (D-14). BundleID is required
// when Enabled is true (validation gate — research Q1; doctor FATAL in Plan 05).
// KeySource controls how the .p8 signing key is retrieved: "keychain" (default)
// or "file" (CredFilePath must be set).
type APNsGatewayConfig struct {
	Enabled      bool   `yaml:"enabled"`
	BundleID     string `yaml:"bundle_id,omitempty"`
	KeySource    string `yaml:"key_source,omitempty"`    // "keychain" | "file"
	CredFilePath string `yaml:"cred_file_path,omitempty"` // when key_source=file
}

// FCMGatewayConfig configures the Firebase Cloud Messaging HTTP v1 leg.
// FCM is EXPERIMENTAL and disabled by default (D-14).
// CredsSource controls how the GCP service-account JSON is retrieved:
// "keychain" (default) or "file" (CredFilePath must be set).
type FCMGatewayConfig struct {
	Enabled      bool   `yaml:"enabled"`
	CredsSource  string `yaml:"creds_source,omitempty"`  // "keychain" | "file"
	CredFilePath string `yaml:"cred_file_path,omitempty"` // when creds_source=file
}

// UnifiedPushGatewayConfig configures the UnifiedPush/ntfy sovereign leg.
// Enabled defaults to true (D-18): this is the default-on path for phone wake.
type UnifiedPushGatewayConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ValidateGateway validates the gateway configuration block (SPEC §12).
// Called by Validate; exported for doctor checks (Plan 05).
func ValidateGateway(cfg *Config) error {
	gw := &cfg.Gateway
	// APNs: bundle_id required when enabled (research Q1).
	if gw.APNs.Enabled && gw.APNs.BundleID == "" {
		return fmt.Errorf("config: gateway.apns.bundle_id must be set when notify.gateway.apns.enabled is true")
	}
	// APNs key_source: must be one of {"keychain","file"} when set; empty
	// means the default "keychain" (set by Defaults) and is also accepted.
	switch gw.APNs.KeySource {
	case "", "keychain", "file":
	default:
		return fmt.Errorf("config: gateway.apns.key_source %q must be keychain or file", gw.APNs.KeySource)
	}
	// FCM creds_source: must be one of {"keychain","file"} when set.
	switch gw.FCM.CredsSource {
	case "", "keychain", "file":
	default:
		return fmt.Errorf("config: gateway.fcm.creds_source %q must be keychain or file", gw.FCM.CredsSource)
	}
	return nil
}

// SessionRegistry configures the daemon-side tmux session registry (Phase 27,
// BACK-03): the tmux -CC control-mode attach, the list-panes poll cadence,
// and the needs_input heuristic knobs. Every timing field follows the
// zero-value-means-default idiom (the WatchModule pattern): 0 uses the
// compiled-in default noted on the field.
type SessionRegistry struct {
	Enabled bool `yaml:"enabled"`

	// IgnoreSessions lists session display names exempted from the
	// needs_input heuristic (D-07, key path session_registry.ignore_sessions).
	// Display names are acceptable here — it is user config, never routing.
	IgnoreSessions []string `yaml:"ignore_sessions,omitempty"`

	// IdleSecs is the no-output threshold before a prompt-shaped pane is
	// considered needs_input. Zero means the compiled-in default 30; the
	// registry clamps values below the 10s floor up to 10 (D-01).
	IdleSecs int `yaml:"idle_secs,omitempty"`

	// PollActiveSecs is the list-panes poll cadence while any pane is
	// active. Zero means the compiled-in default 5 (D-05).
	PollActiveSecs int `yaml:"poll_active_secs,omitempty"`

	// PollIdleSecs is the backed-off poll cadence when all panes are idle.
	// Zero means the compiled-in default 15 (D-05).
	PollIdleSecs int `yaml:"poll_idle_secs,omitempty"`

	// PromptRegex optionally extends the built-in prompt sentinel set
	// (D-02). It must compile (validated at load — T-27-12); empty means
	// sentinels only.
	PromptRegex string `yaml:"prompt_regex,omitempty"`

	// CooldownSecs is the per-(pane, kind) re-notify suppression window.
	// Zero means the compiled-in default 300 (D-08). Declared here so every
	// registry knob lives in one section; consumed by the daemon dispatcher
	// (plan 27-05).
	CooldownSecs int `yaml:"cooldown_secs,omitempty"`
}

// WebUIConfig configures the opt-in (//go:build webui, default OFF) browser
// dashboard served by abysslinkd over the tailnet (Phase 19, WEB-01/WEB-02).
// The zero value is the safe disabled state. BindAddr, when set, MUST bind to
// the tailnet IP only — never 0.0.0.0 or :: (WEB-02, enforced by ValidateWebUI).
// ReadOnly MUST be true; a false value is rejected by ValidateWebUI (the
// config-layer half of the two-layer read-only gate; the HTTP-layer half lives
// in the webui module).
type WebUIConfig struct {
	Enabled     bool   `yaml:"enabled"`                // default false — listener never starts unless explicitly opted in (WEB-01)
	BindAddr    string `yaml:"bind_addr,omitempty"`    // resolved to the tailnet IP at runtime when empty
	Port        int    `yaml:"port,omitempty"`         // default 0 → use 8443
	ReadOnly    bool   `yaml:"read_only"`              // MUST be true; false is rejected by ValidateWebUI (WEB-02)
	AllowNotify bool   `yaml:"allow_notify,omitempty"` // scaffolded, default false (WEB-05)
}

// Observability holds the metrics-server and daily-digest settings (Phase 18).
// All sub-fields default OFF; the zero value is the safe disabled state.
type Observability struct {
	Metrics ObservabilityMetrics `yaml:"metrics"`
	Digest  ObservabilityDigest  `yaml:"digest"`
}

// ObservabilityMetrics configures the in-process metrics HTTP exposition.
// BindAddr, when set, MUST bind to the tailnet IP only — never 0.0.0.0 or ::
// (OBS-03, enforced by ValidateObservability).
type ObservabilityMetrics struct {
	Enabled  bool   `yaml:"enabled"`
	BindAddr string `yaml:"bind_addr,omitempty"`
	Port     int    `yaml:"port,omitempty"`
}

// ObservabilityDigest configures the optional daily digest notification.
//
// Hour is a *int so the YAML zero value is distinguishable from an explicit
// "hour: 0" (midnight): nil means "unset, use the 08:00 default", while a
// non-nil 0 means midnight (NET-16). Valid range is 0–23, enforced by
// ValidateObservability.
type ObservabilityDigest struct {
	Enabled   bool   `yaml:"enabled"`
	Hour      *int   `yaml:"hour,omitempty"`
	NtfyTopic string `yaml:"ntfy_topic,omitempty"`
}

// Backend holds backend-selection settings (v2+). The Type field is
// "tailscale" for v1; future backends include "headscale" and "netbird".
type Backend struct {
	Type string `yaml:"type"` // "tailscale" is the default; set by Load normalizer
}

// HeadscaleServer holds configuration for a locally-provisioned Headscale server (v2+).
// All fields carry yaml: tags so KnownFields(true) strict-mode YAML accepts them.
type HeadscaleServer struct {
	// ServerURL is the public HTTPS URL of the Headscale instance (used in config.yaml server_url).
	ServerURL string `yaml:"server_url"`
	// BinaryPath is the install path for the headscale binary. Default: /usr/local/bin/headscale.
	BinaryPath string `yaml:"binary_path,omitempty"`
	// ConfigPath is the path to headscale's config.yaml. Default: /etc/headscale/config.yaml.
	ConfigPath string `yaml:"config_path,omitempty"`
	// DBPath is the path to headscale's SQLite database. Default: /var/lib/headscale/db.sqlite.
	DBPath string `yaml:"db_path,omitempty"`
	// ACME enables Let's Encrypt automatic cert (opt-in, D-05).
	ACME bool `yaml:"acme,omitempty"`
	// TLSCertPath is the path to the BYO TLS certificate (D-06).
	TLSCertPath string `yaml:"tls_cert_path,omitempty"`
	// TLSKeyPath is the path to the BYO TLS private key (D-06).
	TLSKeyPath string `yaml:"tls_key_path,omitempty"`
	// CertExpiryWarnDays is the days-before-expiry threshold for the hs-tls WARN check. Default: 30.
	CertExpiryWarnDays int `yaml:"cert_expiry_warn_days,omitempty"`
	// PreAuthKeyExpiry is the duration for newly-minted pre-auth keys. Default: "1h" (paranoid-safe, D-11).
	PreAuthKeyExpiry string `yaml:"pre_auth_key_expiry,omitempty"`
	// User is the Headscale user for pre-auth key creation.
	User string `yaml:"user,omitempty"`
}

// NetBirdServer holds configuration for a locally-provisioned NetBird server (v2+).
// All fields carry yaml: tags so KnownFields(true) strict-mode YAML accepts them.
// API key and setup key are NOT stored here — they live in the OS keychain only.
type NetBirdServer struct {
	// ServerURL is the management server base URL (e.g. https://nb.example.com).
	ServerURL string `yaml:"server_url"`
	// MgmtBindAddr is the management listen address. Paranoid default: 127.0.0.1:443.
	MgmtBindAddr string `yaml:"mgmt_bind_addr,omitempty"`
	// MetricsAddr is the metrics bind address. Paranoid default: 127.0.0.1:9090.
	MetricsAddr string `yaml:"metrics_addr,omitempty"`
	// BinaryPath is the path to the user-supplied netbird-server binary (PR-B).
	// Empty means not configured (Linux only; macOS uses container path per PR-A).
	BinaryPath string `yaml:"binary_path,omitempty"`
	// SetupKeyExpiry is the duration string for setup key TTL. Paranoid default: 24h.
	SetupKeyExpiry string `yaml:"setup_key_expiry,omitempty"`
	// AcceptNoSSHCheck is the persisted one-time opt-in for D-04 (--accept-no-sshcheck).
	// Default false — must be explicitly set to acknowledge SSHCheck degradation.
	AcceptNoSSHCheck bool `yaml:"accept_no_sshcheck,omitempty"`
	// TLSCertFile is the path to the BYO TLS certificate.
	TLSCertFile string `yaml:"tls_cert_file,omitempty"`
	// TLSKeyFile is the path to the BYO TLS private key.
	TLSKeyFile string `yaml:"tls_key_file,omitempty"`
	// ConfigPath is the path to netbird-server config.yaml. Default: /etc/netbird/config.yaml.
	ConfigPath string `yaml:"config_path,omitempty"`
}

// Server holds configuration for a self-hosted backend server (v2+).
type Server struct {
	Hostname  string          `yaml:"hostname"` // FQDN of the Headscale / NetBird server (kept for compat)
	Headscale HeadscaleServer `yaml:"headscale"`
	NetBird   NetBirdServer   `yaml:"netbird"`
}

// Rig is the legacy scalar per-rig stub (v1 compat alias).
// It is retained so that any existing abysslink.yaml with a rig: key continues
// to parse under KnownFields(true) strict mode (Open Question 3).
// New configurations should use the Rigs []RigConfig list instead.
type Rig struct {
	Name string `yaml:"name"` // logical rig name used in fleet commands
}

// RigConfig is a per-rig fleet record (Phase 14, D-FS-01).
// Every field carries a yaml: tag because KnownFields(true) strict mode at
// config.go:337 rejects untagged keys.
type RigConfig struct {
	Name      string `yaml:"name"`                // logical rig name; basis of keychain service + topic
	Hostname  string `yaml:"hostname"`            // Tailscale hostname (SSH target, D-FT-03)
	NtfyTopic string `yaml:"ntfy_topic"`          // abysslink-<name>-<8char> (D-NI-01)
	Backend   string `yaml:"backend"`             // backend type at enrollment
	LastSeen  string `yaml:"last_seen,omitempty"` // RFC3339 UTC; updated by fan-out status (Plan 05)
	MAC       string `yaml:"mac,omitempty"`       // hardware MAC for Wake-on-LAN (MOD3-01); empty disables WoL for this rig
}

// Identity holds the user's Tailscale and UNIX identifiers.
type Identity struct {
	Email    string `yaml:"email"`
	UnixUser string `yaml:"unix_user"`
}

// Tailnet holds per-rig Tailscale configuration.
type Tailnet struct {
	Hostname string       `yaml:"hostname"`
	SSH      bool         `yaml:"ssh"`
	Lock     TailnetLock  `yaml:"lock"`
	Admin    TailnetAdmin `yaml:"admin"`
}

// TailnetAdmin holds the non-secret admin-API settings used to push ACLs and
// mint auth keys. The OAuth client SECRET is never stored here — it is read at
// runtime from the ABYSSLINK_TS_OAUTH_SECRET environment variable (or keychain).
// When these fields are empty, the ACL module degrades to manual (clipboard +
// browser) mode.
type TailnetAdmin struct {
	Tailnet       string `yaml:"tailnet"`         // tailnet name, e.g. "you@github" or "-" for default
	OAuthClientID string `yaml:"oauth_client_id"` // NOT secret; the secret comes from env
}

// TailnetLock holds Tailnet Lock settings.
type TailnetLock struct {
	Enabled            bool `yaml:"enabled"`
	DisablementSecrets int  `yaml:"disablement_secrets"`
	ShareWithSupport   bool `yaml:"share_with_support"`
}

// Mobile holds settings for the enrolled phone device.
type Mobile struct {
	Tag            string   `yaml:"tag"`
	Ports          []string `yaml:"ports"`
	SSHCheckPeriod string   `yaml:"ssh_check_period"`
}

// SSHModule configures the SSH integration.
type SSHModule struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"`
}

// TmuxModule configures the tmux integration.
type TmuxModule struct {
	Enabled bool   `yaml:"enabled"`
	Session string `yaml:"session"`
}

// BasicModule is a module with only an enabled flag.
type BasicModule struct {
	Enabled bool `yaml:"enabled"`
}

// NtfyModule configures the ntfy push-notification server.
type NtfyModule struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port,omitempty"` // 0 means use default (2586)
}

// ListenPort returns the configured port or the safe default (2586).
func (m NtfyModule) ListenPort() int {
	if m.Port > 0 {
		return m.Port
	}
	return 2586
}

// NotifyModule configures the generic notification API.
type NotifyModule struct {
	Enabled      bool   `yaml:"enabled"`
	DefaultTopic string `yaml:"default_topic"`
}

// WatchModule configures the watchers run by abysslinkd.
type WatchModule struct {
	Enabled bool        `yaml:"enabled"`
	Panes   []string    `yaml:"panes"`
	Files   []FileWatch `yaml:"files,omitempty"`
	HTTP    []HTTPWatch `yaml:"http,omitempty"`

	// Pane watcher timing. Zero values use the compiled-in defaults
	// (poll 5s, idle 30s, cool-off 300s).
	PanePollSecs    int `yaml:"pane_poll_secs,omitempty"`
	PaneIdleSecs    int `yaml:"pane_idle_secs,omitempty"`
	PaneCoolOffSecs int `yaml:"pane_cool_off_secs,omitempty"`
}

// FileWatch notifies when a line appended to Path matches Grep (a regexp).
type FileWatch struct {
	Path     string `yaml:"path"`
	Grep     string `yaml:"grep"`
	Label    string `yaml:"label,omitempty"`
	PollSecs int    `yaml:"poll_secs,omitempty"` // default 2
}

// HTTPWatch notifies when GET URL's status code changes from Expect (or from
// the previous observation when Expect is 0). IntervalSecs defaults to 60.
type HTTPWatch struct {
	URL          string `yaml:"url"`
	Expect       int    `yaml:"expect,omitempty"`
	Label        string `yaml:"label,omitempty"`
	IntervalSecs int    `yaml:"interval_secs,omitempty"`
}

// Modules groups all module configurations.
type Modules struct {
	SSH             SSHModule    `yaml:"ssh"`
	Tmux            TmuxModule   `yaml:"tmux"`
	Mosh            BasicModule  `yaml:"mosh"`
	Notify          NotifyModule `yaml:"notify"`
	Ntfy            NtfyModule   `yaml:"ntfy"`
	Watch           WatchModule  `yaml:"watch"`
	CodeServer      BasicModule  `yaml:"code_server"`
	Ttyd            BasicModule  `yaml:"ttyd"`
	Syncthing       BasicModule  `yaml:"syncthing"`
	Upsnap          BasicModule  `yaml:"upsnap"`
	EternalTerminal BasicModule  `yaml:"eternal_terminal"`
	Atuin           BasicModule  `yaml:"atuin"`
	Sandbox         BasicModule  `yaml:"sandbox"`
	Asciinema       BasicModule  `yaml:"asciinema"`
}

// ClaudeCodeNotifyOn controls which Claude Code events trigger a notification.
type ClaudeCodeNotifyOn struct {
	Notification bool   `yaml:"notification"`
	StopAfter    string `yaml:"stop_after"`
}

// ClaudeCode wires the optional Claude Code hook consumer.
type ClaudeCode struct {
	Enabled      bool               `yaml:"enabled"`
	APIKeySource string             `yaml:"api_key_source"`
	NotifyOn     ClaudeCodeNotifyOn `yaml:"notify_on"`
}

// Power holds power-management settings.
type Power struct {
	ClosedLidAC string `yaml:"closed_lid_ac"`
}

// Hardening holds OS hardening assertions.
type Hardening struct {
	FileVault        string `yaml:"filevault"`
	LUKS             string `yaml:"luks"`
	FirewallStealth  bool   `yaml:"firewall_stealth"`
	UFWDefaultDeny   bool   `yaml:"ufw_default_deny"`
	DisableMacOSSSHD bool   `yaml:"disable_macos_sshd"`
}

// Defaults returns a Config populated with all safe defaults from DESIGN.md §4.2.
func Defaults() *Config {
	return &Config{
		Version: 1,
		Server: Server{
			Headscale: HeadscaleServer{
				BinaryPath:         "/usr/local/bin/headscale",
				ConfigPath:         "/etc/headscale/config.yaml",
				DBPath:             "/var/lib/headscale/db.sqlite",
				CertExpiryWarnDays: 30,
				PreAuthKeyExpiry:   "1h",
			},
			NetBird: NetBirdServer{
				MgmtBindAddr:   "127.0.0.1:443",
				MetricsAddr:    "127.0.0.1:9090",
				SetupKeyExpiry: "24h",
				ConfigPath:     "/etc/netbird/config.yaml",
			},
		},
		Tailnet: Tailnet{
			SSH: true,
			Lock: TailnetLock{
				Enabled:            true,
				DisablementSecrets: 2,
				ShareWithSupport:   false,
			},
		},
		Mobile: Mobile{
			Tag:            "mobile",
			Ports:          []string{"tcp/22", "udp/60000-61000"},
			SSHCheckPeriod: "12h",
		},
		Modules: Modules{
			SSH:    SSHModule{Enabled: true, Mode: "tailscale"},
			Tmux:   TmuxModule{Enabled: true, Session: "main"},
			Mosh:   BasicModule{Enabled: true},
			Notify: NotifyModule{Enabled: true, DefaultTopic: "rig"},
			Ntfy:   NtfyModule{Enabled: true, Port: 2586},
			Watch:  WatchModule{Enabled: true, Panes: []string{"main"}},
		},
		ClaudeCode: ClaudeCode{
			Enabled:      false,
			APIKeySource: "keychain",
			NotifyOn: ClaudeCodeNotifyOn{
				Notification: true,
				StopAfter:    "60s",
			},
		},
		Power: Power{
			ClosedLidAC: "keep-awake",
		},
		Hardening: Hardening{
			FileVault:        "required",
			LUKS:             "required",
			FirewallStealth:  true,
			UFWDefaultDeny:   true,
			DisableMacOSSSHD: true,
		},
		WebUI: WebUIConfig{
			ReadOnly: true,
			Port:     8443,
		},
		SessionRegistry: SessionRegistry{Enabled: true},
		ContentStore: ContentStoreConfig{
			Enabled:    true,
			Port:       DefaultContentStorePort,
			TTLSeconds: DefaultContentTTLSeconds,
		},
		// Gateway defaults (SPEC §12, D-14, D-18):
		//   APNs and FCM are experimental — disabled by default.
		//   UnifiedPush/ntfy is the sovereign path — enabled by default.
		//   KeySource and CredsSource default to "keychain" (OS keychain, most secure).
		Gateway: GatewayConfig{
			APNs: APNsGatewayConfig{
				Enabled:   false,
				KeySource: "keychain",
			},
			FCM: FCMGatewayConfig{
				Enabled:     false,
				CredsSource: "keychain",
			},
			UnifiedPush: UnifiedPushGatewayConfig{
				Enabled: true,
			},
		},
	}
}

// Load reads path, decodes YAML strictly (unknown keys are rejected), and
// returns the parsed Config. Default values are applied for omitted fields.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the resolved abysslink config file path, not user-controlled at this layer
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // errcheck: close error on read-only/append file handle is non-actionable; data durability handled by explicit Sync where required

	cfg := Defaults()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		// An empty file yields io.EOF from the YAML decoder — give the user an
		// actionable message instead of a bare decode error.
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config: config file %s is empty — run `abysslink init` to generate one", path)
		}
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	// Normalize: a v1 tailnet:-only config has no backend: stanza, so
	// Backend.Type is "". Default it to "tailscale" (Pitfall 4 alias).
	if cfg.Backend.Type == "" {
		cfg.Backend.Type = "tailscale"
	}
	// D-01 (fail-closed): validate before returning. A hand-edited YAML with an
	// unsafe hostname or non-https NetBird URL must never reach argv call sites.
	// The file path is included so the user knows WHICH config failed when
	// several candidates exist (--config flag, $ABYSSLINK_CONFIG, default path).
	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// LoadForRead is the READ-ONLY counterpart to Load (WR-07). It parses path and
// applies defaults exactly like Load, but on a validation failure it returns the
// parsed config together with the validation error instead of discarding the
// config. Callers that never feed config values to argv or a mutation — e.g.
// `rig ls` and `rig export`, which only render cfg.Rigs — can inspect the parsed
// config while still being able to log the validation problem.
//
// SECURITY: LoadForRead must NEVER be used by a path that writes config or feeds
// a config value to an external command. The fail-closed Load remains the only
// entry point for mutating/argv paths (D-01). The returned error is non-nil
// precisely when validation failed, so callers can choose to warn-and-continue
// (read-only) or abort.
func LoadForRead(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the resolved abysslink config file path, not user-controlled at this layer
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // errcheck: close error on read-only file handle is non-actionable

	cfg := Defaults()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config: config file %s is empty — run `abysslink init` to generate one", path)
		}
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	if cfg.Backend.Type == "" {
		cfg.Backend.Type = "tailscale"
	}
	// Return the parsed config ALONGSIDE any validation error: a parse/decode
	// failure is still fatal (nil config above), but a pure validation failure
	// leaves a usable config for read-only rendering. The path is included so
	// the warn-and-continue log identifies which file failed validation.
	if verr := Validate(cfg); verr != nil {
		return cfg, fmt.Errorf("%s: %w", path, verr)
	}
	return cfg, nil
}

// Marshal encodes cfg to canonical YAML bytes. It is the single source of
// truth for the YAML representation used by both Write and the config preview
// in cmd_init.go — keeping them byte-faithful to each other.
func Marshal(cfg *Config) ([]byte, error) {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("config: marshal: %w", err)
	}
	return data, nil
}

// Write marshals cfg to YAML and writes it atomically via audit (backup + rename).
func Write(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: create directory: %w", err)
	}

	data, err := Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: write: %w", err)
	}

	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("config: audit log path: %w", err)
	}
	if err := audit.New(logPath).WriteFile(path, data, 0o600, false); err != nil {
		return fmt.Errorf("config: write: %w", err)
	}
	return nil
}

// Validate checks that cfg contains internally consistent, safe values.
func Validate(cfg *Config) error {
	if cfg.Version != 1 {
		return fmt.Errorf("config: unsupported version %d (only 1 is supported)", cfg.Version)
	}
	if err := validateIdentity(cfg); err != nil {
		return err
	}
	checkPeriod, err := time.ParseDuration(cfg.Mobile.SSHCheckPeriod)
	if err != nil {
		return fmt.Errorf("config: mobile.ssh_check_period %q is not a valid duration: %w", cfg.Mobile.SSHCheckPeriod, err)
	}
	if checkPeriod < time.Minute || checkPeriod > 168*time.Hour {
		return fmt.Errorf("config: mobile.ssh_check_period %q must be between 1m and 168h", cfg.Mobile.SSHCheckPeriod)
	}
	switch cfg.Modules.SSH.Mode {
	case "tailscale", "openssh-fallback":
	default:
		return fmt.Errorf("config: modules.ssh.mode %q must be tailscale or openssh-fallback", cfg.Modules.SSH.Mode)
	}
	switch cfg.ClaudeCode.APIKeySource {
	case "keychain", "env", "none":
	default:
		return fmt.Errorf("config: claudecode.api_key_source %q must be keychain, env, or none", cfg.ClaudeCode.APIKeySource)
	}
	if cfg.ClaudeCode.NotifyOn.StopAfter != "" {
		stopAfter, err := time.ParseDuration(cfg.ClaudeCode.NotifyOn.StopAfter)
		if err != nil {
			return fmt.Errorf("config: claudecode.notify_on.stop_after %q is not a valid duration: %w", cfg.ClaudeCode.NotifyOn.StopAfter, err)
		}
		if stopAfter < 30*time.Second {
			return fmt.Errorf("config: claudecode.notify_on.stop_after %q must be at least 30s to avoid chatty notifications", cfg.ClaudeCode.NotifyOn.StopAfter)
		}
	}
	for _, validate := range []func(*Config) error{
		validateBackend,
		ValidateObservability,
		ValidateWebUI,
		validateWatchPanes,
		validateSessionRegistry,
		ValidateContentStore,
		ValidateGateway,
	} {
		if err := validate(cfg); err != nil {
			return err
		}
	}
	return nil
}

// ValidateHostname is an exported defense-in-depth helper for D-03 argv-site
// guards. It checks a single hostname string against the DNS-safe pattern used
// by validateIdentity and fleet.safeHostname. It is separate from Validate so
// that code that constructs Config structs programmatically (tests, fleet fan-
// out, future paths) can re-check just the hostname before passing it as a
// --hostname= argv token.
//
// Rules:
//   - Empty string → nil (empty means "not set"; caller decides default).
//   - Non-empty string that matches safeHostnamePat → nil.
//   - Non-empty string that does NOT match → descriptive error.
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return nil
	}
	if !safeHostnamePat.MatchString(hostname) {
		return fmt.Errorf("hostname %q contains unsafe characters: "+
			"must match DNS-safe pattern (no leading dashes, ASCII letters/digits/hyphens only)",
			hostname)
	}
	return nil
}

// ValidateWebUI enforces the WEB-02 hard floor for the opt-in web dashboard.
// It is the config-layer half of the two-layer read-only gate. Two checks fire:
//
//   - The bind address, when set, MUST bind to the tailnet IP only. A bind_addr
//     that is unspecified (0.0.0.0 or ::) would expose the dashboard on every
//     interface (Information Disclosure, T-19-01), so it is rejected with the
//     same FATAL error class as the metrics/Funnel rejections. This check
//     applies even when webui.enabled is false (mirrors the metrics pattern); an
//     empty bind_addr is resolved at runtime to the tailnet IP and is accepted.
//   - When webui.enabled is true, read_only MUST be true. A false value would
//     unlock mutations through the dashboard (Tampering, T-19-01), so it is
//     rejected fatally.
//
// It is exported so the daemon can enforce the floor at the point the webui
// listener starts, independently of whether the global Validate is wired into
// the config load path.
func ValidateWebUI(cfg *Config) error {
	if addr := cfg.WebUI.BindAddr; addr != "" && IsUnspecifiedBindAddr(addr) {
		return fmt.Errorf("config: webui.bind_addr %q must not be 0.0.0.0 or :: — webui must bind to the tailnet IP only (WEB-02)", addr)
	}
	if cfg.WebUI.Enabled && !cfg.WebUI.ReadOnly {
		return fmt.Errorf("config: webui.read_only must be true — mutations are disabled in the web UI (WEB-02)")
	}
	return nil
}

// validateIdentity enforces the required identity and tailnet fields. It is
// split out of Validate to keep that function's cyclomatic complexity within
// the golangci gocyclo budget.
func validateIdentity(cfg *Config) error {
	if cfg.Identity.Email == "" {
		return fmt.Errorf("config: identity.email is required")
	}
	if !strings.Contains(cfg.Identity.Email, "@") {
		return fmt.Errorf("config: identity.email %q is not a valid email address", cfg.Identity.Email)
	}
	if cfg.Identity.UnixUser == "" {
		return fmt.Errorf("config: identity.unix_user is required")
	}
	// W3: unix_user flows into the sshd drop-in (`AllowUsers %s`) and the
	// tailnet ACL — reject anything that could smuggle extra directives.
	if err := ValidateUnixUser(cfg.Identity.UnixUser); err != nil {
		return fmt.Errorf("config: identity.unix_user: %w", err)
	}
	if cfg.Tailnet.Hostname == "" {
		return fmt.Errorf("config: tailnet.hostname is required")
	}
	if !safeHostnamePat.MatchString(cfg.Tailnet.Hostname) {
		return fmt.Errorf("config: tailnet.hostname %q is not a valid hostname — "+
			"only [a-z0-9] and internal hyphens/dots allowed, no leading dash (A8)",
			cfg.Tailnet.Hostname)
	}
	return nil
}

// ValidateObservability enforces the OBS-03 hard floor: when the metrics
// exposition bind address is set, it MUST bind to the tailnet IP only. A
// bind_addr that is unspecified (0.0.0.0 or ::) would expose internal metrics
// on every interface (Information Disclosure, T-18-01), so it is rejected with
// the same FATAL error class as the Funnel/backend rejections. An empty
// bind_addr is resolved at runtime to the tailnet IP and is therefore accepted
// here.
//
// It is exported so the daemon can enforce the floor at the point the metrics
// listener starts (CR-02), independently of whether the global Validate is
// wired into the config load path.
func ValidateObservability(cfg *Config) error {
	if addr := cfg.Observability.Metrics.BindAddr; addr != "" && IsUnspecifiedBindAddr(addr) {
		return fmt.Errorf("config: observability.metrics.bind_addr %q must not be 0.0.0.0 or :: — metrics must bind to the tailnet IP only (OBS-03)", addr)
	}
	// NET-16: digest hour, when set, must be a wall-clock hour. nil means
	// "unset" (the daemon defaults to 08:00); 0 means midnight and is valid.
	if h := cfg.Observability.Digest.Hour; h != nil && (*h < 0 || *h > 23) {
		return fmt.Errorf("config: observability.digest.hour %d must be between 0 and 23", *h)
	}
	return nil
}

// ValidateContentStore enforces the BACK-06 bind floor on the content-store
// section at the config layer:
//
//   - bind_addr, when set, must be a literal IP (no host:port, no DNS name —
//     the runtime floor compares it against the backend-resolved tailnet IP,
//     which is always a literal IP) and must not be unspecified (0.0.0.0/::,
//     which would expose notification bodies on every interface).
//   - port, when set, must be a valid TCP port.
//   - ttl_seconds, when set, must sit within [30, 3600] (floor: a phone on a
//     flaky link needs time to fetch; ceiling: bodies must not linger in
//     daemon memory).
//
// It is exported so the daemon re-enforces the floor at the point the content
// listener starts (mirroring ValidateObservability / CR-02), independent of
// the Load-time Validate.
func ValidateContentStore(cfg *Config) error {
	if addr := cfg.ContentStore.BindAddr; addr != "" {
		if IsUnspecifiedBindAddr(addr) {
			return fmt.Errorf("config: content_store.bind_addr %q must not be 0.0.0.0 or :: — the content store must bind to the tailnet IP only (BACK-06)", addr)
		}
		if net.ParseIP(addr) == nil {
			return fmt.Errorf("config: content_store.bind_addr %q must be a literal IP address (no port, no DNS name) — it is matched against the backend-resolved tailnet IP at runtime (BACK-06)", addr)
		}
	}
	if p := cfg.ContentStore.Port; p < 0 || p > 65535 {
		return fmt.Errorf("config: content_store.port %d must be between 1 and 65535 (0 means default %d)", p, DefaultContentStorePort)
	}
	if ttl := cfg.ContentStore.TTLSeconds; ttl != 0 && (ttl < MinContentTTLSeconds || ttl > MaxContentTTLSeconds) {
		return fmt.Errorf("config: content_store.ttl_seconds %d must be between %d and %d (0 means default %d)",
			ttl, MinContentTTLSeconds, MaxContentTTLSeconds, DefaultContentTTLSeconds)
	}
	if ttl := cfg.ContentStore.EnrollTTLSeconds; ttl != 0 && (ttl < MinEnrollTTLSeconds || ttl > MaxEnrollTTLSeconds) {
		return fmt.Errorf("config: content_store.enroll_ttl_seconds %d must be between %d and %d (0 means default %d)",
			ttl, MinEnrollTTLSeconds, MaxEnrollTTLSeconds, DefaultEnrollTTLSeconds)
	}
	return nil
}

// DefaultWebUIPort is the TLS listen port used when webui.port is unset. It is
// the single source of truth shared by the webui listener (resolveWebUIAddr)
// and the doctor live probe (webuiProbeURL) so the two never disagree about the
// effective port (WR-03).
const DefaultWebUIPort = 8443

// EffectiveWebUIHostPort resolves the host and port the webui listener and the
// doctor probe MUST agree on, given only the config (no tailnet-IP resolution,
// which is done at the listener seam). Precedence (single source of truth, WR-03):
//
//   - If bind_addr carries an embedded port (host:port / [host]:port), that port
//     wins and the embedded host is returned. This matches the listener, which
//     honors an embedded port verbatim.
//   - Otherwise the host is bind_addr's bare host (possibly empty, meaning
//     "resolve to the tailnet IP at runtime") and the port is webui.port, or
//     DefaultWebUIPort when unset.
//
// Returning both pieces (rather than two independent resolvers) is what keeps
// the doctor probe targeting the same port the listener actually binds.
func EffectiveWebUIHostPort(cfg *Config) (host string, port int) {
	host = BindAddrHost(cfg.WebUI.BindAddr)
	if _, portStr, err := net.SplitHostPort(cfg.WebUI.BindAddr); err == nil {
		if p, perr := strconv.Atoi(portStr); perr == nil {
			return host, p
		}
	}
	port = cfg.WebUI.Port
	if port <= 0 {
		port = DefaultWebUIPort
	}
	return host, port
}

// IsUnspecifiedBindAddr reports whether addr's host part is an unspecified
// (wildcard) address — IPv4 0.0.0.0 or IPv6 :: — which would expose the
// metrics endpoint on every interface (OBS-03, Information Disclosure).
//
// It parses the host rather than substring-matching, so legitimate IPv6
// tailnet ULA addresses (e.g. fd7a:115c:a1e0::1234, which contain "::" as a
// zero-run abbreviation) are NOT wrongly rejected — only the truly
// unspecified addresses 0.0.0.0 and :: are. addr may be "host:port",
// "[host]:port", or a bare host; a bare/un-splittable value is treated as the
// host itself. A non-IP host (e.g. a DNS name) is not unspecified.
func IsUnspecifiedBindAddr(addr string) bool {
	ip := net.ParseIP(BindAddrHost(addr))
	return ip != nil && ip.IsUnspecified()
}

// BindAddrHost extracts the host part of a bind address that may be "host:port",
// "[host]:port", or a bare host. A bare/un-splittable value (including a
// bracketed host without a port) is treated as the host itself, with any
// surrounding brackets stripped so "[::1]" yields "::1". It is exported so the
// doctor metrics-bind-tailnet check can apply the same OBS-03 tailnet-IP-match
// predicate the daemon enforces at the listener seam (WR-01).
func BindAddrHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
}

// validateBackend enforces backend-specific config invariants.
//
// Headscale: the API key and minted pre-auth key flow in the Authorization:
// Bearer header on every REST call, so server_url MUST be https:// — plaintext
// http would leak those secrets (CR-04). This guards hand-written configs and
// the --yes / non-TTY init paths that bypass the interactive HTTPS prompt.
//
// NetBird: server_url is required when backend.type == "netbird"; without it
// the adapter cannot construct any REST endpoint URL (NB-01/NB-02).
func validateBackend(cfg *Config) error {
	if cfg.Backend.Type == "headscale" {
		if !strings.HasPrefix(cfg.Server.Headscale.ServerURL, "https://") {
			return fmt.Errorf("config: server.headscale.server_url %q must use https:// — plaintext http would leak the API key and pre-auth key", cfg.Server.Headscale.ServerURL)
		}
	}
	if cfg.Backend.Type == "netbird" {
		if cfg.Server.NetBird.ServerURL == "" {
			return fmt.Errorf("config: server.netbird.server_url is required when backend.type is %q", cfg.Backend.Type)
		}
		if !strings.HasPrefix(cfg.Server.NetBird.ServerURL, "https://") {
			return fmt.Errorf("config: server.netbird.server_url %q must use https:// — "+
				"plaintext http would leak the NetBird PAT on every REST call (A7)",
				cfg.Server.NetBird.ServerURL)
		}
	}
	for _, rawURL := range []string{cfg.Server.Headscale.ServerURL, cfg.Server.NetBird.ServerURL} {
		if rawURL == "" {
			continue
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Hostname() == "" {
			return fmt.Errorf("config: server_url %q is not a valid URL", rawURL)
		}
		if !safeHostnamePat.MatchString(u.Hostname()) {
			return fmt.Errorf("config: server_url hostname %q is invalid — "+
				"only DNS-safe chars allowed; leading dash rejects flag injection (A8)", u.Hostname())
		}
	}
	return nil
}

// validateWatchPanes enforces that every tmux pane name in cfg.Modules.Watch.Panes passes
// the DNS-safe charset gate (D-06/NET-03). Each pane name is passed verbatim to
// `tmux capture-pane -t <pane>` by the daemon (daemon/server.go:333); a value beginning
// with `-` would be parsed as a tmux flag (A8 — same class as tailscale hostname injection).
func validateWatchPanes(cfg *Config) error {
	for _, pane := range cfg.Modules.Watch.Panes {
		if !safeHostnamePat.MatchString(pane) {
			return fmt.Errorf("config: modules.watch.panes element %q is not a valid pane name — "+
				"only [a-z0-9] and internal hyphens/dots allowed, no leading dash (A8/NET-03)", pane)
		}
	}
	return nil
}

// validateSessionRegistry enforces that session_registry.prompt_regex
// compiles (T-27-12). User-supplied regex is compiled with regexp.Compile —
// never MustCompile — and rejected with a named-field error; Go's RE2 engine
// has no catastrophic backtracking, so a pattern that compiles is always safe
// to evaluate against pane content. The zero-value section is valid: every
// timing knob defaults downstream (the validateWatchPanes/WatchModule idiom).
func validateSessionRegistry(cfg *Config) error {
	if cfg.SessionRegistry.PromptRegex == "" {
		return nil
	}
	if _, err := regexp.Compile(cfg.SessionRegistry.PromptRegex); err != nil {
		return fmt.Errorf("config: session_registry.prompt_regex %q does not compile: %w",
			cfg.SessionRegistry.PromptRegex, err)
	}
	return nil
}
