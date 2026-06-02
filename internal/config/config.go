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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"gopkg.in/yaml.v3"
)

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
}

// WebUIConfig configures the opt-in (//go:build webui, default OFF) browser
// dashboard served by abysslinkd over the tailnet (Phase 19, WEB-01/WEB-02).
// The zero value is the safe disabled state. BindAddr, when set, MUST bind to
// the tailnet IP only — never 0.0.0.0 or :: (WEB-02, enforced by ValidateWebUI).
// ReadOnly MUST be true; a false value is rejected by ValidateWebUI (the
// config-layer half of the two-layer read-only gate; the HTTP-layer half lives
// in the webui module).
type WebUIConfig struct {
	Enabled     bool   `yaml:"enabled"`             // default false — listener never starts unless explicitly opted in (WEB-01)
	BindAddr    string `yaml:"bind_addr,omitempty"` // resolved to the tailnet IP at runtime when empty
	Port        int    `yaml:"port,omitempty"`      // default 0 → use 8443
	ReadOnly    bool   `yaml:"read_only"`           // MUST be true; false is rejected by ValidateWebUI (WEB-02)
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
type ObservabilityDigest struct {
	Enabled   bool   `yaml:"enabled"`
	Hour      int    `yaml:"hour,omitempty"`
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
	}
}

// Load reads path, decodes YAML strictly (unknown keys are rejected), and
// returns the parsed Config. Default values are applied for omitted fields.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	cfg := Defaults()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	// Normalize: a v1 tailnet:-only config has no backend: stanza, so
	// Backend.Type is "". Default it to "tailscale" (Pitfall 4 alias).
	if cfg.Backend.Type == "" {
		cfg.Backend.Type = "tailscale"
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
	if err := validateBackend(cfg); err != nil {
		return err
	}
	if err := ValidateObservability(cfg); err != nil {
		return err
	}
	if err := ValidateWebUI(cfg); err != nil {
		return err
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
	if cfg.Tailnet.Hostname == "" {
		return fmt.Errorf("config: tailnet.hostname is required")
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
	return nil
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
	}
	return nil
}
