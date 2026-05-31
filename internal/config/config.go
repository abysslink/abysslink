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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"gopkg.in/yaml.v3"
)

// Config is the top-level abysslink.yaml structure.
type Config struct {
	Version    int        `yaml:"version"`
	Backend    Backend    `yaml:"backend"`
	Server     Server     `yaml:"server"`
	Rig        Rig        `yaml:"rig"`
	Identity   Identity   `yaml:"identity"`
	Tailnet    Tailnet    `yaml:"tailnet"`
	Mobile     Mobile     `yaml:"mobile"`
	Modules    Modules    `yaml:"modules"`
	ClaudeCode ClaudeCode `yaml:"claudecode"`
	Power      Power      `yaml:"power"`
	Hardening  Hardening  `yaml:"hardening"`
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

// Server holds configuration for a self-hosted backend server (v2+).
type Server struct {
	Hostname  string          `yaml:"hostname"` // FQDN of the Headscale / NetBird server (kept for compat)
	Headscale HeadscaleServer `yaml:"headscale"`
}

// Rig holds per-rig fleet metadata (v2+ / Phase 14).
// Fields are parsed but not yet consumed in v1 (forward-compat stub).
type Rig struct {
	Name string `yaml:"name"` // logical rig name used in fleet commands
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
	// Headscale backend: the API key and minted pre-auth key flow in the
	// Authorization: Bearer header on every REST call. server_url MUST be https://
	// so those secrets are never sent in cleartext (CR-04). This guards
	// hand-written configs and the --yes / non-TTY init paths that bypass the
	// interactive HTTPS prompt.
	if cfg.Backend.Type == "headscale" {
		if !strings.HasPrefix(cfg.Server.Headscale.ServerURL, "https://") {
			return fmt.Errorf("config: server.headscale.server_url %q must use https:// — plaintext http would leak the API key and pre-auth key", cfg.Server.Headscale.ServerURL)
		}
	}
	return nil
}
