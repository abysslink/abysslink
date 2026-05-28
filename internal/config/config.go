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

	"gopkg.in/yaml.v3"
)

// Config is the top-level abysslink.yaml structure.
type Config struct {
	Version    int        `yaml:"version"`
	Identity   Identity   `yaml:"identity"`
	Tailnet    Tailnet    `yaml:"tailnet"`
	Mobile     Mobile     `yaml:"mobile"`
	Modules    Modules    `yaml:"modules"`
	ClaudeCode ClaudeCode `yaml:"claudecode"`
	Power      Power      `yaml:"power"`
	Hardening  Hardening  `yaml:"hardening"`
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

// NotifyModule configures the generic notification API.
type NotifyModule struct {
	Enabled      bool   `yaml:"enabled"`
	DefaultTopic string `yaml:"default_topic"`
}

// WatchModule configures the idle-pane watcher.
type WatchModule struct {
	Enabled bool     `yaml:"enabled"`
	Panes   []string `yaml:"panes"`
}

// Modules groups all module configurations.
type Modules struct {
	SSH             SSHModule    `yaml:"ssh"`
	Tmux            TmuxModule   `yaml:"tmux"`
	Mosh            BasicModule  `yaml:"mosh"`
	Notify          NotifyModule `yaml:"notify"`
	Ntfy            BasicModule  `yaml:"ntfy"`
	Watch           WatchModule  `yaml:"watch"`
	CodeServer      BasicModule  `yaml:"code_server"`
	Ttyd            BasicModule  `yaml:"ttyd"`
	Syncthing       BasicModule  `yaml:"syncthing"`
	Upsnap          BasicModule  `yaml:"upsnap"`
	EternalTerminal BasicModule  `yaml:"eternal_terminal"`
	Atuin           BasicModule  `yaml:"atuin"`
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
			Ntfy:   BasicModule{Enabled: true},
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
	return cfg, nil
}

// Write marshals cfg to YAML and writes it to path, creating parent directories
// as needed. The file is written atomically via a temp file + rename.
func Write(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: create directory: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("config: write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: rename to final path: %w", err)
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
		if _, err := time.ParseDuration(cfg.ClaudeCode.NotifyOn.StopAfter); err != nil {
			return fmt.Errorf("config: claudecode.notify_on.stop_after %q is not a valid duration: %w", cfg.ClaudeCode.NotifyOn.StopAfter, err)
		}
	}
	return nil
}
