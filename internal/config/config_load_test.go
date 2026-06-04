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

// Package config_test contains RED tests for config.Load fail-closed validation
// (NET-02, NET-03). These tests FAIL until 25-02 adds the Validate call in Load.
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
)

// minimalValidYAML returns a minimal but semantically valid YAML string that
// passes both YAML decode and config.Validate. Used as the base for invalid-
// field tests — only the field under test is set to an invalid value.
func minimalValidYAML() string {
	return `version: 1
identity:
  email: test@example.com
  unix_user: testuser
tailnet:
  hostname: mac-dev
  ssh: true
  lock:
    enabled: true
    disablement_secrets: 2
    share_with_support: false
mobile:
  tag: mobile
  ports:
    - tcp/22
  ssh_check_period: 12h
modules:
  ssh:
    enabled: true
    mode: tailscale
  tmux:
    enabled: true
    session: main
  mosh:
    enabled: true
  notify:
    enabled: true
    default_topic: rig
  ntfy:
    enabled: true
  watch:
    enabled: true
    panes:
      - main
claudecode:
  enabled: false
  api_key_source: keychain
  notify_on:
    notification: false
    stop_after: 60s
power:
  closed_lid_ac: keep-awake
hardening:
  filevault: required
  luks: required
  firewall_stealth: true
  ufw_default_deny: true
  disable_macos_sshd: true
`
}

// writeTempYAML writes yamlContent to a temporary file and returns the path.
// The file is cleaned up at test teardown via t.Cleanup.
func writeTempYAML(t *testing.T, yamlContent string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "abysslink.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("writeTempYAML: %v", err)
	}
	return path
}

// TestLoad_FailClosed_ValidationError asserts that config.Load returns a non-nil
// error when the YAML is syntactically valid but contains a semantically invalid
// field (tailnet.hostname with a non-DNS-safe char).
//
// RED: This test FAILS on the current codebase because config.Load does NOT call
// config.Validate — it returns a nil error and the invalid hostname is silently
// accepted. Wave 1 (plan 25-02) wires the Validate call in Load to make this GREEN.
func TestLoad_FailClosed_ValidationError(t *testing.T) {
	// Replace the valid hostname with one containing a space (non-DNS-safe).
	yaml := minimalValidYAML()
	// Override tailnet.hostname to an invalid value — space is not allowed.
	invalidYAML := `version: 1
identity:
  email: test@example.com
  unix_user: testuser
tailnet:
  hostname: "bad hostname!!"
  ssh: true
  lock:
    enabled: true
    disablement_secrets: 2
    share_with_support: false
mobile:
  tag: mobile
  ports:
    - tcp/22
  ssh_check_period: 12h
modules:
  ssh:
    enabled: true
    mode: tailscale
  tmux:
    enabled: true
    session: main
  mosh:
    enabled: true
  notify:
    enabled: true
    default_topic: rig
  ntfy:
    enabled: true
  watch:
    enabled: true
    panes:
      - main
claudecode:
  enabled: false
  api_key_source: keychain
  notify_on:
    notification: false
    stop_after: 60s
power:
  closed_lid_ac: keep-awake
hardening:
  filevault: required
  luks: required
  firewall_stealth: true
  ufw_default_deny: true
  disable_macos_sshd: true
`
	_ = yaml // silence unused warning until implementation wires Validate in Load
	path := writeTempYAML(t, invalidYAML)

	_, err := config.Load(path)
	if err == nil {
		t.Errorf("expected Load to return error for invalid hostname %q, got nil — "+
			"RED: config.Load does not yet call Validate (fix in plan 25-02)", "bad hostname!!")
	}
}

// TestLoad_NetBird_HTTPRejects asserts that config.Load returns a non-nil error
// when backend.type is "netbird" and server.netbird.server_url uses http://.
//
// RED: This test FAILS on the current codebase because config.Load does NOT call
// config.Validate. Wave 1 (plan 25-02) makes this GREEN (NET-02).
func TestLoad_NetBird_HTTPRejects(t *testing.T) {
	netbirdHTTPYAML := `version: 1
identity:
  email: test@example.com
  unix_user: testuser
backend:
  type: netbird
tailnet:
  hostname: mac-dev
  ssh: true
  lock:
    enabled: true
    disablement_secrets: 2
    share_with_support: false
server:
  netbird:
    server_url: "http://netbird.example.com"
mobile:
  tag: mobile
  ports:
    - tcp/22
  ssh_check_period: 12h
modules:
  ssh:
    enabled: true
    mode: tailscale
  tmux:
    enabled: true
    session: main
  mosh:
    enabled: true
  notify:
    enabled: true
    default_topic: rig
  ntfy:
    enabled: true
  watch:
    enabled: true
    panes:
      - main
claudecode:
  enabled: false
  api_key_source: keychain
  notify_on:
    notification: false
    stop_after: 60s
power:
  closed_lid_ac: keep-awake
hardening:
  filevault: required
  luks: required
  firewall_stealth: true
  ufw_default_deny: true
  disable_macos_sshd: true
`
	path := writeTempYAML(t, netbirdHTTPYAML)

	_, err := config.Load(path)
	if err == nil {
		t.Errorf("expected Load to return error for NetBird http:// server_url, got nil — "+
			"RED: config.Load does not yet call Validate (fix in plan 25-02, NET-02)")
	}
}

// TestLoad_BadHostname_Rejects asserts that config.Load returns a non-nil error
// when tailnet.hostname starts with a dash (invalid DNS label).
//
// RED: This test FAILS on the current codebase because config.Load does NOT call
// config.Validate. Wave 1 (plan 25-02) makes this GREEN (NET-03).
func TestLoad_BadHostname_Rejects(t *testing.T) {
	badHostnameYAML := `version: 1
identity:
  email: test@example.com
  unix_user: testuser
tailnet:
  hostname: "-bad-leading-dash"
  ssh: true
  lock:
    enabled: true
    disablement_secrets: 2
    share_with_support: false
mobile:
  tag: mobile
  ports:
    - tcp/22
  ssh_check_period: 12h
modules:
  ssh:
    enabled: true
    mode: tailscale
  tmux:
    enabled: true
    session: main
  mosh:
    enabled: true
  notify:
    enabled: true
    default_topic: rig
  ntfy:
    enabled: true
  watch:
    enabled: true
    panes:
      - main
claudecode:
  enabled: false
  api_key_source: keychain
  notify_on:
    notification: false
    stop_after: 60s
power:
  closed_lid_ac: keep-awake
hardening:
  filevault: required
  luks: required
  firewall_stealth: true
  ufw_default_deny: true
  disable_macos_sshd: true
`
	path := writeTempYAML(t, badHostnameYAML)

	_, err := config.Load(path)
	if err == nil {
		t.Errorf("expected Load to return error for leading-dash hostname %q, got nil — "+
			"RED: config.Load does not yet call Validate (fix in plan 25-02, NET-03)", "-bad-leading-dash")
	}
}
