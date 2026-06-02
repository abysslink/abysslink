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

// Package backend implements the backend adapter layer for abysslink.
package backend

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
)

// MergeHeadscaleConfig performs a surgical merge of the required hardened keys
// into an existing Headscale config.yaml at cfgPath.
//
// It does NOT overwrite user-owned keys outside the hardened set (oidc.*, dns.*,
// node_update_check_interval, etc.). The merge is idempotent — re-running on an
// already-hardened config produces identical bytes.
//
// Required hardened keys written by this function:
//   - grpc_allow_insecure: false
//   - metrics_listen_addr: 127.0.0.1:9090
//   - server_url: hs.ServerURL
//   - derp.server.enabled: true
//   - derp.server.verify_clients: true    (R-02: use only this key, not the derper-binary flag)
//   - policy.mode: database
//   - logtail.enabled: false
//   - database.type: sqlite
//   - database.sqlite.path: hs.DBPath
//
// TLS keys are mutually exclusive:
//   - BYO mode (hs.ACME==false): sets tls_cert_path, tls_key_path
//   - ACME mode (hs.ACME==true): sets tls_letsencrypt_hostname/challenge_type/listen;
//     clears tls_cert_path and tls_key_path if present
//
// All writes go through internal/audit.WriteFile (backup + audit log on every write).
// In dryRun mode, the diff is logged but nothing is written.
//
// Security: this function never writes the standalone-derper config key for
// client verification — the correct embedded DERP key is derp.server.verify_clients
// (R-02, RESEARCH.md Pitfall 1).
func MergeHeadscaleConfig(ctx context.Context, cfgPath string, hs config.HeadscaleServer, dryRun bool) error {
	// Read existing config (create an empty map if not present).
	m, oldData, err := loadHeadscaleYAML(cfgPath)
	if err != nil {
		return err
	}

	// Apply all required hardened keys.
	applyHardenedKeys(m, hs)

	// Encode merged config.
	newData, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("headscale config: encode: %w", err)
	}

	// Obtain audit log path (shared for both dryRun and live paths).
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("headscale config: audit log path: %w", err)
	}

	if dryRun {
		slog.InfoContext(ctx, "headscale config merge [dry-run]",
			"path", cfgPath,
			"old_bytes", len(oldData),
			"new_bytes", len(newData),
		)
		return audit.New(logPath).WriteFile(cfgPath, newData, 0o600, true)
	}

	// All writes go through internal/audit.WriteFile (backup + log).
	if err := audit.New(logPath).WriteFile(cfgPath, newData, 0o600, false); err != nil {
		return fmt.Errorf("headscale config: write: %w", err)
	}

	slog.InfoContext(ctx, "headscale config merge applied", "path", cfgPath)
	return nil
}

// loadHeadscaleYAML reads the YAML file at path into a map[string]any with a
// lenient decoder (KnownFields false). Returns an empty map if the file does
// not exist, and its pre-merge marshalled bytes for dry-run diffing.
func loadHeadscaleYAML(path string) (map[string]any, []byte, error) {
	var m map[string]any
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a backend config path resolved internally, not user input
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("headscale config: read %s: %w", path, err)
		}
		m = make(map[string]any)
		return m, nil, nil
	}
	// Lenient decode: Headscale has many keys abysslink does not model.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("headscale config: decode %s: %w", path, err)
	}
	if m == nil {
		m = make(map[string]any)
	}
	oldBytes, _ := yaml.Marshal(m) //nolint:errcheck // errcheck: yaml.Marshal on a known-serializable map cannot fail in practice; result used only for diff display
	return m, oldBytes, nil
}

// applyHardenedKeys applies all required hardened keys to the config map m in
// place. This is extracted from MergeHeadscaleConfig to keep gocyclo below the
// project limit (<=15).
//
// It never writes the standalone derper-binary config flag — R-02 specifies
// the correct embedded DERP hardening key: derp.server.verify_clients (bool).
func applyHardenedKeys(m map[string]any, hs config.HeadscaleServer) {
	// Top-level scalar keys.
	m["grpc_allow_insecure"] = false
	m["metrics_listen_addr"] = "127.0.0.1:9090"
	m["server_url"] = hs.ServerURL

	// logtail.enabled = false  (prevents client telemetry to Tailscale Inc.)
	setNestedKey(m, []string{"logtail", "enabled"}, false)

	// policy.mode = database  (required for REST ACL push, D-09)
	setNestedKey(m, []string{"policy", "mode"}, "database")

	// database.type = sqlite; database.sqlite.path
	setNestedKey(m, []string{"database", "type"}, "sqlite")
	if hs.DBPath != "" {
		setNestedKey(m, []string{"database", "sqlite", "path"}, hs.DBPath)
	}

	// derp.server: enabled + verify_clients  (R-02: correct embedded DERP hardening key)
	setNestedKey(m, []string{"derp", "server", "enabled"}, true)
	setNestedKey(m, []string{"derp", "server", "verify_clients"}, true)

	// TLS strategy: ACME vs BYO are mutually exclusive.
	applyTLSKeys(m, hs)
}

// applyTLSKeys sets TLS-related keys based on hs.ACME flag.
// The two modes are mutually exclusive: switching modes removes the other mode's keys.
func applyTLSKeys(m map[string]any, hs config.HeadscaleServer) {
	if hs.ACME {
		// ACME mode: clear BYO keys; set letsencrypt keys.
		delete(m, "tls_cert_path")
		delete(m, "tls_key_path")

		if hostname := extractHostname(hs.ServerURL); hostname != "" {
			m["tls_letsencrypt_hostname"] = hostname
		}
		m["tls_letsencrypt_challenge_type"] = "HTTP-01"
		m["tls_letsencrypt_listen"] = ":http"
	} else if hs.TLSCertPath != "" || hs.TLSKeyPath != "" {
		// BYO mode: clear ACME keys; set cert/key paths.
		delete(m, "tls_letsencrypt_hostname")
		delete(m, "tls_letsencrypt_challenge_type")
		delete(m, "tls_letsencrypt_listen")

		if hs.TLSCertPath != "" {
			m["tls_cert_path"] = hs.TLSCertPath
		}
		if hs.TLSKeyPath != "" {
			m["tls_key_path"] = hs.TLSKeyPath
		}
	}
}

// extractHostname parses rawURL and returns the hostname (without port).
// Returns empty string on parse error.
func extractHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
