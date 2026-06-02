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

package backend

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
)

// MergeNetBirdConfig performs a surgical merge of the required hardened keys
// into an existing NetBird server config.yaml at cfgPath.
//
// It does NOT overwrite user-owned keys outside the hardened set. The merge is
// idempotent — re-running on an already-hardened config produces identical bytes.
//
// Required hardened keys written unconditionally (always idempotent):
//   - disableAnonymousMetrics: true  (CLAUDE.md: no telemetry in any form)
//   - disableGeoliteUpdate: true     (no outbound calls for geolite DB)
//   - metricsPort: 9090              (metrics listener port)
//
// Conditional TLS keys (only if nb.TLSCertFile is non-empty):
//   - server.tls.certFile: nb.TLSCertFile
//   - server.tls.keyFile:  nb.TLSKeyFile
//
// auth.issuer is deliberately left untouched — the provisioner writes the Dex
// default; operators may change the issuer externally without abysslink
// overwriting their choice.
//
// Security: this function never writes the API key, setup key, or any
// credential to config.yaml — those live in the OS keychain only (CLAUDE.md).
// All writes go through internal/audit.WriteFile (backup + audit log on every
// write). In dryRun mode the diff is logged but nothing is written.
func MergeNetBirdConfig(ctx context.Context, cfgPath string, nb config.NetBirdServer, dryRun bool) error {
	// Read existing config (create an empty map if not present).
	m, oldData, err := loadNetBirdYAML(cfgPath)
	if err != nil {
		return err
	}

	// Apply required hardened keys (unconditional, always idempotent).
	m["disableAnonymousMetrics"] = true
	m["disableGeoliteUpdate"] = true
	m["metricsPort"] = 9090

	// Conditional TLS keys — only written when the operator has provided BYO certs.
	if nb.TLSCertFile != "" {
		setNestedKey(m, []string{"server", "tls", "certFile"}, nb.TLSCertFile)
		setNestedKey(m, []string{"server", "tls", "keyFile"}, nb.TLSKeyFile)
	}
	// auth.issuer is intentionally NOT touched here — see docstring above.

	// Encode merged config.
	newData, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("netbird config: encode: %w", err)
	}

	// Obtain audit log path.
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("netbird config: audit log path: %w", err)
	}

	if dryRun {
		slog.InfoContext(ctx, "netbird config merge [dry-run]",
			"path", cfgPath,
			"old_bytes", len(oldData),
			"new_bytes", len(newData),
		)
		return audit.New(logPath).WriteFile(cfgPath, newData, 0o600, true)
	}

	// All writes go through internal/audit.WriteFile (backup + log).
	if err := audit.New(logPath).WriteFile(cfgPath, newData, 0o600, false); err != nil {
		return fmt.Errorf("netbird config: write: %w", err)
	}

	slog.InfoContext(ctx, "netbird config merge applied", "path", cfgPath)
	return nil
}

// loadNetBirdYAML reads the YAML file at path into a map[string]any with a
// lenient decoder (KnownFields false). Returns an empty map if the file does
// not exist, and its pre-merge marshalled bytes for dry-run diffing.
func loadNetBirdYAML(path string) (map[string]any, []byte, error) {
	var m map[string]any
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a backend config path resolved internally, not user input
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("netbird config: read %s: %w", path, err)
		}
		m = make(map[string]any)
		return m, nil, nil
	}
	// Lenient decode: NetBird has many keys abysslink does not model.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("netbird config: decode %s: %w", path, err)
	}
	if m == nil {
		m = make(map[string]any)
	}
	oldBytes, _ := yaml.Marshal(m) //nolint:errcheck // errcheck: yaml.Marshal on a known-serializable map cannot fail in practice; result used only for diff display
	return m, oldBytes, nil
}
