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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestResolveApproveTimeout_NonBlocking asserts the short (test / no-daemon)
// deadline is used without --blocking, independent of any config.
func TestResolveApproveTimeout_NonBlocking(t *testing.T) {
	assert.Equal(t, approveNonBlockingTimeout, resolveApproveTimeout(false))
}

// TestResolveApproveTimeout_BlockingHonorsConfig is the regression guard for
// finding [7]: --blocking must apply the operator's approval.timeout_seconds so
// the CLI's deadline matches the daemon's wait timeout — a hardcoded 120s made
// the hook exit deny before a longer-window approval could arrive.
func TestResolveApproveTimeout_BlockingHonorsConfig(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)

	cfg := testCfgDefaults()
	cfg.Approval.TimeoutSeconds = 300
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	cfgDir := filepath.Join(xdg, "abysslink")
	require.NoError(t, os.MkdirAll(cfgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "abysslink.yaml"), data, 0o600))

	assert.Equal(t, 300*time.Second, resolveApproveTimeout(true),
		"--blocking must apply cfg.Approval.TimeoutSeconds (finding [7])")
}

// TestResolveApproveTimeout_BlockingFallbackWhenConfigMissing asserts the 120s
// daemon-default fallback is used when the config is unreadable (fresh install).
func TestResolveApproveTimeout_BlockingFallbackWhenConfigMissing(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // empty dir — no abysslink.yaml
	assert.Equal(t, approveBlockingTimeoutFallback, resolveApproveTimeout(true),
		"a missing/unreadable config must fall back to the 120s daemon default")
}
