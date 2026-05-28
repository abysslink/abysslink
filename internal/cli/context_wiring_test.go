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
	"runtime"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildDeps_WiresPlatformAndAudit guards against the regression where the
// platform facade and audit writer were never constructed (and the keychain was
// hardcoded nil). buildDeps must always return a non-nil Platform and Audit for
// the host OS.
func TestBuildDeps_WiresPlatformAndAudit(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir()) // avoid touching the real home dir

	cc := &cmdContext{cfg: config.Defaults(), runner: &shell.ExecRunner{}}
	deps, err := buildDeps(context.Background(), cc)
	require.NoError(t, err)

	require.NotNil(t, deps.Platform, "platform facade must be constructed")
	require.NotNil(t, deps.Audit, "audit writer must be constructed")
	assert.Same(t, cc.cfg, deps.Cfg)
	assert.NotNil(t, deps.Runner)

	wantOS := map[string]string{"darwin": "darwin", "linux": "linux"}[runtime.GOOS]
	if wantOS == "" {
		wantOS = "unsupported"
	}
	assert.Equal(t, wantOS, deps.Platform.OS())
}

// TestAllModules_ConstructsCoreSet confirms the full core module set is wired
// from the dependency bundle without panicking on any nil dependency.
func TestAllModules_ConstructsCoreSet(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	cc := &cmdContext{cfg: config.Defaults(), runner: &shell.ExecRunner{}}
	deps, err := buildDeps(context.Background(), cc)
	require.NoError(t, err)

	mods := allModules(deps)
	assert.Len(t, mods, 15) // 11 core + 4 optional (claudecode, code-server, ttyd, eternal-terminal)
	for _, m := range mods {
		assert.NotEmpty(t, m.Name())
	}
}
