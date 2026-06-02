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
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upsnapEnabledCfg returns a config with the upsnap module enabled.
func upsnapEnabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.Modules.Upsnap.Enabled = true
	return cfg
}

// TestDoctorWolApplyGate_Fatal verifies the wol-apply-gate FATAL finding is
// present when upsnap is enabled.
func TestDoctorWolApplyGate_Fatal(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), upsnapEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "wol-apply-gate")
	require.True(t, ok, "wol-apply-gate must be present when upsnap is enabled")
	assert.Equal(t, modules.SeverityFatal, f.Severity)
}

// TestDoctorUpSnapBind_Warn verifies the upsnap-bind WARN finding is present.
func TestDoctorUpSnapBind_Warn(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), upsnapEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "upsnap-bind")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// TestDoctorUpSnapNoPublic_Warn verifies the upsnap-no-public WARN finding is present.
func TestDoctorUpSnapNoPublic_Warn(t *testing.T) {
	findings := mod3DoctorFindings(context.Background(), upsnapEnabledCfg(), shell.NewMockRunner())
	f, ok := findFinding(findings, "upsnap-no-public")
	require.True(t, ok)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
}

// TestDoctorMod3_DisabledNoFindings verifies that a disabled upsnap module
// yields no findings.
func TestDoctorMod3_DisabledNoFindings(t *testing.T) {
	cfg := config.Defaults() // upsnap disabled by default
	findings := mod3DoctorFindings(context.Background(), cfg, shell.NewMockRunner())
	assert.Empty(t, findings)
}
