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
	"testing"

	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
)

func TestDiskEncryptionBlockers(t *testing.T) {
	findings := []modules.Finding{
		{Module: "hardening", Check: "filevault", Severity: modules.SeverityFatal, Message: "FileVault off"},
		{Module: "hardening", Check: "luks", Severity: modules.SeverityFatal, Message: "LUKS off"},
		{Module: "hardening", Check: "firewall", Severity: modules.SeverityFatal, Message: "firewall off"},   // not disk encryption
		{Module: "hardening", Check: "filevault", Severity: modules.SeverityWarning, Message: "warn only"},   // not fatal
		{Module: "tailscale", Check: "installed", Severity: modules.SeverityFatal, Message: "not installed"}, // not hardening — up fixes this
	}

	got := diskEncryptionBlockers(findings)

	// Only the fatal filevault + luks disk-encryption checks block.
	assert.Len(t, got, 2)
	checks := map[string]bool{}
	for _, f := range got {
		checks[f.Check] = true
	}
	assert.True(t, checks["filevault"])
	assert.True(t, checks["luks"])
	assert.False(t, checks["firewall"])
}

func TestDiskEncryptionBlockers_NoneWhenEncrypted(t *testing.T) {
	findings := []modules.Finding{
		{Module: "tailscale", Check: "installed", Severity: modules.SeverityFatal},
		{Module: "hardening", Check: "firewall", Severity: modules.SeverityWarning},
	}
	assert.Empty(t, diskEncryptionBlockers(findings))
}
