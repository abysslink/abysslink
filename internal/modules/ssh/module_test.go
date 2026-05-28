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

package ssh

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHardenedSSHDConfig(t *testing.T) {
	cfg := hardenedSSHDConfig("alice")

	// Security-critical directives must be present.
	assert.Contains(t, cfg, "PasswordAuthentication no")
	assert.Contains(t, cfg, "AllowAgentForwarding no", "prevent a compromised phone pivoting via a forwarded agent")
	assert.Contains(t, cfg, "AllowTcpForwarding no")
	assert.Contains(t, cfg, "X11Forwarding no")
	assert.Contains(t, cfg, "PermitRootLogin no")
	assert.Contains(t, cfg, "AllowUsers alice")
}
