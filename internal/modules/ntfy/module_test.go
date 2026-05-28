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

package ntfy

import (
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
)

func TestGenerateServerConfig_BindsTailnetIPNotWildcard(t *testing.T) {
	m := New(modules.Deps{Cfg: config.Defaults()})
	out := string(m.generateServerConfig("100.64.1.2"))

	assert.Contains(t, out, "listen-http: \"100.64.1.2:2586\"", "must bind to the tailnet IP")
	assert.NotContains(t, out, "0.0.0.0", "must never bind to all interfaces")
	assert.Contains(t, out, "auth-default-access: \"deny-all\"")
}

func TestHasWildcardListen(t *testing.T) {
	assert.True(t, hasWildcardListen(`listen-http: ":2586"`), "bare :port binds to all interfaces")
	assert.False(t, hasWildcardListen(`listen-http: "100.64.1.2:2586"`))
	assert.False(t, hasWildcardListen("no listen line here"))
}

func TestGenerateServerConfig_IsYAMLish(t *testing.T) {
	m := New(modules.Deps{Cfg: config.Defaults()})
	out := string(m.generateServerConfig("100.64.1.2"))
	assert.True(t, strings.HasPrefix(out, "# ntfy server config"))
}
