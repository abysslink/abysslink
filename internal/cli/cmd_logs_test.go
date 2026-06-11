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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogsJSON_NotDoubleEncoded covers U1: `logs --json` must emit each audit
// entry as a single typed JSON object, NOT a {"msg":"{\"time\":...}"} wrapper
// that consumers would have to double-decode.
func TestLogsJSON_NotDoubleEncoded(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateDir)

	logPath, err := audit.DefaultLogPath()
	require.NoError(t, err)
	require.NoError(t, audit.New(logPath).Append("test-op", "/tmp/target-file", nil, false))

	root := buildRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--json", "logs", "--since", "1h"})
	require.NoError(t, root.Execute())

	// Find the entry line (skip any other JSON records).
	var entryLine string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.Contains(line, "test-op") {
			entryLine = line
			break
		}
	}
	require.NotEmpty(t, entryLine, "the audit entry must appear in --json output")

	var obj map[string]any
	require.NoError(t, json.Unmarshal([]byte(entryLine), &obj))
	assert.NotContains(t, obj, "msg",
		"the entry must be a typed object, not a {\"msg\": ...} string wrapper")
	assert.Equal(t, "test-op", obj["op"], "the op field must be directly addressable (single decode)")
	assert.Equal(t, "/tmp/target-file", obj["target"])
}
