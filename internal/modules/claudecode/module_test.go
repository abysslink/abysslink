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

package claudecode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasStopHook(t *testing.T) {
	withHook := []byte(`{
	  "hooks": {
	    "Stop": [
	      {"matcher": "", "hooks": [{"type": "command", "command": "abysslink notify \"Claude stopped\" \"x\""}]}
	    ]
	  }
	}`)
	assert.True(t, hasStopHook(withHook))

	withoutHook := []byte(`{"hooks": {"Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "echo hi"}]}]}}`)
	assert.False(t, hasStopHook(withoutHook))

	assert.False(t, hasStopHook([]byte(`{}`)))
	assert.False(t, hasStopHook([]byte("not json")))
}
