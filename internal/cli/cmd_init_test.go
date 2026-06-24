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

	"github.com/stretchr/testify/require"
)

// TestInitCmd_ResumeFlagRegistered asserts that newInitCmd registers a --resume
// flag. Ported from TestJourneyInitCmd_YesFlagRegistered in journey_test.go
// (plan 35-05 Task 2b: journey.go deletion).
func TestInitCmd_ResumeFlagRegistered(t *testing.T) {
	cmd := newInitCmd()
	require.NotNil(t, cmd.Flags().Lookup("resume"), "--resume flag must be registered on init command")
	require.NotNil(t, cmd.Flags().Lookup("yes"), "--yes flag must be registered on init command")
}
