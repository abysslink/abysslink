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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExitCodeConstants verifies the three documented exit-code constants exist
// and have the correct integer values.
func TestExitCodeConstants(t *testing.T) {
	assert.Equal(t, 0, exitCodeOK, "exitCodeOK must be 0")
	assert.Equal(t, 1, exitCodeError, "exitCodeError must be 1")
	assert.Equal(t, 2, exitCodeFatal, "exitCodeFatal must be 2")
}

// TestExitError_Code verifies that exitError correctly reports its exit code.
func TestExitError_Code(t *testing.T) {
	err := &exitError{code: exitCodeFatal}
	assert.Equal(t, exitCodeFatal, err.ExitCode())
	assert.Contains(t, err.Error(), "2")
}

// TestExitError_IsError verifies that exitError implements the error interface.
func TestExitError_IsError(t *testing.T) {
	var err error = &exitError{code: exitCodeError}
	assert.NotNil(t, err)

	var ee *exitError
	assert.True(t, errors.As(err, &ee))
	assert.Equal(t, exitCodeError, ee.ExitCode())
}
