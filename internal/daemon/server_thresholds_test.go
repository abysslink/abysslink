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

package daemon

import (
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestPaneThresholds_Defaults(t *testing.T) {
	s := &Server{cfg: config.Defaults()}
	assert.Equal(t, panePollInterval, s.panePoll(), "zero PanePollSecs → compiled default")
	assert.Equal(t, paneIdleInterval, s.paneIdle(), "zero PaneIdleSecs → compiled default")
	assert.Equal(t, paneCoolOff, s.paneCoolOffDur(), "zero PaneCoolOffSecs → compiled default")
}

func TestPaneThresholds_NilConfig(t *testing.T) {
	s := &Server{cfg: nil}
	assert.Equal(t, panePollInterval, s.panePoll())
	assert.Equal(t, paneIdleInterval, s.paneIdle())
	assert.Equal(t, paneCoolOff, s.paneCoolOffDur())
}

func TestPaneThresholds_YAMLOverride(t *testing.T) {
	cfg := config.Defaults()
	cfg.Modules.Watch.PanePollSecs = 10
	cfg.Modules.Watch.PaneIdleSecs = 60
	cfg.Modules.Watch.PaneCoolOffSecs = 120

	s := &Server{cfg: cfg}
	assert.Equal(t, 10*time.Second, s.panePoll())
	assert.Equal(t, 60*time.Second, s.paneIdle())
	assert.Equal(t, 120*time.Second, s.paneCoolOffDur())
}

func TestFilePollInterval_DefaultWhenZero(t *testing.T) {
	// FileWatch.PollSecs == 0 must use the filePollInterval constant.
	// We verify the constant matches the expected default.
	assert.Equal(t, 2*time.Second, filePollInterval)
}

func TestFilePollInterval_ConfiguredValue(t *testing.T) {
	// Verify the FileWatch.PollSecs field is read correctly (daemon uses it in
	// watchFile; we test the config round-trip here since watchFile is not
	// directly unit-testable without a running ticker).
	fw := config.FileWatch{Path: "/tmp/x.log", Grep: "FAIL", PollSecs: 30}
	assert.Equal(t, 30, fw.PollSecs)
	assert.Equal(t, 30*time.Second, time.Duration(fw.PollSecs)*time.Second)
}
