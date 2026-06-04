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
	"github.com/abysslink/abysslink/internal/config"
)

// testCfgDefaults returns config.Defaults() with the required identity fields
// populated. Use this (not config.Defaults()) in any test that marshals the
// config to YAML and then calls config.Load — since Load now calls Validate
// (D-01 fail-closed), the config must satisfy all required fields or Load
// returns an error.
func testCfgDefaults() *config.Config {
	cfg := config.Defaults()
	cfg.Identity.Email = "test@example.com"
	cfg.Identity.UnixUser = "testuser"
	cfg.Tailnet.Hostname = "test-rig"
	return cfg
}
