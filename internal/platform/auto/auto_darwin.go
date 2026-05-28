//go:build darwin

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

package auto

import (
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/platform/darwin"
	"github.com/abysslink/abysslink/internal/shell"
)

// New returns the macOS platform implementation. The error return exists for
// signature parity with the Linux factory (which probes the system) and is
// always nil on macOS.
func New(runner shell.Runner) (platform.Platform, error) {
	return darwin.New(runner), nil
}
