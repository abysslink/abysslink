//go:build linux

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

package secrets

import (
	"context"

	"github.com/abysslink/abysslink/internal/shell"
)

// NewStore returns a libsecret (secret-tool) or pass-backed store, probing for
// an available backend. It returns an error if neither is installed.
func NewStore(ctx context.Context, runner shell.Runner) (KeychainStore, error) {
	return NewLinuxStore(ctx, runner)
}
