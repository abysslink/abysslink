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

package backend

import (
	"io"

	"github.com/abysslink/abysslink/internal/limitio"
)

// maxBackendBody re-exports limitio.MaxBackendBody so existing backend call
// sites need no change (D-04 import-change is a one-liner here, not at 25 sites).
const maxBackendBody = limitio.MaxBackendBody

// readLimited re-exports limitio.ReadLimited so existing backend call sites
// need no change (D-04 thin wrapper).
func readLimited(r io.ReadCloser, n int64) ([]byte, error) {
	return limitio.ReadLimited(r, n)
}
