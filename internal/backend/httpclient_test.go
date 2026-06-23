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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackendHTTPClientTimeout locks in the B4 invariant (T-32-17): every
// control-plane REST round-trip in this package goes through the shared
// backendHTTPClient, which MUST carry a non-zero request timeout. A future
// unbounded client (or a switch to http.DefaultClient) would let a hung or
// blackholed control plane stall the CLI forever — this regression test fails
// closed if the timeout is ever removed.
func TestBackendHTTPClientTimeout(t *testing.T) {
	require.NotNil(t, backendHTTPClient, "shared backend HTTP client must exist")
	assert.Positive(t, backendHTTPClient.Timeout,
		"backendHTTPClient.Timeout must be > 0 so no backend REST round-trip is unbounded (B4 / NET-06)")
	assert.Equal(t, backendHTTPTimeout, backendHTTPClient.Timeout,
		"shared client must use the documented backendHTTPTimeout ceiling")
}
