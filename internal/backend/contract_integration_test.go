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

//go:build integration

package backend_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/shell"
)

// TestContract_RealBinary exercises the 3 contract invariants against the real
// tailscale binary. Run with: go test ./internal/backend/ -tags integration
// This test is opt-in and non-blocking (not run in default CI).
func TestContract_RealBinary(t *testing.T) {
	b, err := backend.New(tailscaleCfg(), &shell.ExecRunner{})
	require.NoError(t, err)

	ip, err := b.IP(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, ip, "real tailscale must return a non-empty IP")

	require.NotZero(t, b.SSHConfig().CheckPeriod)
	require.Equal(t, backend.LockFull, b.LockCapability())
}
