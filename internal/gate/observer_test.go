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

// Internal test package (package gate) so we can access unexported Gated
// fields to verify observer registration in SetObserver.
package gate

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGated_SetObserver verifies that:
//   - SetObserver stores fn in Gated.observer.
//   - After Run, the observer is called with a non-zero [32]byte hash.
//   - SetObserver(nil) replaces any previous observer (deregisters).
//   - Observer panic does not propagate to the caller.
func TestGated_SetObserver(t *testing.T) {
	ctx := context.Background()

	t.Run("observer called on Run", func(t *testing.T) {
		inner := &fakeInner{}
		g := New(inner, WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

		var mu sync.Mutex
		var received [][32]byte

		g.SetObserver(func(h [32]byte) {
			mu.Lock()
			defer mu.Unlock()
			received = append(received, h)
		})

		_, err := g.Run(ctx, "echo", "hello")
		require.NoError(t, err)

		mu.Lock()
		defer mu.Unlock()
		require.Len(t, received, 1, "observer must be called exactly once per exec")
		var zero [32]byte
		assert.NotEqual(t, zero, received[0], "observer must receive a non-zero closure hash")
	})

	t.Run("observer called on all exec methods", func(t *testing.T) {
		inner := &fakeInner{}
		g := New(inner, WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

		var mu sync.Mutex
		var count int

		g.SetObserver(func(_ [32]byte) {
			mu.Lock()
			defer mu.Unlock()
			count++
		})

		_, _ = g.Run(ctx, "ls", "-la")
		_, _ = g.RunWithStdin(ctx, nil, "ssh-add", "-")
		_ = g.RunInteractive(ctx, "tailscale", "up")
		_, _ = g.RunWithEnv(ctx, nil, "git", "fetch")
		_, _ = g.RunStream(ctx, "tmux", "-CC")

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, 5, count, "observer must be called once for each of the 5 exec methods")
	})

	t.Run("SetObserver(nil) deregisters observer", func(t *testing.T) {
		inner := &fakeInner{}
		g := New(inner, WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

		var mu sync.Mutex
		var count int

		g.SetObserver(func(_ [32]byte) {
			mu.Lock()
			defer mu.Unlock()
			count++
		})

		// First exec — observer active.
		_, _ = g.Run(ctx, "echo", "before")

		// Deregister.
		g.SetObserver(nil)

		// Second exec — observer must NOT be called.
		_, _ = g.Run(ctx, "echo", "after")

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, 1, count, "observer must not be called after SetObserver(nil)")
	})

	t.Run("observer panic does not propagate", func(t *testing.T) {
		inner := &fakeInner{}
		g := New(inner, WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))

		g.SetObserver(func(_ [32]byte) {
			panic("observer panic must be recovered")
		})

		// Must not panic.
		assert.NotPanics(t, func() {
			_, _ = g.Run(ctx, "echo", "panic-test")
		})
	})
}
