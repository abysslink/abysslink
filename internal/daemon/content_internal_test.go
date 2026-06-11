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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contentClock is an adjustable clock for the content-store tests.
type contentClock struct{ t time.Time }

func (c *contentClock) now() time.Time          { return c.t }
func (c *contentClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newContentClock() *contentClock            { return &contentClock{t: time.Unix(1_750_000_000, 0)} }

func TestMintContent_TokenShapeAndUniqueness(t *testing.T) {
	cs := newContentStore(nil)
	tok1, exp := cs.mintContent("body-1", time.Minute)
	tok2, _ := cs.mintContent("body-2", time.Minute)

	assert.True(t, strings.HasPrefix(tok1, contentTokenPrefix), "token must carry the ablk_c_ prefix")
	// 16 bytes base64url no-pad = 22 chars.
	assert.Len(t, tok1, len(contentTokenPrefix)+22)
	assert.NotEqual(t, tok1, tok2, "tokens must be unique per mint")
	assert.True(t, exp.After(time.Now()), "expiry must be in the future")

	// Single-purpose: one body per token.
	got1, ok := cs.getContent(tok1)
	require.True(t, ok)
	assert.Equal(t, "body-1", got1)
	got2, ok := cs.getContent(tok2)
	require.True(t, ok)
	assert.Equal(t, "body-2", got2)
}

func TestGetContent_UnknownTokenMisses(t *testing.T) {
	cs := newContentStore(nil)
	_, ok := cs.getContent("ablk_c_does-not-exist")
	assert.False(t, ok)
}

func TestGetContent_SingleUse(t *testing.T) {
	cs := newContentStore(nil)
	tok, _ := cs.mintContent("once", 30*time.Second)

	body, ok := cs.getContent(tok)
	require.True(t, ok, "first fetch must resolve")
	assert.Equal(t, "once", body)

	_, ok = cs.getContent(tok)
	assert.False(t, ok, "a replayed token must serve nothing — tokens are single-use")
	assert.Equal(t, 0, cs.len(), "consumed token must be removed")
}

func TestGetContent_ExpiryEnforced(t *testing.T) {
	clk := newContentClock()
	cs := newContentStore(clk.now)
	tok, _ := cs.mintContent("ephemeral", 30*time.Second)

	_, ok := cs.getContent(tok)
	require.True(t, ok, "fresh token must resolve")

	clk.advance(31 * time.Second)
	_, ok = cs.getContent(tok)
	assert.False(t, ok, "expired token must miss")
	assert.Equal(t, 0, cs.len(), "expired entry must be pruned on get")
}

func TestMintContent_PrunesExpiredOnMint(t *testing.T) {
	clk := newContentClock()
	cs := newContentStore(clk.now)
	cs.mintContent("old", 10*time.Second)
	clk.advance(time.Minute)
	cs.mintContent("new", time.Minute)
	assert.Equal(t, 1, cs.len(), "mint must prune expired entries")
}

func TestMintContent_BoundedDropOldest(t *testing.T) {
	clk := newContentClock()
	cs := newContentStore(clk.now)

	var first string
	for i := 0; i < maxContentEntries; i++ {
		tok, _ := cs.mintContent(fmt.Sprintf("body-%d", i), time.Hour)
		if i == 0 {
			first = tok
		}
		// Distinct mint instants so drop-oldest is deterministic.
		clk.advance(time.Millisecond)
	}
	require.Equal(t, maxContentEntries, cs.len())

	over, _ := cs.mintContent("overflow", time.Hour)
	assert.Equal(t, maxContentEntries, cs.len(), "store must stay bounded at max entries")

	_, ok := cs.getContent(first)
	assert.False(t, ok, "the OLDEST entry must have been dropped")
	got, ok := cs.getContent(over)
	require.True(t, ok, "the new entry must be present")
	assert.Equal(t, "overflow", got)
}
