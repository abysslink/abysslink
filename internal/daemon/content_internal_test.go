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

// --- BACK-09: bootstrap (first-contact) capability class ---

func TestMintBootstrap_TokenShape(t *testing.T) {
	cs := newContentStore(nil)
	tok1, exp := cs.mintBootstrap(`{"device":"phone"}`, time.Minute)
	tok2, _ := cs.mintBootstrap(`{"device":"laptop"}`, time.Minute)

	assert.True(t, strings.HasPrefix(tok1, bootstrapTokenPrefix), "token must carry the ablk_e_ prefix")
	// 16 bytes base64url no-pad = 22 chars.
	assert.Len(t, tok1, len(bootstrapTokenPrefix)+22)
	assert.NotEqual(t, tok1, tok2, "tokens must be unique per mint")
	assert.True(t, exp.After(time.Now()), "expiry must be in the future")
}

func TestLookupKind_SingleUse(t *testing.T) {
	cs := newContentStore(nil)
	tok, _ := cs.mintBootstrap("bundle-once", 30*time.Second)

	body, ok := cs.lookupKind(tok, kindBootstrap, true)
	require.True(t, ok, "first bootstrap lookup must resolve")
	assert.Equal(t, "bundle-once", body)

	_, ok = cs.lookupKind(tok, kindBootstrap, true)
	assert.False(t, ok, "a replayed bootstrap token must serve nothing — single-use")
	assert.Equal(t, 0, cs.len(), "consumed token must be removed")
}

// TestLookupKind_CrossClassNoConsume is the LOAD-BEARING BACK-09 regression: a
// cross-class probe must return a MISS and DELETE NOTHING — the kind is checked
// before the single-use delete, so a probe can never burn a victim's live
// token. Asserted in BOTH directions (content↛bootstrap and bootstrap↛content).
func TestLookupKind_CrossClassNoConsume(t *testing.T) {
	cs := newContentStore(nil)

	// content token probed via the bootstrap class → miss, no consume.
	cTok, _ := cs.mintContent("content-body", time.Minute)
	require.Equal(t, 1, cs.len())
	_, ok := cs.lookupKind(cTok, kindBootstrap, true)
	assert.False(t, ok, "a content token probed as bootstrap must miss")
	assert.Equal(t, 1, cs.len(), "a cross-class probe must NOT burn the content token")
	// The content token still resolves via its own class.
	body, ok := cs.getContent(cTok)
	require.True(t, ok, "the content token must survive the wrong-class probe")
	assert.Equal(t, "content-body", body)

	// bootstrap token probed via the content class (== lookupContent) → miss, no consume.
	bTok, _ := cs.mintBootstrap("bootstrap-body", time.Minute)
	require.Equal(t, 1, cs.len())
	_, ok = cs.lookupContent(bTok, true)
	assert.False(t, ok, "a bootstrap token probed as content must miss")
	assert.Equal(t, 1, cs.len(), "a cross-class probe must NOT burn the bootstrap token")
	// The bootstrap token still resolves via its own class.
	body, ok = cs.lookupKind(bTok, kindBootstrap, true)
	require.True(t, ok, "the bootstrap token must survive the wrong-class probe")
	assert.Equal(t, "bootstrap-body", body)
}

func TestLookupKind_TTLExpiry(t *testing.T) {
	clk := newContentClock()
	cs := newContentStore(clk.now)
	tok, _ := cs.mintBootstrap("ephemeral-bundle", 30*time.Second)

	_, ok := cs.lookupKind(tok, kindBootstrap, false)
	require.True(t, ok, "fresh bootstrap token must resolve")

	clk.advance(31 * time.Second)
	_, ok = cs.lookupKind(tok, kindBootstrap, true)
	assert.False(t, ok, "expired bootstrap token must miss")
	assert.Equal(t, 0, cs.len(), "expired entry must be pruned on lookup")
}

// TestMintBootstrap_CountedInCap proves bootstrap entries live in the same map
// and are bounded by the 512-cap drop-oldest across both kinds.
func TestMintBootstrap_CountedInCap(t *testing.T) {
	clk := newContentClock()
	cs := newContentStore(clk.now)

	// Fill the store to the cap mixing content and bootstrap entries.
	for i := 0; i < maxContentEntries; i++ {
		if i%2 == 0 {
			cs.mintContent(fmt.Sprintf("c-%d", i), time.Hour)
		} else {
			cs.mintBootstrap(fmt.Sprintf("b-%d", i), time.Hour)
		}
		clk.advance(time.Millisecond)
	}
	require.Equal(t, maxContentEntries, cs.len())

	// One more bootstrap mint must drop-oldest, not grow past the cap.
	cs.mintBootstrap("overflow-bundle", time.Hour)
	assert.Equal(t, maxContentEntries, cs.len(),
		"bootstrap entries must be counted by the 512-cap (drop-oldest across both kinds)")
}

// TestDropOldest_SparesBootstrapUnderContentFlood proves the BACK-09 eviction
// invariant: a pending (not-yet-fetched) bootstrap token must SURVIVE a flood of
// content tokens, even though it is the oldest + longest-lived entry. A
// class-blind drop-oldest would evict it first and silently break first-contact
// enrollment; drop-oldest must prefer content victims and spare bootstrap.
func TestDropOldest_SparesBootstrapUnderContentFlood(t *testing.T) {
	clk := newContentClock()
	cs := newContentStore(clk.now)

	// Mint the bootstrap token FIRST so it has the earliest mint time (the entry
	// a class-blind drop-oldest would target) and a long TTL.
	bootTok, _ := cs.mintBootstrap("enroll-bundle", 15*time.Minute)
	clk.advance(time.Millisecond)

	// Flood the store well past the cap with newer content tokens.
	for i := 0; i < maxContentEntries+50; i++ {
		cs.mintContent(fmt.Sprintf("flood-%d", i), time.Hour)
		clk.advance(time.Millisecond)
	}
	assert.Equal(t, maxContentEntries, cs.len(), "store stays within the cap")

	// The bootstrap token must still be fetchable — content churn evicted other
	// content entries, never the pending bootstrap one.
	body, ok := cs.lookupKind(bootTok, kindBootstrap, true)
	require.True(t, ok, "pending bootstrap token must survive a content flood (BACK-09)")
	assert.Equal(t, "enroll-bundle", body)

	// Sanity: when ALL entries are bootstrap, drop-oldest still evicts one (the
	// fallback path) so the cap is never exceeded.
	cs2 := newContentStore(clk.now)
	for i := 0; i < maxContentEntries+5; i++ {
		cs2.mintBootstrap(fmt.Sprintf("b-%d", i), time.Hour)
		clk.advance(time.Millisecond)
	}
	assert.Equal(t, maxContentEntries, cs2.len(),
		"all-bootstrap store still respects the cap (drop-oldest falls back to bootstrap)")
}
