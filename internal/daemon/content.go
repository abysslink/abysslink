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
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"sync"
	"time"
)

// Content-store constants (BACK-06). The store is memory-first in the D-13
// spirit: bodies live in daemon memory only, are never written to disk, and
// are lost on restart — that is fine, because every wake also carries a safe
// non-empty fallback title that renders with zero network access (BACK-08).
const (
	// contentTokenPrefix namespaces content tokens so they are visually
	// distinguishable from push tokens ("ablk_p_") and bearers in any debug
	// surface. The suffix is 16 bytes of crypto/rand, base64url no-pad.
	contentTokenPrefix = "ablk_c_"
	// maxContentEntries bounds daemon memory: at the 64 KiB body cap, 512
	// entries are at most 32 MiB. Beyond the bound the OLDEST entry is
	// dropped with a warning (drop-oldest, never an error to the caller).
	maxContentEntries = 512
	// contentPruneInterval is the background expiry sweep cadence; pruning
	// additionally runs inline on every mint and get.
	contentPruneInterval = 60 * time.Second
)

// contentEntry is one minted token→body binding. Single-purpose: a token maps
// to exactly one body for its whole lifetime (one body per token); it is
// never reused or rebound.
type contentEntry struct {
	body    string
	expires time.Time
	minted  time.Time
}

// contentStore is the memory-first TTL'd token→body map behind the tailnet
// content listener (BACK-06). Safe for concurrent use. State is memory-only:
// nothing is ever persisted, and a daemon restart empties the store.
type contentStore struct {
	now func() time.Time

	mu      sync.Mutex
	entries map[string]contentEntry
}

// newContentStore returns an empty store using now as its clock (nil means
// time.Now; tests inject a fake).
func newContentStore(now func() time.Time) *contentStore {
	if now == nil {
		now = time.Now
	}
	return &contentStore{now: now, entries: make(map[string]contentEntry)}
}

// mintContent stores body under a fresh single-purpose token valid for ttl
// and returns the token and its expiry instant. Expired entries are pruned
// first; if the store is still at maxContentEntries, the oldest entry is
// dropped with a warning (metadata only — never body content in the log).
func (c *contentStore) mintContent(body string, ttl time.Duration) (string, time.Time) {
	buf := make([]byte, 16)
	// crypto/rand.Read never returns an error on Go >= 1.24 (the runtime
	// aborts if the OS entropy source is broken), so this cannot fail in
	// normal control flow.
	_, _ = rand.Read(buf)
	token := contentTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.pruneLocked(now)
	for len(c.entries) >= maxContentEntries {
		c.dropOldestLocked()
	}
	expires := now.Add(ttl)
	c.entries[token] = contentEntry{body: body, expires: expires, minted: now}
	return token, expires
}

// getContent returns the body bound to token, or ("", false) when the token
// is unknown or expired. Expired entries are pruned on every call so a lookup
// can never serve a past-TTL body.
func (c *contentStore) getContent(token string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	e, ok := c.entries[token]
	if !ok {
		return "", false
	}
	return e.body, true
}

// len reports the current entry count (test/diagnostic accessor).
func (c *contentStore) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// pruneLocked deletes every expired entry. Caller holds c.mu.
func (c *contentStore) pruneLocked(now time.Time) {
	for tok, e := range c.entries {
		if !e.expires.After(now) {
			delete(c.entries, tok)
		}
	}
}

// dropOldestLocked removes the entry with the earliest mint time (bounded
// store, drop-oldest). NET-11 voice: the drop is logged, never silent —
// metadata only, no body content and no token value in the log line. Caller
// holds c.mu and guarantees len(c.entries) > 0.
func (c *contentStore) dropOldestLocked() {
	var oldestTok string
	var oldest time.Time
	first := true
	for tok, e := range c.entries {
		if first || e.minted.Before(oldest) {
			oldestTok, oldest, first = tok, e.minted, false
		}
	}
	slog.Warn("daemon: content store full — dropping oldest entry",
		"max_entries", maxContentEntries, "dropped_age", c.now().Sub(oldest).String())
	delete(c.entries, oldestTok)
}

// runPruner sweeps expired entries every contentPruneInterval until ctx is
// cancelled. Started together with the content listener.
func (c *contentStore) runPruner(ctx context.Context) {
	ticker := time.NewTicker(contentPruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			c.pruneLocked(c.now())
			c.mu.Unlock()
		}
	}
}
