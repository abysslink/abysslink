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
	// bootstrapTokenPrefix namespaces first-contact bootstrap tokens (BACK-09)
	// so they are structurally distinguishable from content tokens ("ablk_c_")
	// in any debug surface. The suffix is 16 bytes of crypto/rand, base64url
	// no-pad (≥128-bit entropy — same mint as content tokens).
	bootstrapTokenPrefix = "ablk_e_"
	// maxContentEntries bounds daemon memory: at the 64 KiB body cap, 512
	// entries are at most 32 MiB. Beyond the bound the OLDEST entry is
	// dropped with a warning (drop-oldest, never an error to the caller).
	maxContentEntries = 512
	// contentPruneInterval is the background expiry sweep cadence; pruning
	// additionally runs inline on every mint and get.
	contentPruneInterval = 60 * time.Second
)

// entryKind discriminates the capability class of a store entry (BACK-09).
// content entries serve GET /content/{token} bearer-gated; bootstrap entries
// serve the first-contact GET /enroll/{token} bearer-LESS. The kind is checked
// BEFORE the single-use consume (see lookupKind) so a cross-class probe can
// neither read the wrong body class nor burn a victim's live token.
type entryKind string

const (
	// kindContent is a BACK-06 message-body entry (bearer-gated /content/).
	kindContent entryKind = "content"
	// kindBootstrap is a BACK-09 first-contact credential-bundle entry
	// (bearer-LESS /enroll/).
	kindBootstrap entryKind = "bootstrap"
	// kindApprove is a single-use approve-button capability URL (Phase 30 D-14).
	// Served bearer-LESS by GET /approve/{token}; resolves pendingReq to Approved.
	kindApprove entryKind = "approve"
	// kindDeny is a single-use deny-button capability URL (Phase 30 D-14).
	// Served bearer-LESS by GET /deny/{token}; resolves pendingReq to Denied.
	kindDeny entryKind = "deny"
)

const (
	// approveTokenPrefix namespaces approve-button capability URLs so they are
	// visually distinguishable from other token types in debug surfaces. The
	// suffix is 16 bytes crypto/rand base64url no-pad (≥128-bit entropy).
	approveTokenPrefix = "ablk_ok_"
	// denyTokenPrefix namespaces deny-button capability URLs.
	denyTokenPrefix = "ablk_no_"
)

// contentEntry is one minted token→body binding. Single-purpose: a token maps
// to exactly one body for its whole lifetime (one body per token); it is
// never reused or rebound.
type contentEntry struct {
	body    string
	kind    entryKind // BACK-09: capability class, checked BEFORE the consume
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

// mintKind stores body under a fresh single-purpose token of the given
// capability class and prefix, valid for ttl, and returns the token and its
// expiry instant (BACK-09). It generalizes mintContent: the IDENTICAL lock →
// prune → drop-oldest-to-cap → insert sequence, stamping kind on the entry.
// Expired entries are pruned first; if the store is still at maxContentEntries,
// the oldest entry is dropped with a warning (metadata only — never body
// content in the log). Bootstrap entries share this map, so they are counted
// and 512-bounded exactly like content entries.
func (c *contentStore) mintKind(prefix string, kind entryKind, body string, ttl time.Duration) (string, time.Time) {
	buf := make([]byte, 16)
	// crypto/rand.Read never returns an error on Go >= 1.24 (the runtime
	// aborts if the OS entropy source is broken), so this cannot fail in
	// normal control flow.
	_, _ = rand.Read(buf)
	token := prefix + base64.RawURLEncoding.EncodeToString(buf)

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.pruneLocked(now)
	for len(c.entries) >= maxContentEntries {
		c.dropOldestLocked()
	}
	expires := now.Add(ttl)
	c.entries[token] = contentEntry{body: body, kind: kind, expires: expires, minted: now}
	return token, expires
}

// mintContent stores body under a fresh single-purpose content token valid for
// ttl and returns the token and its expiry instant. Thin wrapper over mintKind
// (kindContent) — the BACK-06 signature and behavior are preserved unchanged.
func (c *contentStore) mintContent(body string, ttl time.Duration) (string, time.Time) {
	return c.mintKind(contentTokenPrefix, kindContent, body, ttl)
}

// mintBootstrap stores body under a fresh single-use first-contact
// credential-bundle token valid for ttl (BACK-09). The token carries the
// bootstrapTokenPrefix and is served bearer-LESS by GET /enroll/{token}.
func (c *contentStore) mintBootstrap(body string, ttl time.Duration) (string, time.Time) {
	return c.mintKind(bootstrapTokenPrefix, kindBootstrap, body, ttl)
}

// mintApprove stores requestID under a fresh single-use approve-button
// capability URL token valid for ttl (Phase 30 D-14). Served bearer-LESS by
// GET /approve/{token}; resolves pendingReq to Approved on lookup.
func (c *contentStore) mintApprove(requestID string, ttl time.Duration) (string, time.Time) {
	return c.mintKind(approveTokenPrefix, kindApprove, requestID, ttl)
}

// mintDeny stores requestID under a fresh single-use deny-button capability
// URL token valid for ttl (Phase 30 D-14). Served bearer-LESS by
// GET /deny/{token}; resolves pendingReq to Denied on lookup.
func (c *contentStore) mintDeny(requestID string, ttl time.Duration) (string, time.Time) {
	return c.mintKind(denyTokenPrefix, kindDeny, requestID, ttl)
}

// getContent returns the body bound to token, or ("", false) when the token
// is unknown or expired. The token is consumed on a successful read: it is
// deleted before returning so each minted token serves exactly one fetch
// (true single-use — a replayed token within the TTL gets nothing). Expired
// entries are pruned on every call so a lookup can never serve a past-TTL body.
func (c *contentStore) getContent(token string) (string, bool) {
	return c.lookupContent(token, true)
}

// lookupKind is the kind-aware lookup core (BACK-09). It always does the SAME
// work (lock + prune + map lookup) regardless of outcome, so a handler can run
// an identical lookup on every path — no timing oracle distinguishes an absent,
// expired, or wrong-class token (all return ("", false) → the same uniform
// 404). The capability-class guard `e.kind != want` sits INSIDE the critical
// section, BEFORE the single-use delete, so a class mismatch is a MISS that
// DELETES NOTHING: a cross-class probe can never burn a victim's live token
// (the one load-bearing BACK-09 invariant; Pitfall 1). When kind matches and
// consume is true the entry is deleted (single-use); when consume is false the
// entry is left intact — an auth-failed request must NEVER consume a valid
// token.
func (c *contentStore) lookupKind(token string, want entryKind, consume bool) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(c.now())
	e, ok := c.entries[token]
	if !ok || e.kind != want {
		return "", false
	}
	if consume {
		delete(c.entries, token)
	}
	return e.body, true
}

// lookupContent is getContent with an explicit consume flag. Thin wrapper over
// lookupKind (kindContent) so the bearer-gated /content/ route rejects a
// bootstrap token automatically (kind mismatch → uniform miss). The BACK-06
// constant-work / single-use behavior is preserved unchanged.
func (c *contentStore) lookupContent(token string, consume bool) (string, bool) {
	return c.lookupKind(token, kindContent, consume)
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

// dropOldestLocked removes one entry to keep the store within maxContentEntries
// (bounded store, drop-oldest). It PREFERS the oldest content entry as the
// victim and evicts a bootstrap entry ONLY when every entry is a bootstrap one
// (BACK-09). Rationale: a first-contact bootstrap token is rare (one per active
// enrollment), long-lived (it must survive its full enroll TTL until the phone
// scans the QR), and the single most important entry to preserve — a
// class-blind drop-oldest would always target it FIRST (it is both the oldest
// and the longest-lived), silently breaking enrollment under content-mint
// churn. Exempting it costs almost nothing (bootstrap entries are few and
// short-TTL bounded) while keeping the 512-entry memory bound intact. NET-11
// voice: the drop is logged, never silent — metadata only (kind + age), no body
// content and no token value in the log line. Caller holds c.mu and guarantees
// len(c.entries) > 0.
func (c *contentStore) dropOldestLocked() {
	var oldestTok string
	var oldest time.Time
	var oldestKind entryKind
	first := true
	for tok, e := range c.entries {
		// Eviction preference order (lowest = evict first):
		// 1. kindContent, kindApprove, kindDeny  — evictable at the same priority
		// 2. kindBootstrap — spared while any content/approve/deny entry exists
		// Within the same priority class the earliest mint wins. This ensures
		// bootstrap tokens (rare, long-lived first-contact credentials) are
		// never dropped while approve/deny/content tokens exist (BACK-09 + D-14).
		isEvictable := e.kind == kindContent || e.kind == kindApprove || e.kind == kindDeny
		oldestIsBootstrap := oldestKind == kindBootstrap
		better := first ||
			(oldestIsBootstrap && isEvictable) ||
			(oldestKind == e.kind && e.minted.Before(oldest))
		if better {
			oldestTok, oldest, oldestKind, first = tok, e.minted, e.kind, false
		}
	}
	slog.Warn("daemon: content store full — dropping oldest entry",
		"max_entries", maxContentEntries, "dropped_kind", string(oldestKind),
		"dropped_age", c.now().Sub(oldest).String())
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
