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

package approve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// CAS state constants for pendingReq.state.
const (
	statePending  uint32 = 0
	stateApproved uint32 = 1
	stateDenied   uint32 = 2
	stateTimeout  uint32 = 3
)

// StateApproved and StateDenied are exported aliases for the CAS state
// constants so callers in other packages (e.g. daemon) can pass the
// correct value to Registry.Resolve without using magic numbers.
const (
	StateApproved = stateApproved
	StateDenied   = stateDenied
)

// ErrDenied is returned by Wait when the request was denied (either explicitly
// or via headless timeout).
var ErrDenied = errors.New("approve: request denied")

// ErrTimeout is returned by Wait when the context expires with a TTY available,
// signalling the caller to fall back to a local TTY confirm.
var ErrTimeout = errors.New("approve: request timed out — falling back to TTY confirm")

// Resolution is the outcome of a single pending approval request.
type Resolution struct {
	// Approved is true only when a phone or TTY explicitly approved the action.
	// No timeout, error, or restart path ever produces Approved:true.
	Approved bool
}

// ApprovalToken carries the request identity and closure hash so callers can
// thread it into Gated.Run for TOCTOU re-verification at exec time (D-02,
// APPR-01).
type ApprovalToken struct {
	RequestID   string
	ClosureHash [32]byte
	Tier        TierLevel
}

// pendingReq is one in-flight approval request. It is memory-only and safe for
// concurrent use: state is a CAS atomic, ch is written exactly once (buffered).
type pendingReq struct {
	state       atomic.Uint32 // CAS: statePending → stateApproved|stateDenied|stateTimeout
	requestID   string
	closureHash [32]byte
	tier        TierLevel
	ch          chan Resolution // buffered(1), written exactly once on resolution
	hmacSig     string          // stored for handler verify at resolution time (D-16)
}

// resolve attempts a single CAS transition from statePending to newState.
// On success it sends one Resolution to ch and returns true. On failure (another
// goroutine already won the CAS) it logs at Debug and returns false. This is the
// first-answer-wins invariant (APPR-02).
func (p *pendingReq) resolve(newState uint32) bool {
	if !p.state.CompareAndSwap(statePending, newState) {
		slog.Debug("approve: late resolution ignored — first answer already won",
			"request_id", safePrefix(p.requestID),
		)
		return false
	}
	p.ch <- Resolution{Approved: newState == stateApproved}
	return true
}

// safePrefix returns the first 8 bytes of id for logging — never the full ID
// which could act as a secret (T-30-06).
func safePrefix(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// openOption is an internal functional option for Registry.Open.
type openOption struct {
	actionName string
}

// OpenOption is a functional option for Registry.Open.
type OpenOption func(*openOption)

// WithActionName supplies the action name used for tier resolution at Open time.
// If not provided, the declared tier is used as-is without tier force-upgrade.
func WithActionName(name string) OpenOption {
	return func(o *openOption) { o.actionName = name }
}

// Registry is the in-memory pending-request store. It is safe for concurrent
// use. State is memory-only: a daemon restart drops all pending requests so
// in-flight waits resolve to deny, never approve (APPR-02, D-11).
type Registry struct {
	now func() time.Time

	mu      sync.Mutex
	pending map[string]*pendingReq
}

// NewRegistry returns an empty Registry using now as its clock. A nil now
// defaults to time.Now; tests inject a fake clock.
func NewRegistry(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{
		now:     now,
		pending: make(map[string]*pendingReq),
	}
}

// Open registers a new pending approval request. It resolves the effective tier
// via Tier(); if the effective tier is TierCritical it returns
// ErrCriticalTierTTYOnly immediately and adds nothing to the pending map
// (APPR-04, D-07). Otherwise it stores the request and returns the *pendingReq
// so the caller can pass it to Wait.
//
// The returned *pendingReq is the live state object; callers must not mutate its
// fields directly (they are either immutable after Open or CAS-guarded).
func (r *Registry) Open(requestID string, closureHash [32]byte, declared TierLevel, hmacSig string, opts ...OpenOption) (*pendingReq, error) {
	opt := &openOption{}
	for _, o := range opts {
		o(opt)
	}

	// Tier resolution: force-upgrade if the action name matches a critical pattern.
	effective := declared
	if opt.actionName != "" {
		effective = Tier(declared, opt.actionName, nil)
	}
	if effective == TierCritical {
		return nil, ErrCriticalTierTTYOnly
	}

	req := &pendingReq{
		requestID:   requestID,
		closureHash: closureHash,
		tier:        effective,
		ch:          make(chan Resolution, 1),
		hmacSig:     hmacSig,
	}
	// statePending is the zero value for atomic.Uint32; no explicit Store needed.

	r.mu.Lock()
	r.pending[requestID] = req
	r.mu.Unlock()

	return req, nil
}

// Resolve transitions the named request from statePending to newState via CAS.
// It returns true if this call won the CAS; false if the request was not found
// (already pruned, never opened, or a duplicate call). Callers should pass
// stateApproved or stateDenied; stateTimeout is reserved for Wait.
func (r *Registry) Resolve(requestID string, newState uint32) bool {
	r.mu.Lock()
	req, ok := r.pending[requestID]
	r.mu.Unlock()

	if !ok {
		slog.Warn("approve: resolve called for unknown request — late or duplicate",
			"request_id", safePrefix(requestID),
		)
		return false
	}
	return req.resolve(newState)
}

// Wait blocks until the request resolves, the context expires, or the caller
// cancels. On context expiry:
//   - hasTTY=true: returns (Resolution{}, ErrTimeout) so the caller can fall
//     back to a local TTY confirm (APPR-02, D-09).
//   - hasTTY=false: calls resolve(stateDenied) and returns
//     (Resolution{Approved:false}, ErrDenied). No timeout or error path ever
//     produces Approved:true (APPR-02, D-10).
func (r *Registry) Wait(ctx context.Context, req *pendingReq, hasTTY bool) (Resolution, error) {
	select {
	case res := <-req.ch:
		if !res.Approved {
			return res, ErrDenied
		}
		return res, nil
	case <-ctx.Done():
		if hasTTY {
			return Resolution{}, ErrTimeout
		}
		// Headless: force deny. Ignore the bool return — if another goroutine
		// already resolved (unlikely here), the channel already has one entry
		// and we simply don't block.
		req.resolve(stateDenied) //nolint:errcheck // resolve returns bool, not error
		// Drain the channel if our resolve() won — so the caller gets a clean
		// Approved:false result. If we lost the CAS race the channel already
		// has the winner's result; don't drain it (leave it for the next Wait).
		select {
		case res := <-req.ch:
			_ = res // we already know it's denied
		default:
		}
		return Resolution{Approved: false}, ErrDenied
	}
}

// WaitByID looks up the pending request by requestID and calls Wait. It is a
// convenience method for callers (e.g. daemon's handleApproveWait) that hold
// only the requestID, not the *pendingReq pointer. Returns (Resolution{}, err)
// if the request is not found (err wraps approve.ErrDenied in that case).
func (r *Registry) WaitByID(ctx context.Context, requestID string, hasTTY bool) (Resolution, error) {
	r.mu.Lock()
	req, ok := r.pending[requestID]
	r.mu.Unlock()
	if !ok {
		return Resolution{}, fmt.Errorf("approve: WaitByID: request not found: %s", safePrefix(requestID))
	}
	return r.Wait(ctx, req, hasTTY)
}

// Prune removes a request from the pending map after its lifecycle is complete.
// It should be called after Wait returns to release memory. Calling Prune on an
// unknown requestID is a no-op.
func (r *Registry) Prune(requestID string) {
	r.mu.Lock()
	delete(r.pending, requestID)
	r.mu.Unlock()
}

// Lookup retrieves the stored hmacSig, closureHash, and tier for a pending
// request without advancing its CAS state. It is used by the daemon's
// handleApprove/handleDeny to fetch the fields stored at Open() time before
// calling VerifyApproveURL and Resolve() (D-16, BLOCKER-2 fix). Returns
// ("", [32]byte{}, TierBenign, false) if the request is not found.
func (r *Registry) Lookup(requestID string) (hmacSig string, closureHash [32]byte, tier TierLevel, ok bool) {
	r.mu.Lock()
	req, found := r.pending[requestID]
	r.mu.Unlock()

	if !found {
		return "", [32]byte{}, TierBenign, false
	}
	return req.hmacSig, req.closureHash, req.tier, true
}

// Token returns an ApprovalToken for the given request, suitable for threading
// into Gated.Run for TOCTOU re-verification at exec time (D-02, APPR-01).
func Token(req *pendingReq) ApprovalToken {
	return ApprovalToken{
		RequestID:   req.requestID,
		ClosureHash: req.closureHash,
		Tier:        req.tier,
	}
}

// Errorf wraps an error with the approve package prefix.
func Errorf(format string, args ...any) error {
	return fmt.Errorf("approve: "+format, args...)
}
