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

// Package cli — abysslink approve subcommand (APPR-06, D-15).
//
// This file is the ONLY place in the codebase where Claude Code hook JSON
// schemas (PreToolUse, PermissionRequest) are parsed. All other packages
// (internal/approve, internal/gate, internal/daemon) are Claude-agnostic.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/abysslink/abysslink/internal/daemon"
	"github.com/spf13/cobra"
)

// approveExitCodeDeny is the exit code that signals Claude Code to block tool
// execution. Exit 2 is the PreToolUse blocking mechanism per Claude Code docs
// and the #19298 workaround: the PermissionRequest deny path is unreliable,
// so PreToolUse + exit 2 is the primary gating mechanism.
const approveExitCodeDeny = 2

// preToolUseInput is the stdin JSON shape for a PreToolUse hook invocation.
// Only tool_name and tool_input are used; all other fields are ignored.
type preToolUseInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// permissionRequestInput is the stdin JSON shape for a PermissionRequest
// hook invocation. Only tool_name is used; all other fields are ignored.
type permissionRequestInput struct {
	ToolName string `json:"tool_name"`
}

// approveRequestPayload is the POST /approve/request JSON body.
type approveRequestPayload struct {
	Action        string   `json:"action"`
	ClosureHash   string   `json:"closure_hash"`
	DeclaredTier  int      `json:"declared_tier"`
	ExtraCritical []string `json:"extra_critical,omitempty"`
}

// approveRequestResponse is the POST /approve/request JSON response.
type approveRequestResponse struct {
	RequestID  string `json:"request_id"`
	ApproveURL string `json:"approve_url"`
	DenyURL    string `json:"deny_url"`
	ExpiresAt  string `json:"expires_at"`
}

// approveWaitResponse is the GET /approve/wait/{id} JSON response.
type approveWaitResponse struct {
	Approved  bool   `json:"approved"`
	RequestID string `json:"request_id"`
}

// permissionRequestAllowOutput is the stdout JSON written by --permission-request.
// Claude Code reads this and applies the allow decision.
type permissionRequestAllowOutput struct {
	HookSpecificOutput struct {
		HookEventName string `json:"hookEventName"`
		Decision      struct {
			Behavior string `json:"behavior"`
		} `json:"decision"`
	} `json:"hookSpecificOutput"`
}

// approveDialTimeout is the connection timeout when dialling the daemon unix socket.
// Unreachable daemon → deny immediately within this window (T-30-20).
const approveDialTimeout = 5 * time.Second

// newApproveCmd builds the approve subcommand.
//
// The approve subcommand is the Claude Code hook executor (APPR-06). It is
// NOT user-facing in the conventional sense — it is invoked by Claude Code
// hooks configured by claudecode.Apply(). It runs as a subprocess.
//
// Two modes:
//
//	--check [--blocking]: PreToolUse hook executor. Reads hook JSON from stdin,
//	  calls daemon IPC /approve/request + /approve/wait/{id}, blocks until
//	  resolved, exits 0 (approved) or 2 (denied). The D-03 phone+TTY race is
//	  implemented CLI-side: both goroutines resolve the same CAS registry entry;
//	  first answer wins; the loser's attempt returns a CAS no-op from the daemon.
//
//	--permission-request: PermissionRequest hook executor. Reads hook JSON from
//	  stdin, fires notification asynchronously (fire-and-forget), writes allow
//	  JSON to stdout immediately, exits 0 (#12176 workaround: must return < 1s).
func newApproveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Claude Code hook executor (approve loop — invoked by hooks, not directly by users)",
		Example: `  # PreToolUse hook (configured automatically by 'abysslink up --apply'):
  abysslink approve --check --blocking < hook.json

  # PermissionRequest hook executor:
  abysslink approve --permission-request < hook.json`,
		Long: `abysslink approve is invoked by Claude Code hooks configured by 'abysslink up --apply'.
It is not meant to be run directly by users.

Two modes:

  --check [--blocking]      PreToolUse hook executor. Reads PreToolUse JSON from stdin,
                            sends an approve request to the daemon, blocks until the phone
                            or TTY approves/denies, then exits 0 (approved) or 2 (denied).
                            Exit 2 is the Claude Code PreToolUse blocking mechanism (#19298).

  --permission-request      PermissionRequest hook executor. Reads PermissionRequest JSON
                            from stdin, fires a notification asynchronously (non-blocking),
                            writes allow JSON to stdout immediately, exits 0.
                            (#12176 workaround: PermissionRequest deny is unreliable; use
                             PreToolUse + exit 2 for blocking instead.)`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			check, _ := cmd.Flags().GetBool("check")
			blocking, _ := cmd.Flags().GetBool("blocking")
			permReq, _ := cmd.Flags().GetBool("permission-request")

			if check {
				return runApproveCheck(cmd.Context(), blocking)
			}
			if permReq {
				return runApprovePermissionRequest(cmd.Context())
			}
			return fmt.Errorf("approve: one of --check or --permission-request is required")
		},
	}
	cmd.Flags().Bool("check", false, "PreToolUse hook mode: read hook JSON from stdin, block until phone/TTY resolves, exit 0/2")
	cmd.Flags().Bool("blocking", false, "used with --check: apply the full cfg.Approval.TimeoutSeconds deadline (omit for a short test timeout)")
	cmd.Flags().Bool("permission-request", false, "PermissionRequest hook mode: fire notification async, write allow JSON to stdout, return immediately")
	return cmd
}

// runApproveCheck implements the PreToolUse hook executor (--check [--blocking]).
//
// Protocol (D-03 race — first answer wins):
//  1. Read PreToolUse JSON from stdin; extract tool_name + tool_input.
//  2. Build action identifier and closure hash.
//  3. Dial daemon unix socket (timeout 5s). Unreachable → exit 2 (deny, D-10).
//  4. POST /approve/request → get requestID.
//  5. Launch two goroutines concurrently:
//     a. Phone arm: GET /approve/wait/{id} — blocks until daemon resolves.
//     b. TTY arm (if hasTTY): open /dev/tty, prompt "Approve? [y/N]",
//     POST /approve/resolve/{id} with the answer.
//  6. Select first result from shared channel.
//  7. Exit 0 (approved) or exit 2 (denied/timeout/error).
func runApproveCheck(ctx context.Context, blocking bool) error {
	// Read stdin — the PreToolUse hook JSON.
	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		slog.Error("approve: read stdin", "err", err)
		return &exitError{code: approveExitCodeDeny}
	}

	var input preToolUseInput
	if err := json.Unmarshal(stdinBytes, &input); err != nil {
		slog.Error("approve: parse PreToolUse JSON", "err", err)
		return &exitError{code: approveExitCodeDeny}
	}
	if input.ToolName == "" {
		slog.Error("approve: tool_name is empty in PreToolUse JSON")
		return &exitError{code: approveExitCodeDeny}
	}

	// Build closure hash: sha256(tool_name + tool_input_json).
	// tool_input is treated as opaque data for hashing (never exec'd, T-30-21).
	toolInputJSON := string(input.ToolInput)
	if toolInputJSON == "" {
		toolInputJSON = "{}"
	}
	hashSrc := "claude:" + input.ToolName + ":" + toolInputJSON
	rawHash := sha256.Sum256([]byte(hashSrc))
	closureHashHex := hex.EncodeToString(rawHash[:])

	// Set up the approval timeout.
	timeout := 120 * time.Second // default (cfg.Approval.TimeoutSeconds default)
	if !blocking {
		timeout = 10 * time.Second // short for tests / no-daemon path
	}
	approveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Dial daemon with a tight connection timeout.
	sockPath := daemon.SocketPath()
	if sockPath == "" {
		slog.Error("approve: daemon socket path unavailable")
		return &exitError{code: approveExitCodeDeny}
	}

	httpClient := daemonHTTPClient(sockPath, approveDialTimeout)

	// POST /approve/request.
	payload := approveRequestPayload{
		Action:       input.ToolName,
		ClosureHash:  closureHashHex,
		DeclaredTier: 1, // TierSensitive — default for all Claude tool execs
	}
	reqResp, err := postApproveRequest(approveCtx, httpClient, payload)
	if err != nil {
		slog.Error("approve: POST /approve/request failed", "err", err)
		return &exitError{code: approveExitCodeDeny}
	}
	if reqResp.RequestID == "" {
		slog.Error("approve: empty request_id in daemon response")
		return &exitError{code: approveExitCodeDeny}
	}

	// Shared result channel (buffered 1 — first send wins, D-03).
	resultCh := make(chan bool, 1)

	// Phone arm: GET /approve/wait/{id} — long-poll until daemon resolves.
	go func() {
		approved := waitApproveResult(approveCtx, httpClient, reqResp.RequestID)
		select {
		case resultCh <- approved:
		default:
		}
	}()

	// TTY arm: if we have a controlling terminal, open /dev/tty and prompt.
	launchTTYArm(approveCtx, sockPath, reqResp.RequestID, input.ToolName, resultCh)

	// Select: wait for first answer or timeout.
	select {
	case approved := <-resultCh:
		if approved {
			return nil // exit 0
		}
		return &exitError{code: approveExitCodeDeny} // exit 2
	case <-approveCtx.Done():
		// Timeout: if no TTY this is headless deny (D-10).
		// If TTY was available but didn't answer in time, still deny.
		return &exitError{code: approveExitCodeDeny} // exit 2
	}
}

// runApprovePermissionRequest implements the PermissionRequest hook executor.
//
// Per #12176 workaround: must return within ~1s. Strategy: fire notification
// asynchronously (goroutine) and immediately return allow JSON to stdout.
// The PreToolUse hook (--check) is the actual blocking gate.
//
// WR-05: on a stdin read error the fast-allow path is skipped (do NOT emit
// allow on an input failure — a security tool must not default-allow on error).
// The PreToolUse --check gate is the authoritative blocking path; when stdin
// is unreadable, the safest response is to not allow and let Claude's default
// behaviour stand. We return nil (exit 0) so Claude Code does not treat it as
// an unexpected hook failure, but we write no allow JSON.
func runApprovePermissionRequest(ctx context.Context) error {
	// Read stdin — the PermissionRequest hook JSON.
	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		// WR-05: do NOT fall through to allow — emit no allow JSON on read error.
		slog.Warn("approve: read PermissionRequest stdin failed — not emitting allow (WR-05)", "err", err)
		return nil // exit 0; Claude's default stands; PreToolUse --check is the real gate
	}

	var input permissionRequestInput
	if len(stdinBytes) > 0 {
		_ = json.Unmarshal(stdinBytes, &input) // best-effort; tool_name may be empty
	}

	// Fire notification asynchronously (fire-and-forget).
	// We do NOT wait for this to complete (#12176: must return < 1s).
	if input.ToolName != "" {
		go func() {
			sockPath := daemon.SocketPath()
			if sockPath == "" {
				return
			}
			notifyCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			hc := daemonHTTPClient(sockPath, approveDialTimeout)
			body, _ := json.Marshal(map[string]interface{}{
				"v":     2,
				"kind":  "approval_request",
				"title": "approve " + input.ToolName + "?",
				"body":  "Claude Code is requesting permission to use " + input.ToolName,
			})
			req, err := http.NewRequestWithContext(notifyCtx, http.MethodPost, "http://unix/notify", bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := hc.Do(req)
			if err != nil {
				return
			}
			defer func() { _ = resp.Body.Close() }()
		}()
	}

	// Write allow JSON to stdout immediately (#12176 workaround).
	// The PreToolUse hook will do the actual blocking.
	var out permissionRequestAllowOutput
	out.HookSpecificOutput.HookEventName = "PermissionRequest"
	out.HookSpecificOutput.Decision.Behavior = "allow"
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		slog.Warn("approve: write allow JSON to stdout", "err", err)
	}
	_ = ctx    // context reserved; not blocking
	return nil // exit 0
}

// postApproveRequest POSTs to /approve/request and returns the parsed response.
func postApproveRequest(ctx context.Context, hc *http.Client, payload approveRequestPayload) (*approveRequestResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/approve/request", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("critical tier — TTY approval required (D-07)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("daemon returned HTTP %d", resp.StatusCode)
	}
	var out approveRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// waitApproveResult GETs /approve/wait/{id} and returns true if approved.
// Returns false on any error, timeout, or denial.
func waitApproveResult(ctx context.Context, hc *http.Client, requestID string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/approve/wait/"+requestID, nil)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusRequestTimeout {
		return false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	var out approveWaitResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}
	return out.Approved
}

// launchTTYArm starts the D-03 TTY approval arm when a controlling terminal is
// available. It reports its answer on resultCh ONLY when it won the daemon CAS
// (authoritative). When it loses the CAS (the phone arm resolved first), the
// resolve fails, or no TTY is present, it stays silent so the phone arm reports
// the daemon's authoritative decision — never a contradictory local answer.
func launchTTYArm(ctx context.Context, sockPath, requestID, toolName string, resultCh chan<- bool) {
	if !hasTTYAvailable() {
		return
	}
	go func() {
		approved, authoritative := promptTTY(ctx, sockPath, requestID, toolName)
		if !authoritative {
			return
		}
		select {
		case resultCh <- approved:
		default:
		}
	}()
}

// promptTTY opens /dev/tty directly (not os.Stdin which holds hook JSON),
// prompts the user, then POSTs to /approve/resolve/{id} on the daemon so the
// CAS registry entry is resolved — the same registry as the phone arm (D-03).
//
// It returns (approved, authoritative). authoritative is true ONLY when this TTY
// arm WON the daemon CAS — i.e. the daemon recorded this answer as the decision.
// When authoritative is false (the phone arm resolved first, the user did not
// answer, or the resolve POST failed) the caller MUST NOT report this arm's
// answer: the phone arm's GET /approve/wait returns the daemon's authoritative
// resolution instead. This prevents the two arms from reporting contradictory
// results (D-03 first-answer-wins consistency) — previously promptTTY returned
// its LOCAL answer regardless of the CAS outcome, so a TTY "deny" racing a phone
// "approve" could make the CLI exit deny even though the daemon approved.
func promptTTY(ctx context.Context, sockPath, requestID, toolName string) (approved bool, authoritative bool) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0) //nolint:gosec // G304: /dev/tty is a well-known device, not user input
	if err != nil {
		return false, false
	}
	defer func() { _ = tty.Close() }()

	_, _ = fmt.Fprintf(tty, "Abysslink: approve %q tool call? [y/N]: ", toolName)

	scanner := bufio.NewScanner(tty)
	doneCh := make(chan string, 1)
	go func() {
		if scanner.Scan() {
			doneCh <- scanner.Text()
		} else {
			doneCh <- ""
		}
	}()

	var line string
	select {
	case line = <-doneCh:
	case <-ctx.Done():
		return false, false
	}

	approved = line == "y" || line == "Y"

	// Resolve the same CAS registry entry via the daemon so the phone arm's
	// concurrent WaitByID unblocks — CAS ensures only the first answer wins.
	// The POST /approve/resolve/{id} endpoint was added in CR-02.
	resolveAction := "deny"
	if approved {
		resolveAction = "approve"
	}
	resolveURL := "http://unix/approve/resolve/" + requestID + "?action=" + resolveAction
	hc := daemonHTTPClient(sockPath, approveDialTimeout)
	resolveReq, err := http.NewRequestWithContext(ctx, http.MethodPost, resolveURL, nil)
	if err != nil {
		// URL-build failure (should never happen). We cannot confirm the daemon
		// recorded our answer — defer to the phone arm (fail-closed).
		slog.Warn("approve: build resolve request failed — deferring to phone arm", "err", err)
		return approved, false
	}
	resp, doErr := hc.Do(resolveReq)
	if doErr != nil {
		// The resolve POST failed: the daemon may not have resolved the entry, so
		// we cannot claim our answer is the decision. Defer to the phone arm — its
		// wait will time out to a deny if nothing else resolves (fail-closed).
		slog.Warn("approve: POST /approve/resolve failed — deferring to phone arm", "err", doErr)
		return approved, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.Warn("approve: POST /approve/resolve returned non-2xx — deferring to phone arm", "status", resp.StatusCode)
		return approved, false
	}

	// Parse the CAS outcome: won=true means THIS arm's answer is the recorded
	// decision; won=false means the phone arm already resolved it — defer so the
	// phone arm reports the authoritative answer rather than our (now stale) local one.
	var rr struct {
		Won bool `json:"won"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		slog.Warn("approve: decode resolve response failed — deferring to phone arm", "err", err)
		return approved, false
	}
	return approved, rr.Won
}

// hasTTYAvailable returns true if a controlling terminal is available for
// direct user input. It attempts to open /dev/tty (the controlling terminal
// device) which works even when os.Stdin is redirected (e.g. hook stdin holds
// the hook JSON). This is the correct TTY detection for a subprocess.
func hasTTYAvailable() bool {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0) //nolint:gosec // G304: /dev/tty is a well-known device, not user input
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// daemonHTTPClient builds an HTTP client that dials over the daemon unix socket.
// The dialTimeout controls how long the initial connection attempt waits before
// giving up — a short timeout ensures the approve subprocess exits quickly when
// the daemon is not running (T-30-20).
func daemonHTTPClient(sockPath string, dialTimeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
				defer cancel()
				return (&net.Dialer{}).DialContext(dialCtx, "unix", sockPath)
			},
		},
	}
}
