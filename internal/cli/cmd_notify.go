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

package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// notifyCmdBaseURL is a test seam: when non-empty, all --rig/--all-rigs per-rig
// POSTs target this base URL instead of the resolved ntfy address. Override in
// tests via httptest.Server.URL (mirrors ntfyBaseURL in notify/module.go but
// scoped to cli).
var notifyCmdBaseURL = "" //nolint:gochecknoglobals // gochecknoglobals: package-level var is a test/injection seam for base URL override; intentional

// validNotifyPriorities is the set of ntfy-accepted X-Priority values (1-5 plus
// their documented aliases). An empty string means "unset — server default".
var validNotifyPriorities = map[string]bool{ //nolint:gochecknoglobals // gochecknoglobals: immutable lookup table
	"": true, "min": true, "low": true, "default": true, "high": true,
	"max": true, "urgent": true, "1": true, "2": true, "3": true, "4": true, "5": true,
}

func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify [title] [body]",
		Short: "Send a notification via the ntfy backend or wrap a command",
		Example: `  # Send a simple notification
  abysslink notify "Build done" "CI passed"

  # Send a notification with body from stdin
  echo "output" | abysslink notify "Script done" --stdin

  # Urgent notification with a tag, to a non-default topic
  abysslink notify "Disk full" "/ at 98%" --priority urgent --tag warning --topic ops`,
	}

	cmd.Flags().Bool("stdin", false, "Read notification body from stdin")
	cmd.Flags().String("priority", "default", "Notification priority: min|low|default|high|max (urgent = max)")
	cmd.Flags().String("tag", "", "User-supplied label (ntfy X-Tags; comma-separate for multiple)")
	cmd.Flags().String("topic", "", "Routing key (default from config)")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		cc, err := loadCmdContext(c)
		if err != nil {
			return err
		}

		deps, err := buildDeps(ctx, cc)
		if err != nil {
			return fmt.Errorf("notify: %w", err)
		}
		nm := notifymod.New(deps)

		readStdin, _ := c.Flags().GetBool("stdin")

		// CLI-04: read and validate the delivery option flags, then thread them
		// through the notify module — declared flags must never be silently dropped.
		priority, _ := c.Flags().GetString("priority")
		if !c.Flags().Changed("priority") {
			priority = "" // flag left at default — let ntfy apply its server-side default
		}
		if !validNotifyPriorities[priority] {
			return fmt.Errorf("notify: invalid --priority %q (use min|low|default|high|max|urgent or 1-5)", priority)
		}
		tag, _ := c.Flags().GetString("tag")
		topicFlag, _ := c.Flags().GetString("topic")

		var title, message string
		if readStdin {
			body, readErr := io.ReadAll(os.Stdin)
			if readErr != nil {
				return fmt.Errorf("notify: read stdin: %w", readErr)
			}
			title = "notification"
			if len(args) > 0 {
				title = args[0]
			}
			message = strings.TrimSpace(string(body))
		} else if len(args) >= 2 {
			title = args[0]
			message = args[1]
		} else if len(args) == 1 {
			title = args[0]
			message = ""
		} else {
			return fmt.Errorf("notify: provide title and body, or use --stdin for body from stdin")
		}

		// --rig / --all-rigs branch: send per-rig HMAC-signed notifications
		// (SC-5, FLEET-02, CLI-05). --rig X targets only the named enrolled rig.
		rt, rigErr := resolveRigTargets(c, cc.cfg.Rigs)
		if rigErr != nil {
			return rigErr
		}
		if rt.fanOut && len(rt.rigs) > 0 {
			if topicFlag != "" {
				// CR-04 / T-14-14: each rig has its own isolated topic; a manual
				// override would break per-rig isolation.
				return fmt.Errorf("notify: --topic cannot be combined with --rig/--all-rigs — each rig has its own isolated topic")
			}
			return sendNotifyAllRigs(ctx, rt.rigs, deps.Keychain, title, message, rigNotifyOpts{
				baseURL:  resolveFleetNtfyBaseURL(ctx, cc, deps.Backend),
				priority: priority,
				tags:     tag,
			})
		}

		return nm.SendWithOptions(ctx, title, message, notifymod.SendOptions{
			Priority: priority,
			Tags:     tag,
			Topic:    topicFlag,
		})
	}

	return cmd
}

// rigNotifyOpts carries the resolved delivery options for the per-rig fan-out.
type rigNotifyOpts struct {
	baseURL  string // resolved ntfy base URL; the test seam (notifyCmdBaseURL) wins over it
	priority string // optional X-Priority value ("" = unset)
	tags     string // optional X-Tags value ("" = unset)
}

// resolveFleetNtfyBaseURL resolves the local ntfy base URL for per-rig fan-out
// POSTs. Order (CLI-14): test seam (applied in sendNotifyAllRigs) > tailnet IP
// + configured port > localhost + configured port.
//
// NET-02: ntfy binds the tailnet IP only (native listen-http tailnetIP:port;
// docker -p tailnetIP:port:80), so the POST must target that IP — localhost is
// only a fallback for when the backend cannot resolve a tailnet IP (e.g.
// tailscaled down), mirroring the resolution in notify/module.go baseURL.
func resolveFleetNtfyBaseURL(ctx context.Context, cc *cmdContext, b backend.Client) string {
	port := cc.cfg.Modules.Ntfy.ListenPort()
	host := "localhost"
	if b != nil {
		if ip, err := b.IP(ctx); err == nil && ip != "" {
			host = ip
		}
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// sendNotifyAllRigs sends a per-rig HMAC-signed notification to each targeted
// rig's own ntfy topic. Each POST carries:
//   - X-Abysslink-Rig:    the rig's logical name
//   - X-Abysslink-Rig-Ts: epoch-seconds timestamp (so the verifier can recompute)
//   - X-Abysslink-Rig-Sig: hex(HMAC-SHA256(rigName+"."+ts+"."+title+"."+message))
//     signed with the per-rig keychain key (SC-5, D-NI-03, WR-02)
//
// Security invariants (T-14-17 / T-14-18 / T-14-19 / T-14-20):
//   - HMAC key fetched from per-rig keychain namespace (fleet.RigService), never argv/yaml/log.
//   - Each rig's notification targets only its own NtfyTopic (no cross-topic delivery).
//   - Timestamp transmitted so verifier can reconstruct the canonical string (Pitfall 6).
//   - If a rig has no enrolled signing key, it is skipped with a WARN, not a crash.
//   - Title is included in the HMAC canonical string (WR-02) so a relay cannot alter
//     the displayed subject without breaking the signature.
//   - If a rig has no NtfyTopic, the send fails with an error rather than falling
//     back to a shared topic (CR-04, T-14-14, D-NI-01: no cross-tenant leakage).
//
// Concurrency (WR-04, D-FT-04): all rigs are notified concurrently via errgroup,
// mirroring fleet.FanOut. A per-rig timeout is enforced. UNREACHABLE rigs are
// recorded as errors but do not cancel sibling rigs (SC-2 / Pitfall 1). The
// http.Client is safe for concurrent use and is shared across goroutines.
func sendNotifyAllRigs(
	ctx context.Context,
	rigs []config.RigConfig,
	kc secrets.KeychainStore,
	title, message string,
	opts rigNotifyOpts,
) error {
	const perRigTimeout = 10 * time.Second

	// Resolve the ntfy base URL once for the whole batch (CLI-14):
	// test seam > caller-resolved (config port + tailnet IP) > hardcoded default.
	switch {
	case notifyCmdBaseURL != "":
		opts.baseURL = notifyCmdBaseURL
	case opts.baseURL == "":
		opts.baseURL = "http://localhost:2586"
	}

	// http.Client is goroutine-safe; share it across concurrent rig calls.
	client := &http.Client{Timeout: perRigTimeout}

	// Build the signed timestamp once — same epoch-second for all rigs in the batch.
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	// Pre-size results so we can collect per-rig errors without a mutex.
	rigErrs := make([]error, len(rigs))

	g, gctx := errgroup.WithContext(ctx) // D-FT-04: errgroup for concurrent fan-out

	for i, rig := range rigs {
		i, rig := i, rig // capture loop variables

		g.Go(func() error {
			// Per-rig timeout: wraps gctx (Pitfall 2) so parent cancellation propagates.
			rctx, cancel := context.WithTimeout(gctx, perRigTimeout)
			defer cancel()

			if err := sendRigNotify(rctx, client, rig, kc, title, message, ts, opts); err != nil {
				slog.Warn("notify fleet fan-out: failed to send to rig", "rig", rig.Name, "err", err)
				// SC-2: store the error but return nil so the errgroup does NOT cancel
				// sibling rigs — an unreachable rig is a RESULT VALUE, not a fatal abort.
				rigErrs[i] = err
			}
			return nil
		})
	}

	// g.Wait() always returns nil (goroutines never return a non-nil error above).
	// We surface the first per-rig error to the caller for logging / exit-code purposes.
	_ = g.Wait()

	for _, e := range rigErrs {
		if e != nil {
			return e // return the first rig error (consistent with prior sequential behaviour)
		}
	}
	return nil
}

// sendRigNotify sends a single HMAC-signed notification to one rig's ntfy topic.
//
// CR-04: an empty NtfyTopic is an error — we never fall back to a shared topic.
// WR-02: the HMAC canonical string covers rigName+"."+ts+"."+title+"."+message
// so a relay cannot alter the displayed X-Title without breaking the signature.
// Priority/tags ride as unsigned delivery hints (they affect rendering only,
// never the authenticated payload).
func sendRigNotify(
	ctx context.Context,
	client *http.Client,
	rig config.RigConfig,
	kc secrets.KeychainStore,
	title, message, ts string,
	opts rigNotifyOpts,
) error {
	topic := rig.NtfyTopic
	if topic == "" {
		// CR-04: refuse to route to a shared default topic — this would violate
		// per-rig isolation (T-14-14, D-NI-01, SC-1). Surface as a hard error.
		return fmt.Errorf("notify rig %q: ntfy_topic is not configured; re-enroll with --apply to assign a unique topic", rig.Name)
	}

	url := fmt.Sprintf("%s/%s", opts.baseURL, topic)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(message))
	if err != nil {
		return fmt.Errorf("notify rig %q: create request: %w", rig.Name, err)
	}
	req.Header.Set("X-Title", title)
	req.Header.Set("Content-Type", "text/plain")
	if opts.priority != "" {
		req.Header.Set("X-Priority", opts.priority)
	}
	if opts.tags != "" {
		req.Header.Set("X-Tags", opts.tags)
	}

	// Set rig-identity headers (SC-5, D-NI-03).
	req.Header.Set("X-Abysslink-Rig", rig.Name)
	req.Header.Set("X-Abysslink-Rig-Ts", ts) // Pitfall 6: verifier needs the timestamp

	// Fetch the per-rig HMAC signing key from the keychain (T-14-19: never argv).
	if kc != nil {
		hexKey, keyErr := kc.Get(ctx, fleet.RigService(rig.Name), "hmac-signing-key")
		if keyErr != nil || hexKey == "" {
			// Rig not enrolled with a signing key — surface as WARN, skip signing.
			slog.Warn("notify fleet fan-out: rig has no signing key; sending unsigned", "rig", rig.Name)
		} else {
			// WR-02: include title in the signed canonical string so a relay cannot
			// alter the displayed subject (X-Title) without invalidating the HMAC.
			// New canonical: rigName + "." + ts + "." + title + "." + message
			sig, sigErr := fleet.SignRigMessage(hexKey, rig.Name, ts, title, message)
			if sigErr != nil {
				slog.Warn("notify fleet fan-out: HMAC sign failed", "rig", rig.Name, "err", sigErr)
			} else {
				req.Header.Set("X-Abysslink-Rig-Sig", sig)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify rig %q: POST: %w", rig.Name, err)
	}
	defer resp.Body.Close() //nolint:errcheck // errcheck: response body close error is non-actionable; best-effort cleanup

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notify rig %q: ntfy returned HTTP %d: %s", rig.Name, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	slog.Info("fleet notify sent", "rig", rig.Name, "topic", topic)
	return nil
}
