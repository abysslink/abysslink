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

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/spf13/cobra"
)

// notifyCmdBaseURL is a test seam: when non-empty, all --all-rigs per-rig POSTs
// target this base URL instead of the ntfy default. Override in tests via
// httptest.Server.URL (mirrors ntfyBaseURL in notify/module.go but scoped to cli).
var notifyCmdBaseURL = "" //nolint:gochecknoglobals

func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify [title] [body]",
		Short: "Send a notification via the ntfy backend or wrap a command",
		Example: `  # Send a simple notification
  abysslink notify "Build done" "CI passed"

  # Send a notification with body from stdin
  echo "output" | abysslink notify "Script done" --stdin`,
	}

	cmd.Flags().Bool("stdin", false, "Read notification body from stdin")
	cmd.Flags().String("priority", "default", "Notification priority: low|default|high|urgent")
	cmd.Flags().String("tag", "", "User-supplied label")
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

		// --all-rigs branch: send per-rig HMAC-signed notifications (SC-5, FLEET-02).
		allRigs, _ := c.Flags().GetBool("all-rigs")
		if allRigs && len(cc.cfg.Rigs) > 0 {
			return sendNotifyAllRigs(ctx, cc.cfg.Rigs, deps.Keychain, title, message)
		}

		return nm.Send(ctx, title, message)
	}

	return cmd
}

// sendNotifyAllRigs sends a per-rig HMAC-signed notification to each enrolled
// rig's own ntfy topic. Each POST carries:
//   - X-Abysslink-Rig:    the rig's logical name
//   - X-Abysslink-Rig-Ts: epoch-seconds timestamp (so the verifier can recompute)
//   - X-Abysslink-Rig-Sig: hex(HMAC-SHA256(rigName+"."+ts+"."+message)) signed
//     with the per-rig keychain key (SC-5, D-NI-03)
//
// Security invariants (T-14-17 / T-14-18 / T-14-19 / T-14-20):
//   - HMAC key fetched from per-rig keychain namespace (fleet.RigService), never argv/yaml/log.
//   - Each rig's notification targets only its own NtfyTopic (no cross-topic delivery).
//   - Timestamp transmitted so verifier can reconstruct the canonical string (Pitfall 6).
//   - If a rig has no enrolled signing key, it is skipped with a WARN, not a crash.
func sendNotifyAllRigs(
	ctx context.Context,
	rigs []config.RigConfig,
	kc secrets.KeychainStore,
	title, message string,
) error {
	client := &http.Client{Timeout: 10 * time.Second}

	// Build the signed timestamp once — same second for all rigs in the batch.
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	var firstErr error
	for _, rig := range rigs {
		if err := sendRigNotify(ctx, client, rig, kc, title, message, ts); err != nil {
			slog.Warn("notify --all-rigs: failed to send to rig", "rig", rig.Name, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// sendRigNotify sends a single HMAC-signed notification to one rig's ntfy topic.
func sendRigNotify(
	ctx context.Context,
	client *http.Client,
	rig config.RigConfig,
	kc secrets.KeychainStore,
	title, message, ts string,
) error {
	topic := rig.NtfyTopic
	if topic == "" {
		topic = "rig"
	}

	// Determine the ntfy base URL: test seam > config > localhost default.
	baseURL := notifyCmdBaseURL
	if baseURL == "" {
		baseURL = "http://localhost:2586"
	}
	url := fmt.Sprintf("%s/%s", baseURL, topic)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(message))
	if err != nil {
		return fmt.Errorf("notify rig %q: create request: %w", rig.Name, err)
	}
	req.Header.Set("X-Title", title)
	req.Header.Set("Content-Type", "text/plain")

	// Set rig-identity headers (SC-5, D-NI-03).
	req.Header.Set("X-Abysslink-Rig", rig.Name)
	req.Header.Set("X-Abysslink-Rig-Ts", ts) // Pitfall 6: verifier needs the timestamp

	// Fetch the per-rig HMAC signing key from the keychain (T-14-19: never argv).
	if kc != nil {
		hexKey, keyErr := kc.Get(ctx, fleet.RigService(rig.Name), "hmac-signing-key")
		if keyErr != nil || hexKey == "" {
			// Rig not enrolled with a signing key — surface as WARN, skip signing.
			slog.Warn("notify --all-rigs: rig has no signing key; sending unsigned", "rig", rig.Name)
		} else {
			sig, sigErr := fleet.SignRigMessage(hexKey, rig.Name, ts, message)
			if sigErr != nil {
				slog.Warn("notify --all-rigs: HMAC sign failed", "rig", rig.Name, "err", sigErr)
			} else {
				req.Header.Set("X-Abysslink-Rig-Sig", sig)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify rig %q: POST: %w", rig.Name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("notify rig %q: ntfy returned HTTP %d: %s", rig.Name, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	slog.Info("fleet notify sent", "rig", rig.Name, "topic", topic)
	return nil
}
