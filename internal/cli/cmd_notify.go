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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/modules"
	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/notifyv2"
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

// validNotifyKinds is the closed v2 kind enum accepted by --kind (D-30). The
// five values mirror notifyv2's Kind constants; an empty flag means auto
// (needs_input when the v2 path engages).
var validNotifyKinds = map[string]bool{ //nolint:gochecknoglobals // gochecknoglobals: immutable lookup table
	"needs_input": true, "command_done": true, "approval_request": true,
	"watch_fired": true, "agent_stopped": true,
}

// notifyPaneRe pins pane IDs (--pane and $TMUX_PANE) to the literal tmux %N
// form so a stale or forged value can never ride into the wire (T-27-31:
// routing metadata, format-validated, never a capability).
var notifyPaneRe = regexp.MustCompile(`^%\d+$`) //nolint:gochecknoglobals // gochecknoglobals: compiled-once validation regex

// notifySendMessage and notifySendV1 are test seams over the module send
// paths so the D-31 selection matrix is assertable without a daemon or
// network (mirrors the notifyCmdBaseURL seam idiom above).
var notifySendMessage = func(ctx context.Context, nm *notifymod.Module, msg notifyv2.Message) error { //nolint:gochecknoglobals // gochecknoglobals: package-level var is a test/injection seam; intentional
	return nm.SendMessage(ctx, msg)
}

var notifySendV1 = func(ctx context.Context, nm *notifymod.Module, title, body string, opts notifymod.SendOptions) error { //nolint:gochecknoglobals // gochecknoglobals: package-level var is a test/injection seam; intentional
	return nm.SendWithOptions(ctx, title, body, opts)
}

func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify [title] [body] | notify [flags] -- <command> [args...]",
		Short: "Send a notification via the ntfy backend or wrap a command",
		Example: `  # Send a simple notification (inside tmux the pane is autodetected — v2)
  abysslink notify "Build done" "CI passed"

  # Send a notification with body from stdin
  echo "output" | abysslink notify "Script done" --stdin

  # Urgent notification with a tag, to a non-default topic
  abysslink notify "Disk full" "/ at 98%" --priority urgent --tag warning --topic ops

  # Session-typed v2 notification with an explicit kind
  abysslink notify "review the diff" --kind approval_request

  # Wrap a command: run it, notify "done ✓" / "failed ✗", exit with ITS code
  abysslink notify -- make build`,
	}

	cmd.Flags().Bool("stdin", false, "Read notification body from stdin")
	cmd.Flags().String("priority", "default", "Notification priority: min|low|default|high|max (urgent = max)")
	cmd.Flags().String("tag", "", "User-supplied label (ntfy X-Tags; comma-separate for multiple)")
	cmd.Flags().String("topic", "", "Routing key (default from config)")
	cmd.Flags().String("kind", "", "v2 notification kind: needs_input|command_done|approval_request|watch_fired|agent_stopped (forces v2)")
	cmd.Flags().String("pane", "", "tmux pane ID (%N form) for session routing; forces v2 (default: autodetect from $TMUX_PANE)")

	cmd.RunE = runNotifyCmd

	return cmd
}

// runNotifyCmd is the notify RunE: context/deps setup, flag validation, and
// the wrap-vs-send dispatch (D-32 wrap mode runs before any arg parsing —
// zero pre-dash args is legal there).
func runNotifyCmd(c *cobra.Command, args []string) error {
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

	// CLI-04: read and validate ALL flags up front — declared flags must
	// never be silently dropped, and an invalid --kind/--pane is rejected
	// before anything is sent (D-30).
	f, err := parseNotifyFlags(c)
	if err != nil {
		return err
	}

	// D-32: wrap mode — everything after `--` is exec'd with inherited
	// stdio; the CLI exits with the wrapped command's own exit code.
	if dashAt := c.ArgsLenAtDash(); dashAt >= 0 {
		wrapped := args[dashAt:]
		if werr := validateNotifyWrapFlags(c, f, args[:dashAt], wrapped); werr != nil {
			return werr
		}
		return runNotifyWrap(ctx, cc, nm, newPrinter(c), wrapped, resolveNotifyPane(f.pane))
	}

	return runNotifySend(ctx, c, cc, deps, nm, args, f)
}

// runNotifySend handles the non-wrap path: v1 arg parsing, the rig fan-out
// branch, and the D-31 v1/v2 version selection.
func runNotifySend(ctx context.Context, c *cobra.Command, cc *cmdContext, deps modules.Deps, nm *notifymod.Module, args []string, f notifyFlags) error {
	// D-31: a body cannot ride v2 (content rides the v1 path until the
	// Phase 28 fetched body) — combining them is an explicit error.
	hasBody := f.stdin || len(args) >= 2
	if f.forceV2 && hasBody {
		return fmt.Errorf("notify: --kind/--pane select the v2 path, which carries no body (content rides the v1 path until Phase 28) — drop the body or the v2 flags")
	}
	if f.forceV2 && (f.priority != "" || f.tag != "" || f.topic != "") {
		return fmt.Errorf("notify: --priority/--tag/--topic are v1 delivery options and cannot be combined with --kind/--pane (v2 derives priority and tags from the kind)")
	}

	title, message, err := parseNotifyArgs(args, f.stdin)
	if err != nil {
		return err
	}

	// --rig / --all-rigs branch: send per-rig HMAC-signed notifications
	// (SC-5, FLEET-02, CLI-05). --rig X targets only the named enrolled rig.
	rt, rigErr := resolveRigTargets(c, cc.cfg.Rigs)
	if rigErr != nil {
		return rigErr
	}
	if rt.fanOut && len(rt.rigs) == 0 {
		// --all-rigs with zero enrolled rigs: falling through to a LOCAL send
		// would silently misroute — the user explicitly asked for fan-out.
		return fmt.Errorf("notify: --all-rigs: no rigs are enrolled (enroll one with `abysslink rig add`)")
	}
	if rt.fanOut {
		if f.forceV2 {
			return fmt.Errorf("notify: --kind/--pane cannot be combined with --rig/--all-rigs — v2 rides the local daemon socket only")
		}
		if f.topic != "" {
			// CR-04 / T-14-14: each rig has its own isolated topic; a manual
			// override would break per-rig isolation.
			return fmt.Errorf("notify: --topic cannot be combined with --rig/--all-rigs — each rig has its own isolated topic")
		}
		return sendNotifyAllRigs(ctx, rt.rigs, deps.Keychain, title, message, rigNotifyOpts{
			baseURL:  resolveFleetNtfyBaseURL(ctx, cc, deps.Backend),
			priority: f.priority,
			tags:     f.tag,
		})
	}

	// D-31 version selection: v2 inside tmux / on explicit flags, v1
	// everywhere else — existing scripts keep working unchanged.
	if useNotifyV2(f, hasBody) {
		return sendNotifyV2(ctx, nm, f, title)
	}

	return notifySendV1(ctx, nm, title, message, notifymod.SendOptions{
		Priority: f.priority,
		Tags:     f.tag,
		Topic:    f.topic,
	})
}

// notifyFlags carries the parsed and validated notify flag set.
type notifyFlags struct {
	stdin    bool
	priority string // "" = unset (server default)
	tag      string
	topic    string
	kind     string // "" = auto (needs_input when v2 engages)
	pane     string // validated %N form, "" = autodetect
	forceV2  bool   // --kind or --pane explicitly set (D-31)
}

// parseNotifyFlags reads and validates every notify flag. Invalid values are
// descriptive errors raised before anything is sent.
func parseNotifyFlags(c *cobra.Command) (notifyFlags, error) {
	var f notifyFlags
	f.stdin, _ = c.Flags().GetBool("stdin")

	f.priority, _ = c.Flags().GetString("priority")
	if !c.Flags().Changed("priority") {
		f.priority = "" // flag left at default — let ntfy apply its server-side default
	}
	if !validNotifyPriorities[f.priority] {
		return f, fmt.Errorf("notify: invalid --priority %q (use min|low|default|high|max|urgent or 1-5)", f.priority)
	}
	f.tag, _ = c.Flags().GetString("tag")
	f.topic, _ = c.Flags().GetString("topic")

	f.kind, _ = c.Flags().GetString("kind")
	if f.kind != "" && !validNotifyKinds[f.kind] {
		return f, fmt.Errorf("notify: invalid --kind %q (use needs_input|command_done|approval_request|watch_fired|agent_stopped)", f.kind)
	}
	f.pane, _ = c.Flags().GetString("pane")
	if f.pane != "" && !notifyPaneRe.MatchString(f.pane) {
		return f, fmt.Errorf(`notify: invalid --pane %q: pane IDs must match ^%%\d+$ (tmux %%N form)`, f.pane)
	}
	f.forceV2 = c.Flags().Changed("kind") || c.Flags().Changed("pane")
	return f, nil
}

// parseNotifyArgs resolves title/message exactly as the historical v1 parse —
// byte-identical outputs for every pre-existing invocation shape.
func parseNotifyArgs(args []string, readStdin bool) (title, message string, err error) {
	switch {
	case readStdin:
		body, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return "", "", fmt.Errorf("notify: read stdin: %w", readErr)
		}
		title = "notification"
		if len(args) > 0 {
			title = args[0]
		}
		message = strings.TrimSpace(string(body))
	case len(args) >= 2:
		title, message = args[0], args[1]
	case len(args) == 1:
		title = args[0]
	default:
		return "", "", fmt.Errorf("notify: provide title and body, or use --stdin for body from stdin")
	}
	return title, message, nil
}

// useNotifyV2 implements the locked D-31 selection rule: explicit
// --kind/--pane forces v2 (callers combining them with a body or v1 delivery
// flags were already rejected); a body or any v1-only delivery flag keeps v1
// (never silently drop options — the CLI-04 lesson); otherwise auto — inside
// tmux (TMUX_PANE set, even if malformed) v2, outside v1.
func useNotifyV2(f notifyFlags, hasBody bool) bool {
	if f.forceV2 {
		return true
	}
	if hasBody || f.priority != "" || f.tag != "" || f.topic != "" {
		return false
	}
	return os.Getenv("TMUX_PANE") != ""
}

// sendNotifyV2 builds and sends the v2 Message for the non-wrap path. Session
// and window IDs are unknown CLI-side — the daemon registry enriches display
// names at render time; a pane alone is valid routing identity.
func sendNotifyV2(ctx context.Context, nm *notifymod.Module, f notifyFlags, title string) error {
	kind := notifyv2.KindNeedsInput
	if f.kind != "" {
		kind = notifyv2.Kind(f.kind)
	}
	msg := notifyv2.Message{
		V:       2,
		MsgID:   notifyv2.NewMsgID(),
		Kind:    kind,
		Host:    shortNotifyHostname(),
		Session: notifyv2.SessionRef{Pane: resolveNotifyPane(f.pane)},
		Title:   title,
	}
	if err := notifySendMessage(ctx, nm, msg); err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	return nil
}

// validateNotifyWrapFlags rejects flag and argument combinations wrap mode
// cannot honor. pre holds the positional args that appeared BEFORE the -- (a
// wrap invocation has none — the title is derived from the outcome, D-32).
func validateNotifyWrapFlags(c *cobra.Command, f notifyFlags, pre, wrapped []string) error {
	if len(wrapped) == 0 {
		return fmt.Errorf("notify: wrap mode needs a command after -- (e.g. abysslink notify -- make build)")
	}
	if len(pre) > 0 {
		// Silently discarding a user-supplied title/body would be a CLI-04
		// violation — reject instead.
		return fmt.Errorf("notify: wrap mode takes no arguments before -- (got %q) — the title is derived from the command outcome (D-32)", strings.Join(pre, " "))
	}
	rigName, _ := c.Flags().GetString("rig")
	allRigs, _ := c.Flags().GetBool("all-rigs")
	if rigName != "" || allRigs {
		return fmt.Errorf("notify: --rig/--all-rigs cannot be combined with wrap mode — the wrapped command runs locally and its notification rides the local daemon socket only")
	}
	if f.stdin {
		return fmt.Errorf("notify: --stdin cannot be combined with wrap mode (the wrapped command owns stdin)")
	}
	if f.kind != "" && f.kind != string(notifyv2.KindCommandDone) {
		return fmt.Errorf("notify: wrap mode always sends kind command_done — drop --kind %q", f.kind)
	}
	if f.priority != "" || f.tag != "" || f.topic != "" {
		return fmt.Errorf("notify: --priority/--tag/--topic are v1 delivery options and cannot be combined with wrap mode (D-32 derives priority from the outcome)")
	}
	return nil
}

// runNotifyWrap implements D-32: exec the wrapped argv with inherited stdio
// via the (gated) Runner, send a v2 command_done whose title word reports the
// outcome ("done ✓" / "failed ✗" at high priority), and exit with the wrapped
// command's OWN exit code. A notification failure prints a warning and never
// alters that code (T-27-34: automation built on wrap sees true outcomes).
// Numeric exit code and duration are deliberately deferred to the Phase 28
// fetched body.
func runNotifyWrap(ctx context.Context, cc *cmdContext, nm *notifymod.Module, p Printer, argv []string, pane string) error {
	runErr := cc.runner.RunInteractive(ctx, argv[0], argv[1:]...)

	exitCode := 0
	if runErr != nil {
		var ec interface{ ExitCode() int }
		if !errors.As(runErr, &ec) {
			// The command never ran (e.g. binary not found): there is no exit
			// code to report — surface the exec error itself (exit 1).
			return fmt.Errorf("notify wrap: %w", runErr)
		}
		exitCode = ec.ExitCode()
		if exitCode == -1 {
			// A signal-killed child reports ExitCode() == -1, which the process
			// would surface as 255. Map it to the conventional 128+signum (e.g.
			// SIGTERM → 143) so automation built on wrap sees the real outcome.
			// The WaitStatus assertion's ok form guards platforms without it.
			var sysErr interface{ Sys() any }
			if errors.As(runErr, &sysErr) {
				if ws, ok := sysErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					exitCode = 128 + int(ws.Signal())
				}
			}
		}
	}

	msg := notifyv2.Message{
		V:       2,
		MsgID:   notifyv2.NewMsgID(),
		Kind:    notifyv2.KindCommandDone,
		Host:    shortNotifyHostname(),
		Session: notifyv2.SessionRef{Pane: pane},
		Title:   "done ✓", // D-32: the title word drives tag/priority
	}
	if exitCode != 0 {
		msg.Title = "failed ✗"
		msg.Priority = "high"
	}
	if serr := notifySendMessage(ctx, nm, msg); serr != nil {
		// Warning only — the wrapped command's exit code is the truth.
		p.Error(fmt.Sprintf("notify wrap: notification failed: %v", serr))
	}

	if exitCode != 0 {
		return &exitError{code: exitCode}
	}
	return nil
}

// resolveNotifyPane resolves the v2 pane ID: an explicit --pane wins; else a
// well-formed $TMUX_PANE; else empty. A malformed env value is dropped with a
// debug log, never an error — a notification must not fail on stale tmux
// metadata (Pitfall 8, D-26 spirit).
func resolveNotifyPane(paneFlag string) string {
	if paneFlag != "" {
		return paneFlag // already validated against notifyPaneRe by parseNotifyFlags
	}
	env := os.Getenv("TMUX_PANE")
	if env == "" {
		return ""
	}
	if !notifyPaneRe.MatchString(env) {
		slog.Debug("notify: ignoring malformed TMUX_PANE", "value", env)
		return ""
	}
	return env
}

// shortNotifyHostname returns the short host name for Message.Host (the
// daemon enriches an empty host server-side, but the CLI knows its own).
func shortNotifyHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
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
//   - X-Abysslink-Rig-Sig: hex(HMAC-SHA256 over the length-prefixed fields
//     rigName, ts, title, message — see fleet.SignRigMessage) signed with the
//     per-rig keychain key (SC-5, D-NI-03, WR-02)
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
// WR-02: the HMAC canonical string covers the length-prefixed fields rigName,
// ts, title, message (fleet.SignRigMessage) so a relay cannot alter the
// displayed X-Title — or shift bytes across the title/body boundary — without
// breaking the signature.
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
			// Canonical: length-prefixed fields rigName, ts, title, message.
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
