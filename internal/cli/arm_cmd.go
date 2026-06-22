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
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/abysslink/abysslink/internal/approve"
	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/budget"
	"github.com/abysslink/abysslink/internal/deadman"
	"github.com/abysslink/abysslink/internal/gate"
	notifymod "github.com/abysslink/abysslink/internal/modules/notify"
	"github.com/abysslink/abysslink/internal/notifyv2"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/spf13/cobra"
)

// newArmCmd returns the `abysslink arm -- <cmd> [args...]` command. It wires
// the full apoptosis system: git snapshot, asciinema flight recorder, budget
// watcher, and rollback offer on exit (dry-run default, --apply to restore).
func newArmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "arm -- <cmd> [args...]",
		Short: "Arm an agent run with the apoptosis kill-switch (shadow mode by default)",
		Long: `arm wraps a command with the apoptosis kill-switch. It records a git snapshot
of the working tree, starts an asciinema flight recorder, and monitors the run
for threshold violations (wall-clock, command loops). In shadow mode (default)
it notifies without stopping. Enable the full ladder (SIGSTOP -> phone Resume/Kill)
with budget.ladder: true in abysslink.yaml.`,
		Args: cobra.MinimumNArgs(1),
		Example: `  # Shadow mode (default) — monitor wall-clock and loop budget; notify only.
  abysslink arm -- claude

  # Apply rollback on exit — restore working tree to arm-time state.
  abysslink arm --apply -- claude

  # Wrap any long-running agent command.
  abysslink arm -- aider --model gpt-4o`,
	}

	var apply bool
	cmd.Flags().BoolVar(&apply, "apply", false, "execute rollback on exit (default: dry-run — shows diff only)")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		cc, err := loadCmdContext(c)
		if err != nil {
			return err
		}
		deps, err := buildDeps(c.Context(), cc)
		if err != nil {
			return fmt.Errorf("arm: %w", err)
		}
		p := newPrinter(c)
		nm := notifymod.New(deps)
		// deps.Audit is audit.AuditWriter (WriteFile + Update only). Budget needs
		// Append for cast sha256 binding (KILL-05). Try type assertion to the
		// underlying concrete type; fall back to a no-op appender if unavailable.
		aud := resolveAuditAppender(deps.Audit)
		// deps.Keychain may be nil (no keychain backend on this host). It is
		// threaded into the budget watcher so ladder mode can load the
		// audit-hmac key for D-16 capability-URL signatures (fail-soft).
		return runArm(c.Context(), cc, nm, aud, p, deps.Keychain, args, apply)
	}

	return cmd
}

// armNotifyAdapter implements budget.notifyClient by delegating to the notify
// module. It composes a notifyv2.Message{Kind: KindAgentStopped} and calls the
// notifySendMessage seam (internal/cli/cmd_notify.go:72) so tests can stub it.
// Notification failures are non-fatal (T-31-14): logged with slog.Warn and
// return nil so the arm session is never blocked by a notification failure.
type armNotifyAdapter struct {
	nm *notifymod.Module
}

// SendAgentStopped implements budget.notifyClient.
func (a *armNotifyAdapter) SendAgentStopped(ctx context.Context, reason string) error {
	msg := notifyv2.Message{
		V:     2,
		MsgID: notifyv2.NewMsgID(),
		Kind:  notifyv2.KindAgentStopped,
		Host:  notifyv2.ShortHostname(),
		Title: "agent stopped: " + reason,
	}
	if err := notifySendMessage(ctx, a.nm, msg); err != nil {
		// T-31-14: notification failure must not abort the arm session.
		slog.Warn("arm: SendAgentStopped failed (non-fatal)", "reason", reason, "err", err)
	}
	return nil // always nil — notification failure is non-fatal
}

// armAuditWriter is the internal interface for audit binding in the arm command.
// It matches the budget package's internal auditAppender interface:
// Append(op, target string, content []byte, dryRun bool) error.
// Only *audit.Audit (the unsigned writer) satisfies this — *audit.SignedAudit
// has a different Append signature. resolveAuditAppender handles the dispatch.
type armAuditWriter interface {
	Append(op, target string, content []byte, dryRun bool) error
}

// noopAuditAppender is a safe fallback armAuditWriter when the real audit
// writer does not support Append (e.g. when a SignedAudit is configured).
// It logs a warning and returns nil so the arm session is not blocked.
type noopAuditAppender struct{}

func (n *noopAuditAppender) Append(op, target string, _ []byte, _ bool) error {
	slog.Warn("arm: audit.Append not available — cast sha256 not bound (KILL-05 partial)",
		"op", op, "target", target)
	return nil
}

// resolveAuditAppender attempts to extract an armAuditWriter from the given
// audit.AuditWriter. deps.Audit is audit.AuditWriter (WriteFile + Update
// only), which does not expose Append. We try a type assertion to the
// concrete type that DOES expose Append (the unsigned *audit.Audit). On
// failure we fall back to a no-op so the arm session is never blocked.
func resolveAuditAppender(w interface{}) armAuditWriter {
	if a, ok := w.(armAuditWriter); ok {
		return a
	}
	// The underlying type did not expose Append (e.g. SignedAudit with
	// different signature). Fall back to no-op with a warning.
	slog.Warn("arm: audit writer does not implement Append — cast sha256 not bound in audit chain (KILL-05 partial)")
	return &noopAuditAppender{}
}

// armSnapshot captures the git HEAD SHA and stash SHA at arm time (steps 1-2).
// Returns empty strings when git is unavailable or the working tree is clean.
func armSnapshot(ctx context.Context, runner shell.Runner) (headSHA, stashSHA string) {
	if !shell.LookPath("git") {
		slog.Warn("arm: git not found — snapshot and rollback disabled")
		return "", ""
	}
	gitEnv := map[string]string{"GIT_TERMINAL_PROMPT": "0"}
	headRes, err := runner.RunWithEnv(ctx, gitEnv, "git", "rev-parse", "HEAD")
	if err != nil {
		slog.Warn("arm: git rev-parse HEAD failed — rollback offer unavailable", "err", err)
		return "", ""
	}
	headSHA = strings.TrimSpace(headRes.Stdout)
	if headSHA == "" {
		return "", ""
	}
	stashRes, err := runner.RunWithEnv(ctx, gitEnv, "git", "stash", "create")
	if err != nil {
		slog.Warn("arm: git stash create failed — snapshot unavailable", "err", err)
		return headSHA, ""
	}
	stashSHA = strings.TrimSpace(stashRes.Stdout)
	if stashSHA == "" {
		slog.Info("arm: working tree is clean — no snapshot created")
	}
	return headSHA, stashSHA
}

// armSigFn is the signal-sender seam for armSpawnWatchWait. In production it is
// nil (the watcher uses its default syscall.Kill(-pgid, sig)); tests inject a
// fake so SIGSTOP/SIGCONT can be observed without signalling a real process
// group. The registry and HMAC key are NEVER injected — they are constructed by
// the production path so the CLI ladder test exercises the real wiring.
type armSigFn func(pgid int, sig syscall.Signal) error

// armLockdownFlagPathFn is a package-var seam (mirroring deadmanContactPathFn)
// so tests can redirect the dead-man lockdown flag to a temp file without
// touching XDG_STATE_HOME globally. Production resolves the real XDG path.
var armLockdownFlagPathFn = deadman.LockdownFlagPath

// armIsLockedDown is a package-var seam over deadman.IsLockedDown so a test can
// force the indeterminate (read-error) branch to assert the fail-closed default.
var armIsLockedDown = deadman.IsLockedDown

// armWatcherHook is a test-only seam. When non-nil, armSpawnWatchWait calls it
// with the production-constructed *budget.Watcher and *approve.Registry so a
// test can resolve the pending approve request via the REAL registry without
// injecting its own. It is nil in production (never set outside tests).
var armWatcherHook func(w *budget.Watcher, reg *approve.Registry)

// armDeadmanRegistryFactory builds the persistent armed-run registry that arm
// registers its pgid in (SUPL-06). In production it resolves the canonical
// XDG_STATE_HOME/abysslink/armed-runs.json path and an audit writer over the
// default audit log. Tests override it to point the registry at a temp state
// file + temp audit log. It returns (nil, err) on any wiring failure; the
// caller is fail-soft (a missing registry must NEVER block an arm — the
// kill-switch has to stay usable, mirroring the Phase 31 fail-soft HMAC-key
// decision).
var armDeadmanRegistryFactory = defaultArmDeadmanRegistry

// defaultArmDeadmanRegistry is the production registry factory: state file at
// deadman.StatePath() (XDG_STATE_HOME/abysslink/armed-runs.json), audit writer
// over audit.DefaultLogPath(). Both go through the standard XDG convention used
// by the daemon and the budget/audit packages.
func defaultArmDeadmanRegistry() (*deadman.Registry, error) {
	statePath, err := deadman.StatePath()
	if err != nil {
		return nil, fmt.Errorf("resolve armed-run registry path: %w", err)
	}
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return nil, fmt.Errorf("resolve audit log path: %w", err)
	}
	return deadman.New(statePath, audit.New(logPath)), nil
}

// registerArmedPGID registers pgid in the persistent, audit-written armed-run
// registry so a separate process (the daemon dead-man timer) can discover and
// disarm it (SUPL-06). It returns a deregister func the caller defers so the
// pgid is removed when the armed process exits, on every path.
//
// FAIL-SOFT: a registry wiring/Register failure must NEVER block arming — the
// kill-switch has to stay usable even when the registry is unavailable (mirrors
// the Phase 31 fail-soft HMAC-key decision). On any failure the returned
// deregister func is a no-op. Only the pgid + closure hash + timestamp are
// recorded; never argv or env (no secrets in the registry, CLAUDE.md hard rule).
func registerArmedPGID(pgid int, closureHash string) func() {
	reg, regErr := armDeadmanRegistryFactory()
	if regErr != nil {
		slog.Warn("arm: armed-run registry unavailable — pgid not registered (dead-man switch cannot discover this run); continuing (fail-soft)", "err", regErr)
		return func() {}
	}
	if rerr := reg.Register(deadman.ArmedRun{PGID: pgid, ClosureHash: closureHash, ArmedAt: time.Now().UTC()}); rerr != nil {
		slog.Warn("arm: armed-run registry Register failed — pgid not registered; continuing (fail-soft)", "pgid", pgid, "err", rerr)
		return func() {}
	}
	slog.Info("arm: pgid registered in armed-run registry (SUPL-06)", "pgid", pgid)
	return func() {
		if derr := reg.Deregister(pgid); derr != nil {
			slog.Warn("arm: armed-run registry Deregister failed on exit — stale pgid may remain until pruned", "pgid", pgid, "err", derr)
		}
	}
}

// loadArmHMACKey loads and hex-decodes the abysslink/audit-hmac key from the
// keychain. It mirrors loadApproveHMACKey in cmd/abysslinkd/main.go (same
// service/account as internal/audit.SignedAudit). Returns an error on a
// missing/malformed/empty key; callers fail soft (ladder integrity degrades to
// the unsigned-URL path, arming is never blocked).
func loadArmHMACKey(ctx context.Context, kc secrets.KeychainStore) ([]byte, error) {
	hexKey, err := kc.Get(ctx, "abysslink", "audit-hmac")
	if err != nil {
		return nil, fmt.Errorf("keychain get abysslink/audit-hmac: %w", err)
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode audit-hmac key: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("audit-hmac key is empty")
	}
	return key, nil
}

// armSpawnWatchWait spawns the armed process, runs the budget watcher, and waits
// for the process to exit (steps 5-7). It is extracted from runArm to keep
// cyclomatic complexity below the gocyclo limit.
//
// kc may be nil (no keychain backend). sigFn may be nil in production (the
// watcher uses its default real signal sender); tests inject a fake.
func armSpawnWatchWait(ctx context.Context, cc *cmdContext, aud armAuditWriter, nm *notifymod.Module,
	kc secrets.KeychainStore, sigFn armSigFn,
	userCmd []string, castPath, stashSHA, armHashHex string, hasAsciinema bool) error {
	armedRunner, ok := cc.runner.(shell.ArmedRunner)
	if !ok {
		return fmt.Errorf("arm: runner %T does not implement ArmedRunner — cannot arm process", cc.runner)
	}

	spawnCmd := userCmd[0]
	spawnArgs := userCmd[1:]
	if hasAsciinema && castPath != "" {
		spawnCmd = "asciinema"
		spawnArgs = append([]string{"rec", castPath, "--"}, userCmd...)
	}

	// WR-01 / B10: when the operator opts in (Budget.MinimizeAgentEnv) AND the
	// runner implements the optional ArmedMinimalRunner, spawn the armed agent
	// with the B10-minimized environment so secret-bearing parent vars do not
	// leak into the untrusted agent process. Fail-soft: if the knob is set but
	// the runner cannot minimize, fall back to RunArmed and warn — env
	// minimization is defense-in-depth and must never block arming. Default
	// (knob false) spawns via RunArmed exactly as before.
	var handle *shell.ArmedHandle
	var err error
	if cc.cfg.Budget.MinimizeAgentEnv {
		if mr, ok := cc.runner.(shell.ArmedMinimalRunner); ok {
			slog.Info("arm: spawning agent with minimized env (B10 active — Budget.MinimizeAgentEnv)")
			handle, err = mr.RunArmedMinimal(ctx, spawnCmd, spawnArgs...)
		} else {
			slog.Warn("arm: Budget.MinimizeAgentEnv set but runner does not support env minimization; spawning with full env",
				"runner", fmt.Sprintf("%T", cc.runner))
			handle, err = armedRunner.RunArmed(ctx, spawnCmd, spawnArgs...)
		}
	} else {
		handle, err = armedRunner.RunArmed(ctx, spawnCmd, spawnArgs...)
	}
	if err != nil {
		return fmt.Errorf("arm: spawn: %w", err)
	}
	if handle.PGID <= 0 {
		return fmt.Errorf("arm: invalid pgid %d returned by RunArmed — cannot signal process group", handle.PGID)
	}
	slog.Info("arm: process armed", "pgid", handle.PGID, "cmd", userCmd[0], "cast_path", castPath)

	// SUPL-06: register this armed run's pgid; deregister on exit (the returned
	// func defers below, firing after <-handle.Done on every path). Fail-soft.
	deregister := registerArmedPGID(handle.PGID, armHashHex)
	defer deregister()

	// Budget watcher (step 6).
	budgetCfg := budget.ConfigFrom(cc.cfg.Budget)
	notifyAdapter := &armNotifyAdapter{nm: nm}

	type setObserver interface {
		SetObserver(fn func([32]byte))
	}
	var gatedRunner setObserver
	if g, ok := cc.runner.(setObserver); ok {
		gatedRunner = g
	} else {
		slog.Debug("arm: runner does not implement SetObserver — loop detection disabled")
	}

	// Construct a real approve registry unconditionally (cheap, in-memory) so
	// ladder mode is reachable in production and the prior nil-registry panic
	// (31-VERIFICATION.md gap #1, CR-01) can never recur. Shadow mode is
	// unaffected — it never opens an approve request.
	reg := approve.NewRegistry(nil)
	watcher := budget.NewWatcher(budgetCfg, reg, aud, notifyAdapter, gatedRunner, nil)

	// Test seam: expose the PRODUCTION-built watcher and registry so the CLI
	// ladder regression test can resolve the pending approve request via the
	// real registry (it never constructs its own). nil in production.
	if armWatcherHook != nil {
		armWatcherHook(watcher, reg)
	}

	// Test seam: inject the fake signal sender when provided. Production passes
	// nil and the watcher keeps its default real syscall.Kill(-pgid, sig).
	if sigFn != nil {
		watcher.SetSignalFn(sigFn)
	}

	// Wire the D-16 HMAC key only in ladder mode so approve/deny capability URLs
	// carry an integrity signature. Fail SOFT: a missing key (or no keychain
	// backend) weakens defense-in-depth but must never block arming — the
	// kill-switch has to stay usable on hosts without a keychain. The key bytes
	// are never logged (only availability) and never placed on argv.
	if budgetCfg.Ladder {
		if kc == nil {
			slog.Warn("arm: ladder enabled but no keychain backend — approve HMAC key unavailable; capability-URL integrity check disabled (D-16 defense-in-depth absent)")
		} else if key, kerr := loadArmHMACKey(ctx, kc); kerr != nil {
			slog.Warn("arm: ladder enabled but approve HMAC key unavailable — capability-URL integrity check disabled (D-16 defense-in-depth absent)", "err", kerr)
		} else {
			watcher.SetHMACKey(key)
			slog.Info("arm: ladder HMAC key wired (D-16 capability-URL signatures active)")
		}
	}

	watchCtx, watchCancel := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		defer watchCancel()
		_ = watcher.Watch(watchCtx, handle.PGID, castPath, stashSHA, armHashHex)
	}()

	// Step 7 — Wait for process to exit.
	<-handle.Done
	watchCancel()
	<-watchDone

	if exitErr := handle.Wait(); exitErr != nil {
		slog.Info("arm: process exited with error", "err", exitErr)
	}
	return nil
}

// armLockdownPreflight resolves the dead-man lockdown flag and refuses to arm
// when it is set (CR-03). It FAILS CLOSED on any indeterminate state: a flag
// path that cannot be resolved, or an IsLockedDown read error, both refuse to
// arm rather than silently allowing it — a fresh or compromised agent must not
// be able to re-arm under an unknown lockdown state. The refusal points the
// operator at the actual un-lockdown mechanism available today (there is no
// `deadman clear` subcommand yet — WR-04 is out of scope here): remove the
// lockdown flag file via deadman.ClearLockdownFlag / deleting
// deadman-lockdown.json after investigating.
func armLockdownPreflight() error {
	flagPath, err := armLockdownFlagPathFn()
	if err != nil {
		// Fail-closed: an unresolvable flag path is an indeterminate lockdown state.
		return fmt.Errorf("arm: refusing — could not resolve the dead-man lockdown flag path to confirm the switch is not locked down: %w", err)
	}
	locked, reason, err := armIsLockedDown(flagPath)
	if err != nil {
		// Fail-closed: a read error means the lockdown state is indeterminate.
		return fmt.Errorf("arm: refusing — could not read the dead-man lockdown flag (%s) to confirm the switch is not locked down: %w", flagPath, err)
	}
	if locked {
		return fmt.Errorf("arm: refusing — dead-man lockdown is active (%s); after investigating, clear it by removing the lockdown flag file %s (deadman.ClearLockdownFlag) and re-arm", reason, flagPath)
	}
	return nil
}

// runArm is the core implementation of `abysslink arm`.
//
// Steps:
//  1. Check prerequisites (asciinema, git) via armSnapshot.
//  2. Take git snapshot (git rev-parse HEAD, git stash create) via armSnapshot.
//  3. Build cast file path.
//  4. Compute arm-time closure hash (Pitfall 6: on user's cmd, not asciinema wrapper).
//     5-7. Spawn, watch, wait via armSpawnWatchWait.
//  8. Offer rollback (always show diff; --apply to restore).
func runArm(ctx context.Context, cc *cmdContext, nm *notifymod.Module, aud armAuditWriter, p Printer, kc secrets.KeychainStore, userCmd []string, apply bool) error {
	// CR-03: dead-man lockdown pre-flight — refuse to spawn an agent while the
	// lockdown flag is set, so a fresh or compromised agent cannot re-arm after a
	// dead-man lockdown revoked autonomy. This runs BEFORE armSnapshot/spawn so
	// arming under lockdown aborts as early and cheaply as possible (before the
	// git snapshot and asciinema setup). It is a SAFETY GATE, not a mutating op,
	// so it applies on every arm regardless of --apply (spawning the agent is the
	// action being gated, CLAUDE.md).
	//
	// FAIL-CLOSED default: if the flag path cannot be resolved OR IsLockedDown
	// returns an error, REFUSE to arm rather than falling through to spawn — a
	// fresh/compromised agent must not be able to re-arm under an INDETERMINATE
	// lockdown state. A read error is never treated as "not locked down".
	if err := armLockdownPreflight(); err != nil {
		return err
	}

	hasAsciinema := shell.LookPath("asciinema")
	if !hasAsciinema {
		slog.Warn("arm: asciinema not found — flight recorder disabled; install asciinema to enable KILL-05")
	}

	// Steps 1-2: git prerequisites + snapshot.
	headSHA, stashSHA := armSnapshot(ctx, cc.runner)

	// Step 3 — Cast file path.
	castPath := ""
	if hasAsciinema {
		castDir := armCastDir()
		if mkErr := os.MkdirAll(castDir, 0o700); mkErr != nil {
			slog.Warn("arm: cannot create cast directory — flight recorder disabled", "dir", castDir, "err", mkErr)
		} else {
			castPath = filepath.Join(castDir, notifyv2.NewMsgID()+".cast")
		}
	}

	// Step 4 — Arm-time closure hash (Pitfall 6: use the user's cmd, not the asciinema wrapper).
	armHash := gate.ClosureHashOf(userCmd[0], userCmd[1:])
	armHashHex := hex.EncodeToString(armHash[:])
	slog.Debug("arm: closure hash computed", "prefix", armHashHex[:8])

	// Steps 5-7: spawn, watch, wait. sigFn is nil in production (the watcher
	// uses its default real signal sender); tests inject a fake.
	if err := armSpawnWatchWait(ctx, cc, aud, nm, kc, nil /*sigFn*/, userCmd, castPath, stashSHA, armHashHex, hasAsciinema); err != nil {
		return err
	}

	// Step 8 — Rollback offer.
	return armRollbackOffer(ctx, cc, p, headSHA, stashSHA, apply)
}

// armCastDir returns the directory for storing cast files, honoring XDG_DATA_HOME.
// Follows the XDG Base Directory Specification:
// $XDG_DATA_HOME/abysslink/casts or ~/.local/share/abysslink/casts.
func armCastDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "abysslink", "casts")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Fall back to relative path if home is unavailable (should not happen in practice).
		return filepath.Join(".local", "share", "abysslink", "casts")
	}
	return filepath.Join(home, ".local", "share", "abysslink", "casts")
}

// armRollbackOffer shows the diff since arm time and optionally restores the
// working tree to the arm-time state. The --apply flag gates the restore.
//
// Security: git stash apply is guarded by a HEAD-advance check (T-31-12).
// Never attempts a potentially-conflicting stash apply if HEAD has advanced.
func armRollbackOffer(ctx context.Context, cc *cmdContext, p Printer, headSHA, stashSHA string, apply bool) error {
	if headSHA == "" {
		p.Print("arm: git snapshot unavailable — no rollback offer")
		return nil
	}

	// Always show diff since arm time (informational).
	diffRes, _ := cc.runner.RunWithEnv(ctx, map[string]string{"GIT_TERMINAL_PROMPT": "0"}, "git", "diff", headSHA)
	if diffRes.Stdout != "" {
		p.Print(fmt.Sprintf("Changes since arm time:\n%s", diffRes.Stdout))
	} else {
		p.Print("No changes since arm time.")
	}

	if stashSHA == "" {
		p.Print("Working tree was clean at arm time — nothing to restore.")
		return nil
	}

	if !apply {
		p.Print("(dry-run) Pass --apply to restore working tree to arm-time state")
		return nil
	}

	// --apply path: check if HEAD has advanced since arm time (T-31-12).
	currentHeadRes, err := cc.runner.RunWithEnv(ctx, map[string]string{"GIT_TERMINAL_PROMPT": "0"}, "git", "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("arm: rollback: cannot read current HEAD: %w", err)
	}
	currentHead := strings.TrimSpace(currentHeadRes.Stdout)
	if currentHead != headSHA {
		// T-31-12: HEAD-advance guard — stash may conflict; abort restore.
		p.Print("WARNING: HEAD has advanced since arm — stash may conflict; restore skipped. Diff shown above.")
		return nil
	}

	_, restoreErr := cc.runner.RunWithEnv(ctx, map[string]string{"GIT_TERMINAL_PROMPT": "0"}, "git", "stash", "apply", stashSHA)
	if restoreErr != nil {
		return fmt.Errorf("arm: rollback failed: %w", restoreErr)
	}
	p.Print("Working tree restored to arm-time state.")
	return nil
}
