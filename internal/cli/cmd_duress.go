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
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/deadman"
	"github.com/abysslink/abysslink/internal/duress"
	"github.com/abysslink/abysslink/internal/secrets"
)

// authFailMessage is the SINGLE verbatim message printed when a presented
// credential matches neither slot. It is byte-identical whether or not the
// duress feature is enabled, so probing `abysslink unlock` cannot reveal that a
// decoy exists (DUR-02 indistinguishability).
const authFailMessage = "authentication failed"

// newDuressCmd builds the `abysslink duress` command group (Phase 39, DUR-01..03):
//
//   - enable — enrol a real + decoy credential (read from stdin, never argv) and
//     turn the decoy on in abysslink.yaml (dry-run default; --apply persists).
//   - unlock — present a credential (stdin): the real one shows the real rig
//     view; the decoy one shows a benign view AND degrades the real session for
//     real via the kill-switch; anything else is a normal auth failure.
//   - status — report whether the decoy is configured (no secrets).
//
// The feature is GENERIC (no Claude coupling): it is a constant-time credential
// comparison plus a reversible kill-switch degradation.
func newDuressCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "duress",
		Short: "Configure the opt-in duress decoy (casual-coercion mitigation)",
		Long: `The duress decoy defends against CASUAL COERCION — a shoulder-glance, a
border-guard "show me", a grabbed terminal. Entering the DECOY credential shows
a benign rig view (a quiet machine, no fleet, no live sessions) and, at the same
time, degrades your real session for real through the kill-switch (armed agents
are frozen and killed, a lockdown latch is set so nothing re-arms). It buys you
seconds-to-minutes.

It is NOT plausible deniability against a forensic adversary — the duress stanza
on disk reveals the feature exists, and a determined examiner with the disk WILL
find the real config. Full-disk encryption (FileVault / LUKS) is the real
at-rest control. There is, by design and by test, NO destructive wipe.`,
		Example: `  # Enrol (reads two lines from stdin: real passphrase, then decoy)
  printf 'real-pass\ndecoy-pass\n' | abysslink duress enable --apply

  # Present a credential (reads one line from stdin)
  abysslink duress unlock

  # Show whether the decoy is configured (no secrets)
  abysslink duress status`,
	}
	cmd.AddCommand(newDuressEnableCmd(), newDuressUnlockCmd(), newDuressStatusCmd())
	return cmd
}

// newDuressEnableCmd builds `duress enable`. Dry-run is the default; --apply
// stores the credential digests in the keychain and turns the decoy on.
func newDuressEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable",
		Short: "Enrol a real + decoy credential and enable the decoy (dry-run by default)",
		Long: `Reads TWO lines from stdin — the real passphrase, then the decoy
passphrase — hashes each with a slow salted KDF (argon2id) and stores only the
DIGESTS in the OS keychain (never in config, never on argv). Under --apply it
also sets duress.enabled + decoy.enabled in abysslink.yaml.`,
		Example: `  printf 'real-pass\ndecoy-pass\n' | abysslink duress enable --apply`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDuressEnable(cmd)
		},
	}
}

func runDuressEnable(cmd *cobra.Command) error {
	ctx := cmd.Context()
	p := newPrinter(cmd)
	_, apply, err := resolveApplyFlags(cmd)
	if err != nil {
		return err
	}

	realPass, decoyPass, err := readTwoCredentials(cmd.InOrStdin())
	if err != nil {
		return err
	}
	if realPass == decoyPass {
		return fmt.Errorf("the real and decoy credentials must differ")
	}

	path := resolveConfigPath(cmd)
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load config %s: %w (run `abysslink init` first)", path, err)
	}
	cfg.Duress.Enabled = true
	cfg.Duress.SecretSource = config.DuressSecretSourceKeychain
	cfg.Decoy.Enabled = true
	if vErr := config.Validate(cfg); vErr != nil {
		return vErr
	}

	if !apply {
		printerInfo(p, fmt.Sprintf("[plan] would enrol a real + decoy credential in the keychain and enable the decoy in %s", path))
		printerInfo(p, styleMuted.Render("Dry-run. Re-run with --apply to persist (credentials are read from stdin, never stored in config)."))
		return nil
	}

	cc, err := loadCmdContext(cmd)
	if err != nil {
		return err
	}
	deps, err := buildDeps(ctx, cc)
	if err != nil || deps.Keychain == nil {
		return fmt.Errorf("keychain unavailable — cannot store the credential digests: %w", err)
	}
	if sErr := storeCredentialDigest(ctx, deps.Keychain, duress.RealAccount, realPass); sErr != nil {
		return sErr
	}
	if sErr := storeCredentialDigest(ctx, deps.Keychain, duress.DecoyAccount, decoyPass); sErr != nil {
		return sErr
	}
	if wErr := config.Write(path, cfg); wErr != nil {
		return fmt.Errorf("write config: %w", wErr)
	}

	printerInfo(p, fmt.Sprintf("Duress decoy enabled in %s.", path))
	printerInfo(p, styleMuted.Render("Casual-coercion mitigation only (seconds-to-minutes); NOT forensic deniability. Full-disk encryption is the real at-rest control."))
	return nil
}

// storeCredentialDigest hashes plaintext and stores ONLY the argon2id digest.
func storeCredentialDigest(ctx context.Context, kc secrets.KeychainStore, account, plaintext string) error {
	digest, err := duress.HashCredential(plaintext)
	if err != nil {
		return fmt.Errorf("hash credential: %w", err)
	}
	if err := kc.Set(ctx, duress.KeychainService, account, digest); err != nil {
		return fmt.Errorf("store credential digest: %w", err)
	}
	return nil
}

// readTwoCredentials reads two newline-terminated lines from r (real, decoy).
// Secrets are read from stdin, never argv.
func readTwoCredentials(r io.Reader) (real, decoy string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	if !sc.Scan() {
		return "", "", fmt.Errorf("expected the real credential on the first stdin line")
	}
	real = sc.Text()
	if !sc.Scan() {
		return "", "", fmt.Errorf("expected the decoy credential on the second stdin line")
	}
	decoy = sc.Text()
	if real == "" || decoy == "" {
		return "", "", fmt.Errorf("neither the real nor the decoy credential may be empty")
	}
	return real, decoy, nil
}

// newDuressUnlockCmd builds `duress unlock`. It reads ONE credential line from
// stdin and resolves it. Real → real view. Decoy → benign view + real
// degradation. None → the verbatim auth-failure (exit 1).
//
// It deliberately registers NO --apply / --dry-run flag and mutates immediately
// on the decoy path (kill-ladder + persisted lockdown latch + one audit entry).
// This is the SAME emergency design contract that exempts `abysslink panic`
// (see cmd_panic.go): a dry-run default would defeat the purpose — under
// coercion the operator gets one shot and the degradation must be real and
// instant, not a plan. The degradation is NON-DESTRUCTIVE and reversible (the
// lockdown latch is cleared by the existing repair path), which is what makes
// the no-dry-run exemption safe here.
func newDuressUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Present a credential (stdin): real shows the rig view; decoy shows a benign view and degrades the session",
		Example: `  # Present a credential (reads one line from stdin)
  abysslink duress unlock`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDuressUnlock(cmd)
		},
	}
}

func runDuressUnlock(cmd *cobra.Command) error {
	ctx := cmd.Context()
	p := newPrinter(cmd)

	cred, err := readOneCredential(cmd.InOrStdin())
	if err != nil {
		return err
	}

	cc, err := loadCmdContext(cmd)
	if err != nil {
		return err
	}
	kc := unlockKeychain(ctx, cc)

	switch duress.Resolve(ctx, cred, cc.cfg.Duress, kc) {
	case duress.ModeReal:
		// The real credential: show the REAL rig view. Sessions/Armed are shown
		// as zero here (a live count would differ from the decoy and leak); the
		// real view is honest about the enrolled fleet.
		renderRigView(p, duress.RigView{
			Hostname: cc.cfg.Tailnet.Hostname,
			Fleet:    len(cc.cfg.Rigs),
		})
		return nil
	case duress.ModeDecoy:
		// The decoy credential: show the BENIGN view FIRST (byte-identical shape to
		// a real idle machine), THEN degrade the real session for real — silently.
		// Rendering before the degradation makes the FIRST visible output appear
		// with the same latency as a real unlock: a real unlock renders and the
		// degradation seam (deadman.Lockdown) never runs, so if the trigger came
		// first the decoy screen would stall for the kill-ladder grace on every
		// armed pgid — a timing tell that leaks the presence/count of a real fleet
		// (DUR-02). fireDuressTrigger silences all degradation logging and uses a
		// short kill grace so prompt-return stays prompt as well.
		renderRigView(p, duress.DecoyRigView(cc.cfg.Decoy))
		fireDuressTrigger(ctx, kc)
		return nil
	default:
		// Neither slot matched (or the feature is off / the keychain is degraded):
		// the normal, verbatim authentication failure.
		printerError(p, authFailMessage)
		return &exitError{code: exitCodeError}
	}
}

// readOneCredential reads a single newline-terminated line from r.
func readOneCredential(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	if !sc.Scan() {
		return "", fmt.Errorf("expected a credential on stdin")
	}
	return sc.Text(), nil
}

// renderRigView prints a rig view. The SAME renderer is used for the real and
// the decoy path, so the two are byte-for-byte indistinguishable (DUR-02).
func renderRigView(p Printer, v duress.RigView) {
	p.Printv("host", v.Hostname)
	p.Printv("fleet", strconv.Itoa(v.Fleet))
	p.Printv("sessions", strconv.Itoa(v.Sessions))
	p.Printv("armed", strconv.Itoa(v.Armed))
}

// duressKeychainFn constructs the keychain store for a credential lookup. It is
// a package-var seam so tests inject secrets.NewMockStore() and NEVER touch the
// live keychain (a live `security` read hangs on a GUI prompt).
var duressKeychainFn = secrets.NewStore

// unlockKeychain best-effort resolves the keychain store for a credential
// lookup. A nil result makes Resolve fail closed (auth failure), never open.
func unlockKeychain(ctx context.Context, cc *cmdContext) secrets.KeychainStore {
	kc, err := duressKeychainFn(ctx, cc.runner)
	if err != nil {
		slog.Warn("duress unlock: keychain unavailable; resolving fails closed", "err", err)
		return nil
	}
	return kc
}

// duressKillGrace is the SIGTERM -> SIGKILL grace on the duress path. It is far
// shorter than the dead-man default (5s) because a coerced hand-over wants the
// kill to complete promptly, and a multi-second, fleet-size-proportional stall
// before prompt-return would itself be a timing tell (DUR-02). The degradation
// stays REAL — SIGTERM then SIGKILL — just prompt.
const duressKillGrace = 250 * time.Millisecond

// fireDuressTrigger wires the daemon-owned degradation dependencies from the
// composition seam (mirrors cmd/abysslinkd startDeadmanTimer) and runs the
// reversible kill-switch degradation.
//
// It runs SILENTLY: every degradation log line (this function's, duress.Trigger's,
// and deadman.Lockdown's "disarming"/"lockdown executed" WARNs) is routed to a
// discard handler for the duration of the call. Those lines name "duress" and
// "lockdown"; a real unlock emits none, so leaving them on the default handler
// would print duress-shaped text to the very shoulder-surfer the decoy exists to
// defeat (DUR-02). The default logger is restored on return. Best-effort: a
// wiring failure still shows the benign view (the human-factors mitigation) and
// is swallowed, never surfaced to the observer.
func fireDuressTrigger(ctx context.Context, kc secrets.KeychainStore) {
	// Silence ALL degradation logging so the decoy path is byte-for-byte silent
	// on stderr, matching a real unlock (DUR-02 indistinguishability).
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	defer slog.SetDefault(prevLogger)

	logPath, err := audit.DefaultLogPath()
	if err != nil {
		slog.Warn("duress unlock: audit log path unavailable; degradation latch skipped", "err", err)
		return
	}
	var aud *audit.Audit
	if kc != nil {
		aud = audit.NewWithKeychain(logPath, kc)
	} else {
		aud = audit.New(logPath)
	}

	var reg *deadman.Registry
	if statePath, sErr := deadman.StatePath(); sErr == nil {
		reg = deadman.New(statePath, aud)
	} else {
		slog.Warn("duress unlock: registry state path unavailable; live agents not signalled (latch only)", "err", sErr)
	}
	flagPath, fErr := deadman.LockdownFlagPath()
	if fErr != nil {
		slog.Warn("duress unlock: lockdown flag path unavailable; latch skipped", "err", fErr)
	}

	if tErr := duress.Trigger(ctx, duress.TriggerOpts{
		Registry:        reg,
		FlagPath:        flagPath,
		LockdownUpdater: aud,
		Audit:           aud,
		KillGrace:       duressKillGrace,
	}); tErr != nil {
		slog.Warn("duress unlock: degradation reported errors (best-effort)", "err", tErr)
	}
}

// newDuressStatusCmd builds `duress status` — a read-only report that reveals
// no secrets and no decoy-vs-real detail.
func newDuressStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the duress decoy is configured (no secrets)",
		Example: `  # Show whether the decoy is configured (no secrets)
  abysslink duress status`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := newPrinter(cmd)
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p.Printv("enabled", strconv.FormatBool(cc.cfg.Duress.Enabled))
			if cc.cfg.Duress.Enabled {
				p.Printv("secret_source", cc.cfg.Duress.ResolvedSecretSource())
				printerInfo(p, styleMuted.Render("Casual-coercion mitigation only; NOT forensic deniability. No destructive wipe by design."))
			} else {
				printerInfo(p, styleMuted.Render("The duress decoy is OFF. Enable it with `abysslink duress enable --apply`."))
			}
			return nil
		},
	}
}
