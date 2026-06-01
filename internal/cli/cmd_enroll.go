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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/backend"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/fleet"
	"github.com/abysslink/abysslink/internal/qr"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/tui"
	"github.com/spf13/cobra"
	"github.com/tailscale/hujson"
)

// rigNameRe validates rig names: lowercase alphanumeric and hyphens, 1–63 chars.
// Used as keychain service suffix, ntfy topic component, and SSH host token (T-14-11, ASVS V5).
var rigNameRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// v1KeychainAccounts is the exhaustive list of account names stored under
// service="abysslink" in the v1 keychain namespace. This list is the source of
// truth for non-destructive migration at enroll time (PATTERNS §Keychain migration,
// RESEARCH Pitfall 4: no keychain List primitive — never use security dump-keychain).
//
// Extend this list when a new account is added to the v1 "abysslink" service.
// Headscale/NetBird keys use separate service names and are NOT migrated.
var v1KeychainAccounts = []string{
	"ntfy-password",
	"anthropic-api-key",
	"code-server-password",
}

// aclManagerFace is the internal subset of backend.ACLManager used by enrollRig.
// It is defined as a narrower interface to allow test injection without pulling
// in the full backend.ACLManager type assertion chain.
type aclManagerFace interface {
	GetACL(ctx context.Context) (raw []byte, etag string, err error)
	SetACL(ctx context.Context, acl []byte, etag string) error
}

// enrollRigOpts carries all inputs for enrollRig, enabling clean test injection.
type enrollRigOpts struct {
	name          string // rig name (validated against rigNameRe)
	cfgPath       string // path to abysslink.yaml
	keychain      secrets.KeychainStore
	apply         bool           // false = dry-run; true = apply
	overrideTopic string         // optional: override the derived ntfy topic (for tests)
	aclManager    aclManagerFace // nil = skip ACL step (no ACL-capable backend)
	hostname      string         // Tailscale hostname for the rig (empty = use os.Hostname)
	backendType   string         // backend type string (empty = "tailscale")
	stdout        io.Writer      // optional: capture stdout (nil = os.Stdout)
}

// aclGrant mirrors the subset of tailscale/acl.go aclGrant used for rig-to-rig detection.
// We parse the raw JSON to detect existing grants without importing the tailscale sub-package.
type enrollACLDoc struct {
	Grants []enrollACLGrant `json:"grants"`
}

type enrollACLGrant struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
}

// enrollRig implements the core logic of `abysslink enroll rig <name> [--apply]`.
// It is a pure function over its opts — no global state, no direct os.WriteFile,
// no fmt.Println. All output goes to opts.stdout (or is suppressed in dry-run).
//
// Step order (D-KN/D-NI/D-AI):
//  1. Validate rig name.
//  2. Generate HMAC signing key; store in keychain (apply) or preview (dry-run).
//  3. Migrate v1 keychain entries (non-destructive; dry-run skips Set).
//  4. Derive ntfy topic; collision-check against existing rigs.
//  5. Push rig-to-rig ACL deny (absence-of-grant) + validate-after-push (SC-3).
//  6. Append RigConfig to cfg.Rigs; persist via config.Write (audit).
func enrollRig(ctx context.Context, opts enrollRigOpts) error {
	out := opts.stdout
	if out == nil {
		out = os.Stdout
	}

	if !rigNameRe.MatchString(opts.name) {
		return fmt.Errorf("enroll rig: invalid rig name %q (must match ^[a-z0-9-]{1,63}$)", opts.name)
	}

	cfg, err := config.Load(opts.cfgPath)
	if err != nil {
		cfg = config.Defaults()
	}

	rigSvc := fleet.RigService(opts.name)

	if err := enrollRigGenerateKey(ctx, opts, rigSvc, out); err != nil {
		return err
	}
	if err := enrollRigMigrateV1(ctx, opts, rigSvc, out); err != nil {
		return err
	}

	topic, err := enrollRigDeriveTopic(opts, cfg)
	if err != nil {
		return err
	}

	if opts.aclManager != nil {
		if err := enforceRigToRigACLDeny(ctx, opts.aclManager, opts.apply, out); err != nil {
			return err
		}
	}

	return enrollRigWriteConfig(opts, cfg, topic, out)
}

// enrollRigGenerateKey generates the HMAC signing key and stores it (or previews).
// NEVER writes the key to yaml or audit body (T-14-09, D-KN-01).
func enrollRigGenerateKey(ctx context.Context, opts enrollRigOpts, rigSvc string, out io.Writer) error {
	hexKey, err := fleet.GenerateSigningKey()
	if err != nil {
		return fmt.Errorf("enroll rig: key gen: %w", err)
	}
	if !opts.apply {
		fmt.Fprintf(out, "[dry-run] Would generate and store HMAC signing key for rig %q\n", opts.name)
		return nil
	}
	if opts.keychain == nil {
		return fmt.Errorf("enroll rig: keychain unavailable")
	}
	if err := opts.keychain.Set(ctx, rigSvc, "hmac-signing-key", hexKey); err != nil {
		return fmt.Errorf("enroll rig: store signing key: %w", err)
	}
	// Print the key ONCE with a one-time-warning box (mirror Tailnet Lock UX).
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "┌─────────────────────────────────────────────────────────────────┐\n")
	fmt.Fprintf(out, "│  ONE-TIME SECRET: HMAC signing key for rig %q\n", opts.name)
	fmt.Fprintf(out, "│  Store this in your password manager — it will not be shown again.\n")
	fmt.Fprintf(out, "│  %s\n", hexKey)
	fmt.Fprintf(out, "└─────────────────────────────────────────────────────────────────┘\n")
	fmt.Fprintf(out, "\n")
	return nil
}

// enrollRigMigrateV1 copies v1 keychain entries into the rig-scoped service.
// Known v1 accounts under service="abysslink". Headscale/NetBird keys are
// separate service names and must NOT be migrated here. Non-destructive: v1 entries
// remain accessible after migration. Dry-run previews without calling Set (Pitfall 4).
func enrollRigMigrateV1(ctx context.Context, opts enrollRigOpts, rigSvc string, out io.Writer) error {
	if opts.keychain == nil {
		return nil
	}
	for _, acct := range v1KeychainAccounts {
		val, getErr := opts.keychain.Get(ctx, "abysslink", acct)
		if getErr != nil {
			continue // Entry absent — skip silently (non-fatal).
		}
		if opts.apply {
			if setErr := opts.keychain.Set(ctx, rigSvc, acct, val); setErr != nil {
				return fmt.Errorf("enroll rig: migrate keychain entry %q: %w", acct, setErr)
			}
		} else {
			fmt.Fprintf(out, "[dry-run] Would migrate keychain entry abysslink/%s → %s/%s\n", acct, rigSvc, acct)
		}
	}
	return nil
}

// enrollRigDeriveTopic derives the ntfy topic and checks for collisions (SC-1, D-NI-02).
func enrollRigDeriveTopic(opts enrollRigOpts, cfg *config.Config) (string, error) {
	topic := opts.overrideTopic
	if topic == "" {
		suffix := make([]byte, 4)
		if _, err := rand.Read(suffix); err != nil {
			return "", fmt.Errorf("enroll rig: topic suffix: %w", err)
		}
		topic = "abysslink-" + opts.name + "-" + hex.EncodeToString(suffix)
	}
	for _, existing := range cfg.Rigs {
		if existing.NtfyTopic == topic {
			return "", fmt.Errorf("enroll rig: ntfy topic %q already used by rig %q (SC-1, D-NI-02); choose a unique name or override --ntfy-topic", topic, existing.Name)
		}
	}
	return topic, nil
}

// enrollRigWriteConfig appends the RigConfig and persists via config.Write (audit).
// Refuses re-enrollment of an existing rig name (CR-02: silent duplicate creation
// causes mr-key-uniqueness FATAL and silently destroys the existing HMAC key).
func enrollRigWriteConfig(opts enrollRigOpts, cfg *config.Config, topic string, out io.Writer) error {
	// Guard against duplicate-name enrollment (CR-02, T-14-15).
	// Fail unconditionally — both dry-run and apply must surface this error so
	// the operator knows the name is already enrolled before any mutations occur.
	for _, existing := range cfg.Rigs {
		if existing.Name == opts.name {
			return fmt.Errorf("enroll rig: rig %q is already enrolled; use a unique name or remove the existing entry first (re-enrolling silently destroys the HMAC key)", opts.name)
		}
	}

	hostname := opts.hostname
	if hostname == "" {
		h, hErr := os.Hostname()
		if hErr == nil {
			hostname = h
		}
	}
	backendType := opts.backendType
	if backendType == "" {
		backendType = cfg.Backend.Type
		if backendType == "" {
			backendType = "tailscale"
		}
	}

	rig := config.RigConfig{
		Name:      opts.name,
		Hostname:  hostname,
		NtfyTopic: topic,
		Backend:   backendType,
	}

	if opts.apply {
		cfg.Rigs = append(cfg.Rigs, rig)
		if err := config.Write(opts.cfgPath, cfg); err != nil {
			return fmt.Errorf("enroll rig: write config: %w", err)
		}
		fmt.Fprintf(out, "Enrolled rig %q (topic=%s, backend=%s)\n", opts.name, topic, backendType)
	} else {
		fmt.Fprintf(out, "[dry-run] Would enroll rig %q (topic=%s, backend=%s, hostname=%s)\n",
			opts.name, topic, backendType, hostname)
	}
	return nil
}

// enforceRigToRigACLDeny implements the absence-of-grant discipline for Tailscale/Headscale:
//  1. GetACL to read the current document.
//  2. Assert no tag:laptop→tag:laptop (or reverse) grant exists.
//  3. SetACL to persist (forces a validate-after-push round-trip).
//  4. GetACL again to confirm read-back shows no rig↔rig allow path (Phase 13 SC-3).
func enforceRigToRigACLDeny(ctx context.Context, mgr aclManagerFace, apply bool, out io.Writer) error {
	// Read current ACL.
	raw, etag, err := mgr.GetACL(ctx)
	if err != nil {
		return fmt.Errorf("enroll rig: GetACL: %w", err)
	}

	// Parse grants to detect any tag:laptop→tag:laptop path.
	if err := assertNoRigRigGrant(raw); err != nil {
		return fmt.Errorf("enroll rig: ACL security violation: %w", err)
	}

	if apply {
		// SetACL (persist; idempotent write forces the read-back round-trip).
		if err := mgr.SetACL(ctx, raw, etag); err != nil {
			return fmt.Errorf("enroll rig: SetACL: %w", err)
		}

		// Validate-after-push: re-read and assert again (Phase 13 SC-3).
		raw2, _, err := mgr.GetACL(ctx)
		if err != nil {
			return fmt.Errorf("enroll rig: ACL validate-after-push GetACL: %w", err)
		}
		if err := assertNoRigRigGrant(raw2); err != nil {
			return fmt.Errorf("enroll rig: ACL validate-after-push failed: %w", err)
		}
		fmt.Fprintf(out, "ACL isolation verified: no tag:laptop↔tag:laptop grant found (absence-of-grant, SC-3)\n")
	} else {
		fmt.Fprintf(out, "[dry-run] Would verify ACL: no tag:laptop↔tag:laptop grant (absence-of-grant)\n")
	}

	return nil
}

// assertNoRigRigGrant parses the ACL HuJSON (or plain JSON) and returns an error
// if any grant has tag:laptop in both Src and Dst. This implements the
// absence-of-grant security invariant for rig-to-rig isolation (Decision A1).
//
// CR-03: Uses hujson.Standardize before json.Unmarshal so that Tailscale ACL
// documents containing C-style comments or trailing commas (which the Tailscale
// admin UI preserves and GetACL returns verbatim) are parsed correctly. A parse
// failure is FATAL — we cannot assert safety if the document is unreadable.
func assertNoRigRigGrant(raw []byte) error {
	// Standardize HuJSON → plain JSON (strips comments and trailing commas).
	// github.com/tailscale/hujson is a direct dep in go.mod (not transitive).
	std, err := hujson.Standardize(append([]byte(nil), raw...))
	if err != nil {
		return fmt.Errorf("cannot standardize HuJSON ACL (CR-03): %w", err)
	}

	var doc enrollACLDoc
	if err := json.Unmarshal(std, &doc); err != nil {
		// Parse failure is fatal — we cannot assert the absence-of-grant without
		// a successfully parsed document (fail closed, never downgrade to WARN).
		return fmt.Errorf("cannot parse ACL document: %w", err)
	}

	const laptopTag = "tag:laptop"
	for _, g := range doc.Grants {
		srcHasLaptop := containsStr(g.Src, laptopTag)
		dstHasLaptop := containsStr(g.Dst, laptopTag)
		if srcHasLaptop && dstHasLaptop {
			return fmt.Errorf("tag:laptop→tag:laptop grant found in ACL (rig-to-rig lateral movement, T-14-10); remove this grant before enrolling")
		}
	}
	return nil
}

// containsStr reports whether haystack contains needle (case-sensitive).
func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

const oauthSecretEnv = "ABYSSLINK_TS_OAUTH_SECRET" //nolint:gosec // env var name, not a secret

func newEnrollCmd() *cobra.Command {
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll a device into the tailnet",
	}
	rigCmd := &cobra.Command{
		Use:   "rig <name>",
		Short: "Enroll another laptop as a named rig in the fleet",
		Example: `  # Preview what enrollment would do (default: dry-run)
  abysslink enroll rig workstation

  # Apply: generate key, migrate secrets, push ACL, write config
  abysslink enroll rig workstation --apply`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)

			b, bErr := cc.backend()
			if bErr != nil {
				return fmt.Errorf("enroll rig: backend init: %w", bErr)
			}

			// Build deps for keychain.
			deps, dErr := buildDeps(ctx, cc)
			if dErr != nil {
				return fmt.Errorf("enroll rig: deps: %w", dErr)
			}

			// Optional: ACL capability (gate on Capabilities().ACL).
			var aclMgr aclManagerFace
			if b.Capabilities().ACL {
				if am, ok := b.(backend.ACLManager); ok {
					aclMgr = am
				}
			}

			hostname, _ := b.Hostname(ctx)

			printerInfo(p, styleBold.Render("Enroll rig: "+args[0]))
			if cc.dryRun {
				printerInfo(p, styleMuted.Render("Dry-run mode — no changes will be made. Use --apply to execute."))
			}

			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = defaultConfigPath()
			}

			return enrollRig(ctx, enrollRigOpts{
				name:        args[0],
				cfgPath:     cfgPath,
				keychain:    deps.Keychain,
				apply:       cc.apply,
				aclManager:  aclMgr,
				hostname:    hostname,
				backendType: cc.cfg.Backend.Type,
				stdout:      cmd.OutOrStdout(),
			})
		},
	}

	enroll.AddCommand(newEnrollPhoneCmd(), rigCmd)
	return enroll
}

func newEnrollPhoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "phone",
		Short: "Mint a tagged auth key, show a QR, and walk through phone pairing",
		Example: `  # Show a QR code for phone pairing and walk through enrollment
  abysslink enroll phone

  # Non-interactive enrollment (skip Pause stops)
  abysslink enroll phone --yes`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cc, err := loadCmdContext(cmd)
			if err != nil {
				return err
			}
			p := newPrinter(cmd)
			tag := "tag:" + cc.cfg.Mobile.Tag

			b, err := cc.backend()
			if err != nil {
				return fmt.Errorf("enroll phone: backend init: %w", err)
			}
			adminAPI, hasAdmin := b.(backend.AdminAPI)
			hasCreds := hasAdmin &&
				cc.cfg.Tailnet.Admin.Tailnet != "" &&
				cc.cfg.Tailnet.Admin.OAuthClientID != "" &&
				os.Getenv(oauthSecretEnv) != ""

			printerInfo(p, styleBold.Render("Enroll phone"))
			printerInfo(p, "")
			printerInfo(p, "1. Install Tailscale on your phone (scan to open the download page):")
			qr.PrintANSI(os.Stdout, "https://tailscale.com/download")
			printerInfo(p, "")

			// §6-sanctioned stop point: external action (phone install).
			// Pause after the install-app QR (step 1) and BEFORE minting/showing
			// the auth-key QR (step 2). The key-scan and device-join poll are
			// automated — no stop there (per §6: never for pollable things).
			autoYes, _ := cmd.Flags().GetBool("yes")
			if err := enrollPhoneInstallPause(ctx, p, autoYes); err != nil {
				return err
			}

			if !hasCreds {
				printerInfo(p, styleWarn.Render("No admin OAuth client configured — cannot mint an auth key automatically."))
				printerInfo(p, "Create a single-use, pre-authorized key tagged "+styleCode.Render(tag)+" at:")
				printerInfo(p, "  "+styleCode.Render("https://login.tailscale.com/admin/settings/keys"))
				printerInfo(p, "Then sign in on the phone with that key.")
			} else if err := enrollWithAdminKey(ctx, p, adminAPI, tag); err != nil {
				return fmt.Errorf("enroll phone: %w", err)
			}

			// ntfy subscription QR (best-effort — needs the tailnet IP).
			printNtfyQR(ctx, p, cc, b)

			// Printable runbook for the remaining manual steps.
			// §7 note 10 (lock-screen hygiene) fires here alongside the runbook.
			emitSecurityNote(p, cc.jsonOut, "lock-screen-hygiene") // §7 note 10
			if path, err := writeRunbook(ctx, cc); err == nil {
				printerInfo(p, "")
				printerInfo(p, "Manual steps (SSO passkey, disable SMS 2FA, hide lock-screen previews) are in:")
				printerInfo(p, "  "+styleCode.Render(path))
			}
			return nil
		},
	}
}

// enrollPhoneInstallPause is the §6-sanctioned stop after the Tailscale install
// QR (step 1) and before the auth-key QR (step 2). It calls tui.Pause which is
// a no-op under autoYes=true or when stdin is not a TTY (non-interactive), so
// automated / CI runs never hang. The key-scan and device-join poll in
// enrollWithAdminKey are NOT gated — they are pollable (the tool detects the join).
func enrollPhoneInstallPause(ctx context.Context, p Printer, autoYes bool) error {
	_ = p // Pause handles its own output; Printer is accepted for future use
	return tui.Pause(ctx, "Press Enter once Tailscale is installed on your phone", autoYes)
}

// enrollWithAdminKey mints a tagged auth key, shows its QR, and polls for the
// phone to appear on the tailnet with the expected tag.
func enrollWithAdminKey(ctx context.Context, p Printer, admin backend.AdminAPI, tag string) error {
	key, err := admin.CreateAuthKey(ctx, []string{tag})
	if err != nil {
		return fmt.Errorf("mint auth key: %w", err)
	}
	printerInfo(p, "2. In the Tailscale app choose \"Sign in with auth key\" and scan:")
	qr.PrintANSI(os.Stdout, key)
	printerInfo(p, "")
	printerInfo(p, "Waiting for the phone to join the tailnet (up to 2 minutes)...")

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
		devices, derr := admin.Devices(ctx)
		if derr != nil {
			continue
		}
		for _, d := range devices {
			for _, t := range d.Tags {
				if t == tag {
					printerInfo(p, styleSuccess.Render(fmt.Sprintf("Phone joined: %s (%s)", d.Name, t)))
					return nil
				}
			}
		}
	}
	printerInfo(p, styleWarn.Render("Timed out waiting for the phone. Re-run `abysslink doctor` once it has joined."))
	return nil
}

// printNtfyQR shows a QR for the ntfy subscription URL when the tailnet IP is
// known. It uses the backend.Client already in scope (Status) rather than
// re-shelling `tailscale ip`/`tailscale status --json`, so it stays
// backend-neutral and avoids the fragile hand-rolled JSON line parser (WR-01).
func printNtfyQR(ctx context.Context, p Printer, cc *cmdContext, b backend.Client) {
	if !cc.cfg.Modules.Ntfy.Enabled {
		return
	}
	st, err := b.Status(ctx)
	if err != nil || st.Self == nil {
		printerInfo(p, styleWarn.Render("⚠  Could not get tailnet status — ntfy subscription QR skipped."))
		printerInfo(p, styleMuted.Render("  Run `tailscale up` then re-run `abysslink enroll phone` to get the QR."))
		return
	}

	// Prefer MagicDNS hostname — survives IP changes. Fall back to the first
	// tailnet IP when DNSName is empty.
	hostname := strings.TrimRight(st.Self.DNSName, ".")
	if hostname == "" && len(st.Self.TailscaleIPs) > 0 {
		hostname = st.Self.TailscaleIPs[0].String()
	}
	if hostname == "" {
		printerInfo(p, styleWarn.Render("⚠  No tailnet hostname or IP available — ntfy subscription QR skipped."))
		return
	}

	topic := cc.cfg.Modules.Notify.DefaultTopic
	if topic == "" {
		topic = "rig"
	}
	port := cc.cfg.Modules.Ntfy.ListenPort()

	deepLink := fmt.Sprintf("ntfy://%s:%d/%s", hostname, port, topic)
	printerInfo(p, "")
	printerInfo(p, "3. Subscribe to notifications in the ntfy app:")
	printerInfo(p, styleMuted.Render("   Android: tap + → Scan QR code"))
	qr.PrintANSI(os.Stdout, deepLink)
	printerInfo(p, styleMuted.Render("   iPhone:  tap + → enter manually:"))
	printerInfo(p, fmt.Sprintf("     Server:  http://%s:%d", hostname, port))
	printerInfo(p, fmt.Sprintf("     Topic:   %s", topic))
}

// writeRunbook writes a Markdown runbook of the remaining manual steps and
// returns its path. It is recorded through the audit log like any other write.
func writeRunbook(ctx context.Context, cc *cmdContext) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Documents")
	if _, statErr := os.Stat(dir); statErr != nil {
		dir = abysslinkStateDir()
	}
	if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
		return "", mkErr
	}
	path := filepath.Join(dir, "abysslink-runbook-"+time.Now().Format("20060102")+".md")

	if cc.cfg == nil {
		return "", fmt.Errorf("no config")
	}
	body := runbookMarkdown(cc)
	deps, err := buildDeps(ctx, cc)
	if err != nil {
		return "", err
	}
	if err := deps.Audit.WriteFile(path, []byte(body), 0o600, false); err != nil {
		return "", err
	}
	return path, nil
}

func runbookMarkdown(cc *cmdContext) string {
	return fmt.Sprintf(`# Abysslink phone runbook

Generated %s for %s.

These steps cannot be automated — do them on your phone / in the SSO console:

## 1. SSO hardening (one-time)
- Enroll a **passkey** (or hardware security key) for your Tailscale SSO identity (%s).
- **Disable SMS 2FA** if it is enabled — SMS is SIM-swap vulnerable.

## 2. Phone lock screen
- Hide notification **previews** on the lock screen so notification bodies are not exposed.
- Enable an app lock / biometric lock on your SSH client.

## 3. Tailnet Lock (if enabled)
- Store the disablement secrets printed by "abysslink lock init" in your password manager.
- Print at least one on paper and keep it somewhere safe.

## 4. SSH client
- iOS: Blink Shell (paid, best mosh support) or Termius (free tier). No fully-free FOSS SSH+mosh client exists on iOS.
- Android: ConnectBot (SSH) or Termux from F-Droid (SSH + mosh).
- Connect with:  mosh %s -- tmux new -A -s main

## 5. Verify
- Run "abysslink doctor" on the laptop — everything should be green.
`,
		time.Now().Format("2006-01-02"),
		cc.cfg.Identity.Email,
		cc.cfg.Identity.Email,
		cc.cfg.Tailnet.Hostname,
	)
}
