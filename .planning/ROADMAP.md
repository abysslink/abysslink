# Roadmap: Abysslink

## Overview

Abysslink ships as a single static Go binary that automates a paranoid-by-default phone-to-laptop remote-control setup over Tailscale. The build journey follows the IMPLEMENTATION-TASKS.md phase structure: repo skeleton first, then a solid CLI foundation, then platform abstractions, then Tailscale integration, then the full module system with all core modules, then the complete command surface, then optional modules (claudecode, code-server, ttyd, eternal-terminal), then release infrastructure, and finally end-to-end conformance verification and polish. Every phase produces something independently verifiable before the next phase starts.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Repo Bootstrap** - Initialise repo skeleton, CI, and goreleaser pipeline; `make lint test` is green
- [x] **Phase 2: Core CLI Scaffold** - Cobra command tree, config struct, shell.Runner, audit log, Printer, and TUI forms in place
- [x] **Phase 3: Platform Abstraction** - Darwin and Linux platform impls with package manager, keychain, service installer, and distro detection
- [x] **Phase 4: Tailscale Integration** - Local API client, HuJSON ACL editor, OAuth admin client, and Tailnet Lock shell wrapper
- [x] **Phase 5: Module System & Core Modules** - Module interface, runner, and all 11 core modules (Tailscale, SSH, tmux, mosh, notify, ntfy, watch, ACL, Lock, power, hardening)
- [x] **Phase 6: Top-Level Commands** - Full command surface: init, up, status, doctor, repair, enroll, acl, lock, rotate, enable/disable, backup, panic, uninstall, logs, upgrade, daemon, threat-model, and enroll-rig stub
- [x] **Phase 7: Optional Modules** - claudecode, code-server, ttyd, and eternal-terminal modules
- [x] **Phase 8: Release Infrastructure** - goreleaser pipeline, POSIX install script, Nix flake, and mkdocs-material docs site
- [x] **Phase 9: Verification & Polish** - Conformance tool, security audit, and performance budget validation
- [x] **Phase 10: Journey & Rich TUI** - One guided, resumable, rich-TUI user journey with explicit stop points, full security callouts, and complete non-interactive/JSON parity (completed 2026-05-29)

---

## v2.0.0 — Self-Hosted Backends & Fleet ✅ SHIPPED 2026-06-02

Phases 11–14 (18 plans) — backend-pluggable (Tailscale/Headscale/NetBird) + multi-rig fleet with per-rig keychain/ntfy/ACL isolation. Audit PASSED (15/15 requirements).
→ Archived: [`milestones/v2.0.0-ROADMAP.md`](milestones/v2.0.0-ROADMAP.md) · [`milestones/v2.0.0-REQUIREMENTS.md`](milestones/v2.0.0-REQUIREMENTS.md) · audit `v2.0.0-MILESTONE-AUDIT.md`

---

## v3.0.0 — Harden, Observe & Control ✅ SHIPPED 2026-06-03

Phases 16–21 (6 phases, 24 plans) — supply-chain hardening (cosign v3 / SLSA L2 / dual SBOM / reproducible builds), tamper-evident HMAC-chained audit log + fuzzing, opt-in tailnet-bound metrics & `GET /status` + `report` + fleet digest, opt-in `//go:build webui` Web UI dashboard (TLS/WhoIs/CSRF/CSP/read-only), security-audit pass (gosec+semgrep zero-unsuppressed, 18 sec-* checks, per-backend threat model), and optional modules (WoL/atuin/sandbox/asciinema) + NetBird fleet parity. Audit PASSED (3 integration gaps closed). Every new listener opt-in, tailnet-bound, auth-gated, FATAL-doctor-gated. Local tag `v3.0.0`.
→ Archived: [`milestones/v3.0.0-ROADMAP.md`](milestones/v3.0.0-ROADMAP.md) · [`milestones/v3.0.0-REQUIREMENTS.md`](milestones/v3.0.0-REQUIREMENTS.md) · audit `v3.0.0-MILESTONE-AUDIT.md`

---

## v3.0.1 — Network & Dependency Security Hotfix ✅ SHIPPED 2026-06-04

Phases 22, 23, 23.1, 23.2, 24, 25, 26 (7 phases, 29 plans) — closes the 2026-06-03 full security audit (11 agents): network/dependency lockdown (ntfy tailnet-only bind, NetBird https-only server_url, argv-injection guards, go1.26.4 / x/crypto v0.52.0 / CSRF→net/http.CrossOriginProtection), doctor/threat-model honesty (shared finding set, fail-closed disk encryption, nb-lock warning, minimum-versions table, probe-failure tri-state), tamper-evident audit hardening (HMAC-chained backups, anchor-every-append + keychain counter, cross-process flock, direction-aware verifyCounter), DoS bounding (limitio + WriteFilePath streaming), and a blocking govulncheck CI gate. All 20 requirements verified. Audit PASSED. Phase 26 (post-ship fold-in, after pushed tag `v3.0.1`): gated 8-stage init journey + first-run fixes (openURL, Stage 2 autoYes, pmset parse, sudo RunInteractive, terminal restore) — verification 25/25, human UAT approved. Deferred: Phase 23 FileVault mid-encryption `fdesetup` string literals (MED, real-hardware confirmation; fail-closed regardless).
→ Archived: [`milestones/v3.0.1-ROADMAP.md`](milestones/v3.0.1-ROADMAP.md) · [`milestones/v3.0.1-REQUIREMENTS.md`](milestones/v3.0.1-REQUIREMENTS.md) · audits [`milestones/v3.0.1-MILESTONE-AUDIT.md`](milestones/v3.0.1-MILESTONE-AUDIT.md) (phases 22–25) + [`milestones/v3.0.1-MILESTONE-AUDIT-phase-26.md`](milestones/v3.0.1-MILESTONE-AUDIT-phase-26.md) (incremental, supersedes)

---

## v4.0.0 — Launchpad ✅ SHIPPED 2026-06-21 (merged via PR #38 on 2026-06-23; launch gates LNCH-02/04/05/06 operator-owned — see milestones/v4.0.0-MILESTONE-AUDIT.md + LAUNCH.md)

**Milestone goal:** Ship the revenue substrate (session-aware notification backbone + phone approve loop + agent kill-switch) and launch Abysslink publicly. The CLI stays free OSS forever; every future paid product (mobile app first, v5, separate repo) sits on this milestone's platform.

**Immutable rule added this milestone:** the push payload carries routing metadata only — no body, no secrets, no code. Content is fetched over the tailnet. APNs/FCM/ntfy.sh see a device token, a generic title, and opaque session IDs, never content.

**Structure:** 7 phases (27–33), compressed from the 9-phase research proposal per coarse granularity — contracts/seams fold into Phase 27 as its first plans; enrollment + content store merge into Phase 28 with enrollment-before-store preserved as intra-phase ordering. All research-verified ordering invariants hold: registry before gateway, enrollment before content store, approve/kill-switch decoupled from the gateway (both ride existing ntfy), supply-chain strictly before distribution, launch last behind its three blocking gates.

**Parallel track (non-blocking):** Apple Developer account paperwork ($99/yr enrollment, .p8 APNs key, Developer ID for Gatekeeper) starts at milestone start in parallel with Phase 27 — it feeds Phase 29 (APNs leg) and Phase 33 (Homebrew cask signing) but never blocks the critical path; the launch headline rides existing ntfy by design.

- [x] **Phase 27: Session-Aware Notification Backbone** - notify-v2 typed schema + shell.Runner streaming + GatedRunner seam + tmux -CC session registry + v2 dispatch over existing ntfy (executed 2026-06-10; verification found gaps — see 27-VERIFICATION.md) (completed 2026-06-10)
- [x] **Phase 28: Device Enrollment v2 & Tailnet Content Delivery** - per-device revocable credentials (token/bearer/SSH cert, panic-wired) + tailnet-only content store + ack receipts + safe fallback titles (implemented 2026-06-11 via Fable multi-agent build outside the GSD plan loop; 3 adversarial review passes; cross-process revoke-race + FetchRef TLS-host fixes; see 28-SUMMARY.md) (completed 2026-06-11)
- [x] **Phase 28.1: Device SSH CA sshd Integration** - auto-wire `TrustedUserCAKeys` to the device CA + enforce revocation via an `ssh-keygen -k` KRL referenced by `RevokedKeys`, both through the existing hardened-sshd reconcile path (DEVC-05/06; closes Phase 28's manual-CA-copy-paste + dead `RevokedSerials()` threads) (completed 2026-06-14)
- [x] **Phase 29: Push Gateway & Outbox** - push.Gateway interface + bbolt outbox; UnifiedPush/ntfy sovereign path shipped working, APNs/FCM interface-complete experimental (completed 2026-06-15)
- [x] **Phase 30: Phone Approve Loop** - signed single-use approve/deny bound to execution-closure hash, GatedRunner flips enforcing, pre-app bridges with tier policy, claudecode consumer (plans complete + verified 5/5; awaiting human UAT 2026-06-17) (completed 2026-06-17)
- [x] **Phase 31: Agent Kill-Switch ("Apoptosis")** - budget module: notify → SIGSTOP-then-ask → kill ladder, shadow-mode default, pgid kill, rollback offer, flight-recorder cast hash in audit chain (5/5 plans; shipped ladder nil-panic closed in 31-05) (completed 2026-06-18)
- [x] **Phase 32: Supply-Chain Depth & Trimmed Fortify** - SLSA L3 + Scorecard + Syft/Grype/VEX, doctor external version floors, cheap MED gaps, at-risk profile + dead-man switch (7/7 plans; 3 release-gated proofs fire at the v4 tag) (completed 2026-06-20)
- [x] **Phase 33: Distribution & Public Launch** - Homebrew cask + AUR pinned to attested artifacts; quickstart fire-drill, claims audit, real-device sovereign push test gate the Show HN launch (3/3 plans; launch-ready artifacts built + verified 7/7 must-haves; LNCH-02/04/05/06 operator gates — see 33-VERIFICATION.md) (completed 2026-06-21)

---

## v4.1.0 — Surface & Depths 🚧 IN PROGRESS (started 2026-06-24)

**Milestone goal:** Three equal-weight threads — (A) replace the v1 guided journey + 8-stage `init` wizard with a polished on-brand interactive TUI (the *surface*); (B) clear the full deferred at-risk security backlog (the *depths*); (C) post-launch hardening/polish from real launch feedback. Every new security item strengthens a floor; no floor weakens. The CLI stays free OSS forever.

**Immutable floors carried (unchanged):** `--dry-run` default; secrets never on argv / never in audit; ntfy + listeners bind tailnet IP only (the loopback OAuth callback is a same-host rendezvous on `127.0.0.1`, distinct from the tailnet-bind rule); Tailnet Lock on by default, disablement secrets printed once never stored; FileVault/LUKS fail-closed; SSH `checkPeriod` 12h; only `internal/cli` writes stdout/stderr via `Printer`; all exec via `shell.Runner`; all file mutations via `internal/audit`; no Claude coupling in core modules; push payload = routing metadata only.

**Scope decisions (2026-06-24, research-driven):** duress = non-destructive decoy config only (destructive wipe dropped — theater + self-DoS); hardware keys = macOS Secure Enclave default + FIDO2 opt-in, both cgo-free shell-out (`CGO_ENABLED=0` floor); browser spawn routed through the existing `shell.Runner` openURL/`shell.LookPath` (not `pkg/browser`'s `os/exec` — pkg/browser allowed for detection only); attestation = local boot-state reads only (no cloud/remote verifier).

**Structure:** 6 phases (34–39), continuing the phase numbering from v4.0.0 (last phase 33). Compressed from the 7-phase research proposal per coarse granularity — TUI theme + IO boundary + banner + CGO=0 guard fold into Phase 34 (foundation); the flow layer, `init` rebuild, `journey.go` deletion, browser hand-off and `gallery` merge into Phase 35; Secure Memory + the highest-risk HMAC-key rotation stay together in Phase 36 (mlock underpins rotation); hardware keys + local attestation merge into Phase 37 (both depend on MEM, both cgo-free shell-out); backlog closure B1/B2/B8 + at-risk doctor coverage is the independent low-cost Phase 38; the cross-thread duress/decoy join folds together with post-launch polish in the closing Phase 39. All research ordering invariants hold: theme/IO boundary before the flow (everything consumes the theme; the boundary prevents `Printer` regressions); MEM before ROT and before HWK; duress last (needs the new flow AND the security providers).

**Research flags (deep research at phase planning):** Phase 36 (HMAC epoch'd-chain design — the single highest-risk item: versioned epochs, in-chain marker signed by the OLD key, per-entry key selection, no false TAMPERED); Phase 37 (cgo-free per-platform hardware-key + attestation paths); Phase 38 (real-hardware FileVault mid-encryption string literals — known gap until verified); Phase 39 (duress threat model — casual-coercion, NOT forensic plausible-deniability).

- [ ] **Phase 34: TUI Foundation** - Abyss two-tone `*huh.Theme` + reusable lipgloss styles + go-figure banner (NO_COLOR/non-truecolor degrade) + Printer/huh IO boundary wired first + CGO_ENABLED=0 four-target cross-build CI guard
- [ ] **Phase 35: Browser Hand-off & Wizard Flow** - composable `internal/flow` steps threading one typed FlowState; `init` rebuilt on the flow layer + `journey.go` deleted; glamour-rendered results via Printer; `internal/browser` fire-and-forget + RFC 8252 loopback OAuth callback (+PKCE); cyan spinner + bordered framing + footer + hidden `gallery`
- [ ] **Phase 36: Secure Memory & Audit HMAC-Key Rotation** - `SecureBytes` mlock/zeroize in `internal/secrets` (honest WARN on RLIMIT_MEMLOCK, defense-in-depth framing); versioned audit-chain key epochs + `rotate audit-hmac --apply` (marker signed by OLD key, old keys retained) + `sec-` doctor checks — HIGHEST-RISK, research-flagged
- [ ] **Phase 37: Hardware-Backed Keys & Local Attestation** - macOS Secure Enclave + FIDO2 opt-in `HardwareKeyProvider` (cgo-free `ssh-keygen` shell-out through `shell.Runner`, fail-closed, key-kind in `status`); `internal/attest` local boot-state reads (csrutil/SIP, SecureBoot/TPM PCR) fail-closed tri-state in `doctor`/`--profile at-risk` — research-flagged
- [ ] **Phase 38: Backlog Closure & Doctor Coverage** - B1 Tailnet Lock WARN → hard gate w/ explicit override; B2 FileVault mid-encryption fail-closed (string-literal real-hardware gap flagged); B8 per-rig fleet HMAC domain separation; every new v4.1 footgun gets a paired `sec-` doctor check wired into `--profile at-risk` (tightened to FATAL)
- [ ] **Phase 39: Duress/Decoy & Post-Launch Polish** - non-destructive decoy config (constant-time compare, panic-paired, indistinguishability check, honest casual-coercion threat-model copy, audit-logged without leaking which credential); quickstart < 10 min re-measured against the new TUI; launch-feedback doctor gaps closed; no-telemetry / no-scope-creep held — research-flagged (duress threat model)

---

## Phase Details

### Phase 1: Repo Bootstrap

**Goal**: The repository compiles, lints, and tests clean with full CI coverage and a goreleaser release pipeline wired up
**Depends on**: Nothing (first phase)
**Requirements**: REPO-01, REPO-02, REPO-03, REPO-04, REPO-05, REPO-06
**Success Criteria** (what must be TRUE):

  1. `go build ./...` and `go vet ./...` exit 0 on the package skeleton with `doc.go` in every package
  2. `make lint test` exits 0 on macOS 13+ and Ubuntu 22.04
  3. CI matrix runs on ubuntu-latest + macos-latest for Go 1.22 and 1.23 and passes on a fresh PR
  4. `goreleaser --snapshot` produces darwin/amd64, darwin/arm64, linux/amd64, linux/arm64 archives plus .deb and .rpm
  5. Repo has Apache-2.0 LICENSE, NOTICE, SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md, .gitignore, .editorconfig, and .golangci.yml

**Plans**: 3 plans

Plans:

- [ ] 01-01-PLAN.md — Go module init + Apache-2.0 legal files + .golangci.yml tooling config
- [ ] 01-02-PLAN.md — Makefile (6 targets) + full package skeleton (doc.go in every package) + abysslink.yaml.example
- [ ] 01-03-PLAN.md — GitHub Actions CI matrix + goreleaser release pipeline

### Phase 2: Core CLI Scaffold

**Goal**: Developers can run any `abysslink` subcommand stub, config round-trips cleanly, and every cross-cutting internal (shell, audit, printer, TUI) has full test coverage
**Depends on**: Phase 1
**Requirements**: CLI-01, CLI-02, CLI-03, CLI-04, CLI-05, CLI-06, CLI-07, CLI-08
**Success Criteria** (what must be TRUE):

  1. `abysslink --help` lists every subcommand from DESIGN.md §5; each responds to `--help`
  2. `--dry-run` is the active default for all mutating subcommands; `--apply` is required to mutate
  3. Config struct round-trips cleanly from YAML; unknown keys error in strict mode; `abysslink.yaml.example` passes its own validation
  4. `internal/shell` has 100% test coverage via `MockRunner`; no bare `os/exec` calls exist outside that package
  5. Audit log writes JSON-line entries with backup; `Restore(ts)` round-trips; no secret content appears in log body
  6. Printer snapshot tests pass in both human and `--json` modes with `NO_COLOR` respected

**Plans**: 3 plans

Plans:

- [ ] 02-01-PLAN.md — Go dependencies + cmd/abysslink/main.go wiring + Cobra command tree (all subcommand stubs)
- [ ] 02-02-PLAN.md — internal/config (Config struct, Defaults, Load, Validate) + internal/shell (Runner, ExecRunner, MockRunner) with 100% coverage
- [ ] 02-03-PLAN.md — internal/audit (Append, Backup, Restore) + internal/cli/printer + internal/tui (styles, forms) + make lint test gate

### Phase 3: Platform Abstraction

**Goal**: Abysslink can install packages, manage services, store secrets in the OS keychain, and detect disk encryption status on both macOS and Linux without any platform-specific code leaking above `internal/platform`
**Depends on**: Phase 2
**Requirements**: PLAT-01, PLAT-02, PLAT-03, PLAT-04
**Success Criteria** (what must be TRUE):

  1. `Platform` interface is satisfied by Darwin and Linux impls; stub compiles for cross-compile targets
  2. Linux distro detection from `/etc/os-release` correctly maps debian/ubuntu/fedora/rhel/centos/arch/nixos to the right package manager in table-driven tests with fixtures
  3. Keychain adapter stores and retrieves a secret without putting it on argv; macOS uses `security`, Linux tries `secret-tool` then `pass` then emits a clear error
  4. Service install/uninstall round-trip leaves no launchd plist or systemd unit artifacts on disk

**Plans**: TBD

### Phase 4: Tailscale Integration

**Goal**: Abysslink can query and drive tailscaled, edit ACLs round-trip in HuJSON, call the Tailscale admin API, and shell Tailnet Lock operations — all against mocked or real backends
**Depends on**: Phase 3
**Requirements**: TS-01, TS-02, TS-03, TS-04
**Success Criteria** (what must be TRUE):

  1. `internal/tailscale/local.go` correctly reports Status, IP, Hostname, and Lock state and handles both open-source tailscaled and the GUI variant
  2. `internal/tailscale/acl.go` parses, mutates, and re-serialises a real HuJSON ACL preserving comments and trailing commas; golden-file tests pass
  3. `internal/tailscale/admin.go` OAuth flow completes against an `httptest.Server`; manual-mode degrades to clipboard+browser-open
  4. `internal/tailscale/lock.go` Init captures disablement secrets to stdout and never writes them to disk; integration test passes against real `tailscale` binary

**Plans**: TBD

### Phase 5: Module System & Core Modules

**Goal**: `abysslink up --apply` converges every core module in dependency order; each module is independently testable and idempotent; a second run on an already-converged machine is a no-op
**Depends on**: Phase 4
**Requirements**: MOD-01, MOD-02, MOD-03, MOD-04, MOD-05, MOD-06, MOD-07, MOD-08, MOD-09, MOD-10, MOD-11, MOD-12, MOD-13
**Success Criteria** (what must be TRUE):

  1. Module interface (Detect, Plan, Apply, Verify, Repair) is implemented by all 11 core modules; dependency graph produces correct topological order
  2. Module runner propagates context cancellation; a second `up --dry-run` on a converged machine produces an empty plan
  3. ntfy server config binds exclusively to the tailnet IP; health check verify passes; admin password is in keychain and never appears in audit log
  4. `abysslink notify "title" "body"` delivers a notification via the ntfy backend; socket round-trip is under 100 µs
  5. `abysslink watch add/list/remove` works; pane-idle, file-tail, and HTTP-change watchers hot-reload on YAML change inside `abysslinkd`
  6. Hardening module: `doctor` fails closed on macOS if FileVault is off; warns on Linux if home is on an unencrypted disk

**Plans**: TBD
**UI hint**: yes

### Phase 6: Top-Level Commands

**Goal**: Every user-facing command documented in DESIGN.md §5 is fully implemented and acceptance-tested; the CLI is the complete product surface
**Depends on**: Phase 5
**Requirements**: CMD-01, CMD-02, CMD-03, CMD-04, CMD-05, CMD-06, CMD-07, CMD-08, CMD-09, CMD-10, CMD-11, CMD-12, CMD-13, CMD-14, CMD-15, CMD-16, CMD-17, CMD-18
**Success Criteria** (what must be TRUE):

  1. `abysslink init` completes an interactive wizard end-to-end with scripted inputs and writes a valid `abysslink.yaml`
  2. `abysslink up --apply` on a fresh machine converges all enabled modules; `--dry-run` on a converged machine completes in under 3 seconds
  3. `abysslink status` renders a one-screen summary in under 500 ms warm / 2 s cold; `--json` mode is machine-parseable
  4. `abysslink doctor` exits 0/1/2 with correct severity; every footgun from `04-troubleshooting.md` has a corresponding check
  5. `abysslink panic` completes all revocations within 10 seconds with no confirmation prompt and logs to audit and ntfy
  6. `abysslink enroll phone` mints a tagged auth key, displays ANSI-art QR, polls for device join, and produces a printable PDF runbook
  7. `abysslink upgrade` verifies the sigstore/cosign signature before replacing the binary; refuses to run as root

**Plans**: TBD
**UI hint**: yes

### Phase 7: Optional Modules

**Goal**: The four optional modules (claudecode, code-server, ttyd, eternal-terminal) are installable, configurable, and verifiable via `abysslink doctor`
**Depends on**: Phase 6
**Requirements**: OPT-01, OPT-02, OPT-03, OPT-04
**Success Criteria** (what must be TRUE):

  1. `claudecode` module writes `~/.claude/settings.json` hooks calling `abysslink notify`; Anthropic API key is stored in keychain; `doctor` checks for post-reboot keychain unlock
  2. `code-server` module installs, binds to tailnet IP only, stores password in keychain, and is HTTPS-reachable on ACL-granted port
  3. `ttyd` module installs with `tailscale cert` HTTPS, binds to tailnet IP, and emits a basic-auth warning on first access
  4. `eternal-terminal` module installs ET server + client, installs a service unit, and grants ACL tcp/2022

**Plans**: TBD

### Phase 8: Release Infrastructure

**Goal**: Any tagged `v*` commit produces signed, verifiable multi-arch release artifacts installable via a one-liner on macOS and Linux; Nix users can build from the flake; docs deploy automatically
**Depends on**: Phase 7
**Requirements**: REL-01, REL-02, REL-03, REL-04
**Success Criteria** (what must be TRUE):

  1. `goreleaser --snapshot` produces all four OS/arch binaries, .deb, .rpm, SBOM, and cosign signature without error
  2. `scripts/install.sh` runs without root on Ubuntu 22.04, Debian 12, Fedora 40, macOS 13, and macOS 14; cosign-verifies the download; shellcheck exits 0
  3. `nix flake check` passes; `nix build .#abysslink` produces the binary
  4. `mkdocs build` succeeds; docs site includes quickstart, module pages, threat model, troubleshooting, FAQ, and contributing

**Plans**: TBD

### Phase 9: Verification & Polish

**Goal**: Abysslink passes a full conformance run, a security audit, and a performance budget check on all supported platforms; the project is ready for a v1.0.0 tag
**Depends on**: Phase 8
**Requirements**: QA-01, QA-02, QA-03
**Success Criteria** (what must be TRUE):

  1. `cmd/abysslink-conformance` drives fresh→init→up→doctor, module disable+re-enable, 6+ break-and-repair scenarios, reboot+keychain-locked flow, and panic+recovery without failure
  2. Security audit passes: no secrets in audit log (grep), no secrets on argv (gosec), no telemetry calls, default YAML matches threat-model defaults, upgrade verifies signature
  3. Performance budget met: `status` under 500 ms warm / 2 s cold; `up --dry-run` on converged machine under 3 s; `abysslinkd` resident under 20 MB; CLI binary under 50 MB

**Plans**: TBD

### Phase 10: Journey & Rich TUI

**Goal**: The entire user journey is a single guided, resumable, rich-TUI flow with explicit stop points, complete security callouts, and full non-interactive/JSON parity — enterprise-grade, nothing missing
**Depends on**: Phase 9
**Requirements**: UX-01, UX-02, UX-03, UX-04, UX-05, UX-06, UX-07, UX-08, UX-09, UX-10
**Success Criteria** (what must be TRUE):

  1. `abysslink init` guides a new user from zero to a working phone connection + a verified `doctor` in one command, with a stage progress header and explicit stop points; every stage is independently runnable and idempotent (re-run is a no-op or clean resume)
  2. Every system mutation is preceded by a preview + confirm (or `--yes`), is backed up, and is reversible; fail-closed gates (disk encryption, 12h checkperiod) still block correctly
  3. The interface is live (animated spinner + module progress table) on a TTY and plain off it; `NO_COLOR` honored; never hangs waiting for input in non-interactive / CI contexts
  4. `status`, `doctor`, and `up` emit structured `--json` with no ANSI escapes; exit codes 0/1/2 are correct and documented
  5. All 12 required security notes (USER-JOURNEY-TUI.md §7) appear at the correct journey points; the Tailnet Lock guided path shows disablement secrets once and requires the typed `I HAVE PRINTED IT` attestation
  6. `make lint test` green; conformance scenarios (`cmd/abysslink-conformance`) cover the guided journey end-to-end

**Plans**: 6 plans

Plans:

- [x] 10-01-PLAN.md — TUI primitives: Pause, ConfirmTyped, ConfirmBlast, Note, JourneyHeader, SecretBox (UX-02)
- [x] 10-02-PLAN.md — Terminal capability detection (term.go) + structured ANSI-free JSON printer (UX-03, UX-04)
- [x] 10-03-PLAN.md — Live rich TUI components (spinner, module table, progress bar) + `up` ConfirmBlast apply gate (UX-01, UX-06)
- [x] 10-04-PLAN.md — Pre-mutation config preview + high-blast typed confirms for uninstall/backup-restore (UX-06, UX-08)
- [x] 10-05-PLAN.md — Guided Setup Journey orchestrator (7 stages + resume) + Tailnet Lock once-only secret box & typed attestation (UX-05, UX-07)
- [x] 10-06-PLAN.md — Output parity & polish: exit codes, status/doctor JSON+tables, `--explain`, 12 security notes, panic feedback, conformance (UX-09, UX-10)

**UI hint**: yes

---

### Phase 22: Network & Dependency Lockdown

**Goal**: Close 6 CRITICAL/HIGH security findings from the 2026-06-03 full audit: restore the ntfy tailnet-only bind floor (NET-01 CRITICAL), close the cleartext-PAT gap for NetBird (NET-02), close the flag-injection gap in hostname/server_url config (NET-03), and eliminate all reachable stdlib CVEs by bumping Go to 1.26.4 (DEP-01), x/crypto to v0.52.0 (DEP-02), and replacing the unmaintained gorilla/csrf (CVE-2025-47909) with stdlib CrossOriginProtection (DEP-03).
**Depends on**: Phase 21
**Requirements**: NET-01, NET-02, NET-03, DEP-01, DEP-02, DEP-03
**Success Criteria** (what must be TRUE):

  1. `govulncheck ./...` reports 0 reachable CVEs; go.mod `go` directive = `1.26.4`; all 6 CI workflows use `go-version: "1.26.4"`
  2. `go list -m golang.org/x/crypto` ≥ v0.52.0
  3. `go mod why github.com/gorilla/csrf` = "not needed"; `go mod graph | grep gorilla/csrf` = empty; `go build -tags webui ./...` = 0 errors
  4. `config.Validate` rejects NetBird `server_url` with `http://` prefix and rejects `tailnet.hostname` with leading dash or non-DNS-safe chars
  5. `abysslink doctor` includes ntfy-bind and ntfy-loopback findings; ntfy docker run argv has no `127.0.0.1` port mapping
  6. `make lint test` green; all new tests (TestNtfyBindCheck, TestNtfyLoopbackReachCheck, TestValidateNetBirdHTTP, TestValidateHostname) pass

**Plans**: 4 plans

Plans:

- [x] 22-01-PLAN.md — Go toolchain + x/crypto bump: go.mod go 1.26.3→1.26.4 + x/crypto v0.52.0 + all 6 CI workflows aligned (DEP-01, DEP-02)
- [x] 22-02-PLAN.md — Config validation: NET-02 NetBird https guard + NET-03 safeHostnamePat + hostname/server_url charset gates (NET-02, NET-03)
- [x] 22-03-PLAN.md — ntfy tailnet-bind floor: remove loopback -p from module.go + new cmd_doctor_ntfy.go with dual-signal doctor check (NET-01)
- [x] 22-04-PLAN.md — WebUI CSRF migration: safeweb→stdlib CrossOriginProtection + 5 security headers + gorilla-free go.mod (DEP-03)

---

### Phase 23: Doctor Honesty & Coverage

**Goal**: Make the security-posture surface honest — `threat-model` and `doctor` report from one shared finding set, disk-encryption verification fails closed on unknown/error state, the NetBird backend surfaces Tailnet-Lock-absent unconditionally, and `doctor` gains a minimum-versions table that FATALs on known-vulnerable component versions.
**Depends on**: Phase 22
**Requirements**: DOC-01, DOC-02, DOC-03, DOC-04
**Success Criteria** (what must be TRUE):

  1. `abysslink threat-model` derives every row's ✓/✗ from the SAME full finding set as `abysslink doctor` (`collectDoctorFindings`), not just core-module `Doctor()`; rows whose backing check did not run render "unknown/—", never ✓ (DOC-01)
  2. Linux `checkLUKS` emits FATAL when `lsblk` is missing/errors/unparseable (not `nil,nil`); macOS treats FileVault in-progress/deferred as not-fully-enabled; `up`'s disk-encryption gate blocks on "unknown" (DOC-02)
  3. The NetBird backend emits an unconditional `nb-lock` SeverityWarning (Tailnet Lock absent), mirroring the existing `hs-lock`, and the `threat-model` row reflects it (DOC-03)
  4. `abysslink doctor` surfaces a minimum-versions table that FATALs on known-vulnerable versions — at minimum ntfy < 2.21 (CVE-2026-39087, CVSS 9.8); structured to add Tailscale/tmux/mosh floors; distinguishes vendored-stdlib CVEs from protocol CVEs (DOC-04)
  5. `make lint test` green; new tests cover threat-model/doctor finding-set parity, fail-closed disk-encryption states, the `nb-lock` warning, and the version-floor table

**Plans**: 4 plans
Plans:
**Wave 1**

- [x] 23-01-PLAN.md — DOC-01 OK-emission backfill for 5 core-module checks (funnel, acl_drift, remote_login/sshd_running, lock_enabled, listen_address) + per-module OK tests
- [x] 23-02-PLAN.md — DOC-02 fail-closed disk encryption: checkLUKS/checkFileVault FATAL on unknown/in-progress + filevault/luks OK backfill (single-emission) + MockRunner tests
- [x] 23-03-PLAN.md — DOC-03 unconditional nb-lock advisory WARN + DOC-04 version-floor table/detector (ntfy <2.21 FATAL, CVE-2026-39087) + findingFix remediation

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 23-04-PLAN.md — DOC-01 tri-state threat-model over collectDoctorFindings + DOC-04 floor wiring + DOC-02 up gate non-overridable for unknown + lint/test gate

### Phase 24: v3.0.1 security closeout — audit-chain integrity, bounded reads, and govulncheck CI gate (AUD-01, AUD-02, DOS-01, CI-01)

**Goal:** Close the final 4 v3.0.1 security requirements so the milestone reaches 20/20: bind backups to the tamper-evident HMAC chain and resist tail-truncation (AUD-01, AUD-02), bound every attacker-influenceable read (DOS-01), and add `govulncheck ./...` as a blocking CI gate (CI-01).
**Requirements**: AUD-01 (A9 HMAC-bound backups), AUD-02 (A10 anchor-refresh truncation resistance), DOS-01 (A11 bounded reads), CI-01 (govulncheck blocking CI gate)
**Depends on:** Phase 23.2
**Plans:** 7/7 plans complete

**Wave 1** *(parallel)*

Plans:

- [x] 24-01-PLAN.md — AUD-01: BackupWithChain + RestoreGated (HMAC-bound backup + chain-walk restore gate)
- [x] 24-02-PLAN.md — CI-01: harden-runner on lint.yml + test.yml + REQUIREMENTS.md:93 Phase 24 fix
- [x] 24-04-PLAN.md — DOS-01 Part A: limitedWriter (exec.go) + MaxBytesReader (/notify) + readLimited on 15 NetBird seam sites

**Wave 2** *(depends on Wave 1)*

- [x] 24-03-PLAN.md — AUD-02: per-Append anchor (fatal) + ReadCounter/WriteCounter + Verify CounterStatus UNKNOWN tri-state *(blocked on 24-01)*
- [x] 24-05-PLAN.md — DOS-01 Part B: tailscale/limit.go + readLimited on 7 admin.go + 8 Headscale seam sites *(blocked on 24-04)*

**Wave 3 — gap closure** *(VERIFICATION.md found AUD-01 + AUD-02 BLOCKERs; AUD-01/AUD-02 chain functions were dead code / counter-failure faked a permanent truncation alarm)*

- [x] 24-06-PLAN.md — AUD-02 gap: Append deletes the keychain counter key on IncrementCounter failure so Verify degrades to CounterStatus="unknown" instead of a permanent false "mismatch"/TRUNCATION_DETECTED
- [x] 24-07-PLAN.md — AUD-01 gap: wire BackupWithChain (WriteFile + netbird + headscale) and RestoreGated (live `backup restore` + --accept-unverified-backup, fail-closed) into production so the A9 chain gate is live *(blocked on 24-06: shared signed.go)*

### Phase 25: Close v3.0.1 debt: config.Validate-on-load, CLI bounded reads, AUD-02 concurrency

**Goal:** Wire config.Validate into config.Load (fail-closed), bound all CLI remote-response and binary-install reads, and fix the AUD-02 cross-process concurrency defects so the v3.0.1 milestone audit reaches zero outstanding code items.
**Requirements**: NET-02, NET-03, DOS-01, AUD-02, DOC-03, DOC-04
**Depends on:** Phase 24
**Plans:** 5/5 plans complete

Plans:

- [x] 25-00-PLAN.md — Wave 0: Test scaffolding (limitio_test, config_load_test, flock.go stub, signed_test additions)
- [x] 25-01-PLAN.md — limitio leaf package + backend/limit.go wrapper + DOC-03 nb-lock findingFix + DOC-04 ntfy-version threatRows
- [x] 25-02-PLAN.md — config.Load fail-closed (D-01) + 4 swallowing callers fixed + NET-03 argv defense-in-depth (D-03)
- [x] 25-03-PLAN.md — DOS-01 CLI bounded reads: 4 sites (D-05) + WR-02 audit.WriteFilePath streaming (D-06)
- [x] 25-04-PLAN.md — AUD-02 flock (D-07) + appendNoRefresh single anchor/counter refresh per WriteFile (D-08)

### Phase 26: Init journey gating & first-run fixes

**Goal:** `abysslink init` becomes a genuinely gated interactive wizard: each journey stage pauses for user confirmation, stages 3–6 offer to actually run `up --apply` / `lock init --apply` / `enroll phone` / `doctor` (instead of printing the command and scrolling past), a new ACL stage guides `abysslink acl push --apply`, and three first-run bugs are fixed — (1) openURL macOS probe uses `open --version` which exits 1 so the browser never opens yet "Browser opened" is printed (cmd_init.go:228-246, 200-206); (2) journey Stage 2 hardcodes autoYes=true (journey.go:113,116) so sudo mutations run unprompted and duplicate init RunE work; (3) checkACSleepDisabled pmset parser requires exactly-2-field "sleep 0" lines, but `pmset -g` emits trailing annotations, so `sudo pmset` re-runs every init (cmd_init.go:594-606). Headless paths (--yes/--json/non-TTY) stay non-blocking; --resume keeps working via journey-state.json. The documented "journey is NON-BLOCKING" design comment in journey.go and the DESIGN.md §6/§7 references must be reconciled.
**Requirements**: TBD
**Depends on:** Phase 25
**Plans:** 3/3 plans complete
Plans:
**Wave 1**

- [x] 26-01-PLAN.md — shell.LookPath + openURL B1 fix + checkACSleepDisabled B3 fix + regression tests

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 26-02-PLAN.md — B2 fix (Stage 2 no-dup) + 8-stage gated journey + per-stage gates + ACL stage + updated tests

**Wave 3 (gap-closure)** *(blocked on Wave 2 completion)*

- [x] 26-03-PLAN.md — sudo tty-wiring (RunInteractive for privileged calls) + power module already-disabled short-circuit + terminal state teardown before child spawn

**Cross-cutting constraints:**

- make lint test green

---

### Phase 27: Session-Aware Notification Backbone

**Goal**: Notifications identify the exact tmux session, window, and pane that needs attention — typed, secret-free by construction, delivered over the existing ntfy path with zero new external accounts
**Depends on**: Phase 26 (v3.0.1 complete — first phase of v4.0.0)
**Requirements**: BACK-01, BACK-02, BACK-03, BACK-04, BACK-05
**Success Criteria** (what must be TRUE):

  1. A notification arriving on the phone reads like "rig-1 · claude · %3 needs input" — host, consumer, and `{$session,@window,%pane}` identity included — never a bare "agent needs you"
  2. `GET /sessions` on the daemon unix socket lists live tmux sessions/windows/panes with a `needs_input` state that sets on the watch idle-prompt heuristic and clears on new output; the registry survives a tmux server restart (registry epoch bump), reconnects with backoff, and refuses tmux < 3.2 with a clear message
  3. A v2 `Message` carrying any body/content/secret-bearing field is rejected by `Validate()` — only routing metadata (ULID msg_id, kind, session IDs + epoch, deep_link, fetch ref, priority, actions) and a safe generic title ever leave the daemon
  4. Existing v1 `POST /notify` consumers (fleet fan-out posts v1 today) keep working unchanged alongside v2 dispatch
  5. `tmux -CC` control mode runs through the new `shell.Runner` streaming method (ExecRunner live + MockRunner transcript playback) with structural events only and `list-panes` poll as source of truth — no `os/exec` bypass, no `%output` subscription

**Plans**: 8 plans
Plans:
**Wave 1**

- [x] 27-01-PLAN.md — internal/notifyv2 leaf: Message schema + Validate() + ntfy renderer (BACK-01)
- [x] 27-02-PLAN.md — shell.RunStream streaming method + MockRunner transcript playback + ResolvePath (BACK-02)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 27-03-PLAN.md — internal/session core: config, model, control-mode parser, supervisor + version gate (BACK-03)
- [x] 27-04-PLAN.md — internal/gate observe-only GatedRunner + composition-root injection + /status counter (BACK-02)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 27-05-PLAN.md — daemon v2 dispatch: Notifier widening, X-Click, cooldown/ceiling/retry policy, handleNotify v2 branch (BACK-05)
- [x] 27-06-PLAN.md — needs_input heuristic + transition emission incl. restart-lost (BACK-03, BACK-04)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 27-07-PLAN.md — GET /sessions + registry hosting + transition→Message bridge (BACK-03, BACK-04)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 27-08-PLAN.md — CLI notify v2 + wrap mode + SendMessage + doctor tmux>=3.2 WARN (BACK-03, BACK-05)

**Notes:** Lands the milestone's infrastructure seams first, as observe-only no-ops: `internal/notifyv2` is a NEW leaf package (deliberate deviation from the spec's literal `modules/notify` placement — that creates an import cycle; documented here per research), the `shell.Runner` streaming extension, and the pass-through `GatedRunner` decorator injected at the two composition roots (flips to enforcing in Phase 30). Research: standard patterns, no research-phase needed.

### Phase 28: Device Enrollment v2 & Tailnet Content Delivery

**Goal**: The phone is an enrolled, individually revocable device that fetches real notification content over the tailnet only — opaque wake, fail-closed content store, honest delivery receipts
**Depends on**: Phase 27
**Requirements**: DEVC-01, DEVC-02, DEVC-03, DEVC-04, BACK-06, BACK-07, BACK-08
**Success Criteria** (what must be TRUE):

  1. `abysslink enroll phone` registers a per-device push token, per-device bearer credential, and a revocable SSH certificate minted by an in-process CA; re-enrolling rotates all of them cleanly; the enrollment record is cert-ready (mTLS upgrade path without schema break)
  2. `abysslink panic` atomically revokes every device credential — push token, bearer, SSH cert — as a tracked panic step
  3. Tapping a notification fetches the real body from `GET /content/:token` over the tailnet using the per-device bearer; an unauthenticated or off-tailnet request gets nothing, tokens are single-purpose and TTL'd, and the listener fails closed on any non-tailnet bind address (metrics-server bind floor reused)
  4. With the phone off the tailnet at fetch time, the wake still renders an actionable non-empty fallback title with zero network access — never an empty notification (zero-network render test)
  5. `abysslink status` reports wake-sent vs ack-received separately; phone acks (`POST /ack`) land in the audit chain as hash-only receipts; a missed ack never triggers an automatic re-wake; stale devices are flagged via `last_seen` reconciliation

**Plans**: Built 2026-06-11 outside the GSD plan loop (Fable multi-agent: `internal/device` foundation → daemon content-store/ack/listener + CLI device surface, parallel). Bearer chosen over mTLS for v4 (record kept cert-ready). All 5 success criteria met; see `28-SUMMARY.md`. Status: **COMPLETE**.

**Notes:** Enrollment plans execute before content-store plans within this phase — the store's auth gate consumes enrollment-minted credentials (credential-less-then-retrofit is the named failure mode). Confirm bearer-vs-mTLS (SPEC §14 Q2; research recommends bearer for v4) at phase planning. Research: standard patterns (extends existing enroll/panic seams + metrics-server template).

### Phase 28.1: Device SSH CA sshd Integration

**Goal**: The device SSH CA minted in Phase 28 is actually enforced by sshd — minted device certs are trusted automatically (no manual copy-paste) and revoked serials are rejected at the server — closing the two loose threads Phase 28 left: `TrustedUserCAKeys` wiring and the dead-code `RevokedSerials()` path
**Depends on**: Phase 28 (consumes `Store.CAPublicKey` and `Store.RevokedSerials()`; extends the hardened sshd drop-in from `internal/modules/ssh`)
**Requirements**: DEVC-05, DEVC-06
**Success Criteria** (what must be TRUE):

  1. After `abysslink up --apply`, the hardened sshd drop-in references `TrustedUserCAKeys` pointing at an audit-written managed file containing the device CA public key (`Store.CAPublicKey`); a freshly enrolled device's certificate authenticates to sshd with no manual operator step
  2. The hardened drop-in references `RevokedKeys` pointing at an audit-written OpenSSH KRL built from `Store.RevokedSerials()` via `ssh-keygen -k` (invoked through `shell.Runner`, never raw `os/exec`); after `abysslink panic`/`revoke`/`rotate` and the next reconcile, sshd rejects the revoked certificate serial(s)
  3. Both files install through the existing `ssh.Apply → installHardenedSSHD` reconcile path: `--dry-run` is the default and prints the intended writes without mutating, `--apply` is required to mutate, every write goes through `internal/audit`, and `sshd -t` validates the staged config before the sudo install
  4. The immutable hardened directives (`PasswordAuthentication no`, `PermitRootLogin no`, forwarding off, etc.) are unchanged — the CA/KRL directives are additive only; an empty revocation set produces a valid empty KRL (no certs accidentally trusted, none accidentally rejected)
  5. `abysslink doctor` gains a check that the trusted-CA file and KRL on disk match the current device store state (drift between enrolled/revoked devices and the installed sshd files is reported)

**Plans**: 2 plans (Wave 1: seam + CA/KRL generation/install; Wave 2: doctor drift check + idempotency gate)

Plans:
**Wave 1**

- [x] 28.1-01-PLAN.md — CAProvider seam (composition-root injection) + ssh-keygen -k KRL generation/staging + additive TrustedUserCAKeys/RevokedKeys directives + ordered CA/KRL install in installHardenedSSHD (DEVC-05, DEVC-06)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 28.1-02-PLAN.md — doctor CA/KRL drift check (success criterion 5) wired into collectDoctorFindings + findingFix + end-to-end no-churn idempotency gate (make lint test) (DEVC-05, DEVC-06)

**Notes:** Scope is two coupled pieces: (A) auto-trust (`TrustedUserCAKeys`) and (B) revocation enforcement (KRL + `RevokedKeys`) — B is meaningless without A. KRL generation needs `ssh-keygen -k` with a serial-spec; it lives in `internal/modules/ssh` (which holds the `shell.Runner`), reading serials from the device `Store` — the `device` package itself must not shell out. Follows the existing `installHardenedSSHD` staging convention (stage to `~/.config/abysslink/generated/`, `audit.WriteFile`, validate, sudo `install`). Immutable-default rule: never weaken the hardened sshd config; additive directives only.

### Phase 28.2: One-Scan Tailnet Credential Pull

**Goal**: A freshly enrolled phone receives its entire credential bundle by scanning ONE small QR — a short single-use capability URL it fetches over the tailnet — instead of the operator hand-copying an SSH key, certificate, and two tokens (or scanning four oversized per-credential QRs). Closes the "huge per-credential QRs can't fit the terminal" UX gap from Phase 28.1 while preserving every Phase-28 content-store security property.
**Depends on**: Phase 28 (reuses the BACK-06 tailnet content store, its single-use token model, TLS/MagicDNS bind, and the device `Store` bundle), Phase 28.1 (built on merged `enroll --qr`)
**Requirements**: BACK-09, DEVC-07
**Success Criteria** (what must be TRUE):

  1. The daemon content server serves a NEW bearer-less bootstrap route `GET /enroll/{token}` that returns a staged credential bundle as JSON exactly once: the high-entropy single-use token in the URL path is the ONLY credential required (no device bearer — none exists at first contact), the entry is consumed on first successful fetch, and a second fetch or a fetch after the short TTL returns the same uniform 404 as a bad token (no oracle, constant-work lookup)
  2. Bootstrap entries are a distinct capability class from BACK-06 content entries: a `/content/{token}` request can never serve a bootstrap (bundle) entry bearer-less, and a `/enroll/{token}` request can never serve a content (message-body) entry — kind is validated BEFORE the single-use consume, so a cross-class probe returns 404 without burning a live token
  3. `abysslink enroll phone --apply` stages the freshly minted bundle into the running daemon over the LOCAL unix socket (`POST /enroll/stage`, never the network mux; bundle travels in the request body, never on argv) and prints ONE short capability-URL QR that fits a standard 80-column terminal; the one-time secret box still prints as the source of truth
  4. Graceful degradation: when the daemon is not running / the content listener is disabled / staging fails, enroll prints a clear notice and falls back to the secret box plus, if `--qr` is set, the per-credential QRs — it never blocks enrollment, never errors out, and never silently drops the secrets
  5. Security defaults hold: the content listener stays tailnet-only TLS (fails closed off-tailnet), the bootstrap TTL is short and separate from the content TTL, the staged bundle is transient daemon memory (exempt from the audit-mutation rule like the BACK-06 store, never written to disk), the bundle never appears in any log, and the capability URL is shown once as a QR and never persisted; `make lint test` green with new tests covering the single-use consume, the cross-class 404-without-consume, TTL expiry, the unix-socket staging round-trip, and the daemon-unreachable fallback

**Plans**: 3 plans (3 waves — strict dependency chain: store+route → staging+config → enroll UX)

Plans:
**Wave 1**

- [x] 28.2-01-PLAN.md — BACK-09 store layer: `kind` discriminator + `mintBootstrap`/`lookupKind` (kind-checked-before-consume) + bearer-LESS `GET /enroll/{token}` route (BACK-09)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 28.2-02-PLAN.md — BACK-09 staging seam: local `POST /enroll/stage` unix route + `Client.Stage` RPC + separate `content_store.enroll_ttl_seconds` (300/30/900) config (BACK-09)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 28.2-03-PLAN.md — DEVC-07 enroll UX: pull-is-default stage + ONE capability-URL QR + always-print secret box + graceful degradation; shared `deviceBundleRecord` constructor (no wire drift) (DEVC-07)

**Notes:** The bootstrap endpoint deliberately bypasses the per-device bearer because the phone has no credentials yet at first contact — the security model rests instead on (a) ≥128-bit single-use token entropy, (b) consume-on-first-success, (c) a short separate TTL, (d) tailnet-only bind (the phone must already be on the tailnet to reach it), and (e) the capability URL traveling only operator-screen → operator-phone-camera via QR. The secret box still prints because one-time secrets are shown once regardless; the pull is a typing-convenience, not a confidentiality upgrade (documented explicitly). Reuses the BACK-06 `contentStore` (tag entries with a kind), `mintFetchRef`'s advertise-host/port resolution, and the existing daemon unix-socket client in `internal/cli`. Out of scope: any mobile app (the "phone" is curl/Shortcuts/Tasker/any tailnet HTTP client — we expose the endpoint + document the contract), fleet/multi-device pull, and persisting staged bundles across daemon restart.

### Phase 29: Push Gateway & Outbox

**Goal**: The rig wakes the phone reliably — sovereign UnifiedPush/ntfy path shipped working end-to-end on real hardware, APNs/FCM legs built interface-complete but honestly flagged experimental until the v5 app ships a receiver
**Depends on**: Phases 27, 28 (full wake → fetch → ack loop)
**Requirements**: PUSH-01, PUSH-02, PUSH-03, PUSH-04, PUSH-05, PUSH-06
**Success Criteria** (what must be TRUE):

  1. On a real de-Googled Android device with screen off and Doze active, the full opaque-wake → tailnet-fetch loop works via UnifiedPush over the existing ntfy module — no Google or Apple dependency
  2. Push delivery survives daemon restarts: persistent bbolt outbox with exponential backoff, duplicate suppression by msg_id, dead-token pruning on APNs 410 / FCM UNREGISTERED, and a per-device wakes-per-hour ceiling
  3. Concurrent approval requests arrive as separate notifications, never collapsed into one (per-kind collapse policy; collapse-id never the bare session_id)
  4. APNs (.p8 from keychain, alert priority 10 + mutable-content) and FCM (data message, priority high) legs pass httptest-backed coverage and are documented **experimental**; the Gateway interface structurally has no silent-push type
  5. `abysslink doctor` covers the new push surfaces: gateway creds readable from daemon context (launchd / headless systemd), content-store bind floor, stale device tokens, and the ntfy.sh iOS relay honesty warning in both directions

**Plans**: 5 plans

Plans:
**Wave 1**

- [x] 29-01-PLAN.md — internal/push package scaffold: Gateway interface, Wake struct, CollapseID, Outbox (bbolt), CredsSource, backoff/dedup/ceiling — PUSH-01, PUSH-05

**Wave 2** *(blocked on Wave 1)*

- [x] 29-02-PLAN.md — UnifiedPush sovereign leg (APNs httptest-backed experimental) — PUSH-02, PUSH-03
- [x] 29-03-PLAN.md — FCM raw HTTP v1 leg (httptest-backed, experimental) — PUSH-04

**Wave 3** *(blocked on Wave 2)*

- [x] 29-04-PLAN.md — Config schema + daemon wiring: bbolt open, dispatch fan-out, outbox retry goroutine, /status gateway counters — PUSH-01..05

**Wave 4** *(blocked on Wave 3)*

- [x] 29-05-PLAN.md — Doctor push checks (10 checks) + integration test scaffold + real-device runbook — PUSH-06

**Notes:** DEEP RESEARCH FLAG — three decision gates resolved in writing at phase start: (a) APNs relay-vs-sideload (SPEC §14 Q1, product decision, reconciled with the no-proprietary-cloud brand), (b) FCM SDK vs raw HTTP v1 (measure binary delta; swap if > ~3 MB — Gateway interface keeps the swap invisible), (c) daemon-keychain access spike per platform × session type (may force a documented `creds_source: file` 0600 fallback). The bbolt outbox file is daemon runtime state — explicitly documented as exempt from the audit-mutation rule. Apple Developer paperwork (started at milestone start, parallel track) feeds the APNs leg here but never blocks this phase: UnifiedPush/ntfy is the shipping path.

### Phase 30: Phone Approve Loop

**Goal**: The user approves or denies gated actions from the phone with signed, single-use, action-hash-bound requests — approval can never weaken dry-run, never auto-resolve, and never be spoofed between approval and execution
**Depends on**: Phases 27, 28 (transport rides ntfy action buttons + tailnet content/ack — deliberately NOT blocked by Phase 29)
**Requirements**: APPR-01, APPR-02, APPR-03, APPR-04, APPR-05, APPR-06
**Success Criteria** (what must be TRUE):

  1. A gated command blocks until the user answers on the phone (ntfy action buttons / Pushcut / Tasker today); resolution is compare-and-swap once-only — first answer wins, the deny-then-late-approve race is rejected, daemon restart with pending requests resolves to deny, timeout falls back to the terminal prompt, and no timeout/error/restart path ever resolves to approve
  2. The approved action is bound to the execution-closure hash (argv + cwd + resolved binary + script content) and re-verified at exec time — anything swapped between approval and execution is refused (TOCTOU structurally closed)
  3. Bridge taps via single-use 256-bit capability URLs can never approve panic-revoke, kill-switch disarm, or destructive `--apply` — the tier policy is enforced in code, not docs
  4. Every approve/deny decision is audit-chained as request-ID + action hash (never caller free-text); the `GatedRunner` flips from observe-only to enforcing with daemon-internal commands bypassing the gate (self-deadlock rule); phone approval is an alternative satisfier of the existing `--apply` confirm gate, never a weakener of dry-run default
  5. Claude Code permission prompts route through the loop via the PermissionRequest hook — quarantined in the claudecode module, zero Claude coupling in approve/notify/gate

**Plans**: 5 plans

Plans:
**Wave 1** *(parallel)*

- [x] 30-01-PLAN.md — internal/approve leaf package: CAS registry, HMAC signing, tier constants (APPR-01, APPR-02, APPR-03, APPR-04)
- [x] 30-02-PLAN.md — daemon approve extensions: kindApprove/kindDeny, handleApprove/handleDeny, unix-socket IPC, /status counters (APPR-02, APPR-03, APPR-04)

**Wave 2** *(blocked on Wave 1)*

- [x] 30-03-PLAN.md — gate.go enforcing flip + notifyv2 Actions[] un-drop + ntfy X-Actions header (APPR-01, APPR-05)

**Wave 3** *(blocked on Wave 2)*

- [x] 30-04-PLAN.md — config YAML keys + claudecode hook writers + abysslink approve CLI subcommand (APPR-05, APPR-06)

**Wave 4** *(blocked on Wave 3)*

- [x] 30-05-PLAN.md — AST coupling tests + make lint test integration gate (APPR-05, APPR-06)

**Notes:** DEEP RESEARCH FLAG — TOCTOU closure-hashing design, CAS resolution semantics, capability-URL tier policy, and upstream Claude hook bugs (#12176, #19298) resolved in 30-RESEARCH.md. Demoable even if Phase 29 slips (rides existing ntfy).

### Phase 31: Agent Kill-Switch ("Apoptosis")

**Goal**: A runaway agent is observed, frozen, and — only on explicit opt-in — killed, with a rollback offer and a phone buzz; the launch headline, riding existing ntfy so it cannot slip on push-platform timelines
**Depends on**: Phases 27 (GatedRunner command stream + registry kill targeting), 30 (resume-with-approval) — deliberately NOT Phase 29
**Requirements**: KILL-01, KILL-02, KILL-03, KILL-04, KILL-05
**Success Criteria** (what must be TRUE):

  1. An armed agent run that exceeds a wall-clock limit, iteration/loop cap (repeated identical commands via the GatedRunner stream), or optional estimated token-spend tier (local JSONL) — all thresholds in `abysslink.yaml` — triggers the escalation ladder notify → SIGSTOP-then-ask → kill; shadow mode (observe + notify only) is the shipped default and hard kill is explicit opt-in
  2. A SIGSTOPped agent can be resumed from the phone via the approve loop
  3. Kill terminates the whole process group (pgid plumbed at spawn through shell.Runner) — never `tmux kill-pane`
  4. On stop/kill the user gets an `agent_stopped` notification with reason, an audit-position rollback offer, and the arm-time git snapshot reference; all copy says "freezes the agent and shows you the damage" — never claims to undo agent work or report dollar-precise savings
  5. The armed run is recorded via the existing asciinema module and the cast file's sha256 is bound into the audit chain entry for that run

**Plans**: TBD

### Phase 32: Supply-Chain Depth & Trimmed Fortify

**Goal**: The release pipeline reaches SLSA L3 with Scorecard/SBOM/VEX depth, doctor enforces external version floors, the cheap MED gaps close, and the at-risk profile + dead-man switch ship — all strictly before any new distribution channel exists
**Depends on**: Phase 26 baseline (CI/pipeline track — parallelizable with Phases 27–31, but MUST complete before Phase 33)
**Requirements**: SUPL-01, SUPL-02, SUPL-03, SUPL-04, SUPL-05, SUPL-06
**Success Criteria** (what must be TRUE):

  1. Tagged releases carry SLSA v1 Build L3 attestations (build moved into a reusable workflow + `actions/attest`), a post-release `slsa-verifier` CI gate passes, and a single `VERIFYING.md` contract is implemented by `abysslink verify`/`upgrade` — one verification story, not three
  2. OpenSSF Scorecard runs in CI (badge added only if score ≥ ~8; structurally-low checks documented in SECURITY.md; score never cited in launch copy); Syft/Grype scans the existing SBOMs with pipeline-generated OpenVEX (govulncheck-derived; hand-written statements carry expiry)
  3. `abysslink doctor` enforces the extended external version floors: NetBird ≥ 0.57.0, Tailscale ≥ 1.98.1 (+ statedir-when-locked), EternalTerminal ≥ 6.2.0 (prefer-mosh), OpenSSH ≥ 10.0 PQ-KEX
  4. The cheap MED gaps are closed: timeouts on every backend REST client (B4), symlink-TOCTOU guard on audit write/backup paths (B5), ntfy topic entropy ≥ 128 bits (B9), child-process env minimization in shell.Runner (B10)
  5. `doctor --profile at-risk` runs the strict-profile check set, and the configurable dead-man-switch timer auto-revokes agent autonomy and locks down after the no-contact interval

**Plans**: TBD

**Notes:** DEEP RESEARCH FLAG — the SLSA L3 reusable-workflow migration interacts with the existing cosign v3 / goreleaser pipeline in fiddly ways (checksum config, tag immutability); verify against current goreleaser v2.16 docs at planning time. Ordering is load-bearing: attest first, then Phase 33 builds brew/AUR on top of attested artifacts — reversing it ships unverifiable channels.

### Phase 33: Distribution & Public Launch

**Goal**: Abysslink is installable via Homebrew and AUR pinned back to attested artifacts, and the public launch executes as a tested artifact — three blocking gates pass before the Show HN goes live
**Depends on**: Phase 32 (attested artifacts — strict) + Phases 27–31 (kill-switch demo + approve loop + sovereign push are the launch story); LNCH-02, LNCH-04, LNCH-05 gate LNCH-06 execution
**Requirements**: LNCH-01, LNCH-02, LNCH-03, LNCH-04, LNCH-05, LNCH-06
**Success Criteria** (what must be TRUE):

  1. `brew install` via the goreleaser `homebrew_casks` tap (Gatekeeper handled) and an AUR install both work on clean machines and pin back to Phase 32-attested artifacts
  2. An outsider completes the quickstart in under 10 minutes on fresh macOS and Ubuntu VMs (fire-drill — BLOCKING GATE for LNCH-06)
  3. The claims audit passes: every security sentence in README/docs maps to a code or doctor-check pointer; the who-sees-what table per push path (UnifiedPush sovereign / FCM / ntfy.sh-relayed iOS) is published; the "how this is built" AI-story note is live (BLOCKING GATE for LNCH-06)
  4. The full opaque-wake → tailnet-fetch → ack loop passes on a physical phone with the screen off before launch (BLOCKING GATE for LNCH-06)
  5. README hero + 30-sec split-screen demo (phone buzz → tap → exact session → approve) + WHY-ABYSSLINK.md (naming Moshi / Claude Code Channels / claude-push / ntfy honestly) + docs site are live, and the launch executes: Show HN Tue–Thu morning ET with the kill-switch demo as headline and a 48h founder-response plan, plus Lobsters and r/selfhosted / r/ClaudeAI / r/commandline / r/golang; GitHub Sponsors enabled quietly; friendly company-interest capture on the docs site (never "Enterprise — contact us")

**Plans**: TBD

**Notes:** Apple Developer account paperwork (enrollment, Developer ID signing for Gatekeeper, .p8 for the experimental APNs leg) starts in parallel at milestone start and is consumed here and in Phase 29 — it never blocks the critical path; the quarantine-hook fallback covers the cask if signing lags. Launch is a tested artifact with its own acceptance criteria, not marketing executed after engineering: gates 2–4 above decide the launch date.

### Phase 34: TUI Foundation

**Goal**: Establish the Abyss two-tone visual identity and the Printer/huh IO boundary as the single, tested foundation every later TUI step consumes — before any wizard flow exists — so theme drift, NO_COLOR crashes, and a silently-broken static binary are caught here
**Depends on**: Phase 33 (v4.0.0 complete — first phase of v4.1.0)
**Requirements**: TUI-01, TUI-02, TUI-08
**Success Criteria** (what must be TRUE):

  1. Every form/title/selection rendered through the new theme shows the Abyss identity — cyan accent/nav/titles, violet active selection, steel muted — sourced from one `internal/ui/theme.go` (the only place colors are defined), with huh field names verified against the pinned `huh v1.0.0` (not guessed)
  2. The two-tone slant banner ("ABYSS" cyan / "LINK" violet) renders inside a rounded border on a truecolor terminal and degrades to readable plain/dim output under `NO_COLOR`, a non-truecolor `$TERM`, or a dumb terminal — and never crashes in any of those modes
  3. The Printer/huh IO boundary is in place: live huh `.Run()` is gated behind `interactive()` and isolated so deterministic output still flows through `internal/cli.Printer`; existing `--json`/non-TTY output stays byte-stable (no regression)
  4. A `CGO_ENABLED=0` cross-build CI check compiles the binary for all four targets (darwin/amd64, darwin/arm64, linux/amd64, linux/arm64) and fails the build if a TUI dependency pulls in cgo

**Plans**: 4 plans
**Wave 1**

- [ ] 34-01-PLAN.md — internal/ui package: Abyss palette + AbyssTheme() *huh.Theme + single-source-of-color guard (Wave 1)
- [ ] 34-02-PLAN.md — byte-stability goldens for status/doctor/header/livetable, captured BEFORE migration (Wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 34-03-PLAN.md — full color consolidation: re-source cli/tui from internal/ui, byte-identical; remove dead tui styles (Wave 2)
- [ ] 34-04-PLAN.md — two-tone slant banner (go-figure, never-crash tiers) + four-target CGO_ENABLED=0 CI guard (Wave 2)

**UI hint**: yes

### Phase 35: Browser Hand-off & Wizard Flow

**Goal**: Replace the v1 journey + 8-stage `init` wizard with a composable, on-brand guided flow built on the Phase 34 theme — one typed `FlowState`, no globals — and add a paranoid-by-default browser hand-off (fire-and-forget plus an RFC 8252 loopback OAuth callback) so the new `init` is the complete, demo-ready surface
**Depends on**: Phase 34 (consumes the theme, banner, and IO boundary)
**Requirements**: TUI-03, TUI-04, TUI-05, TUI-06, TUI-07, BRWS-01, BRWS-02, BRWS-03
**Success Criteria** (what must be TRUE):

  1. `abysslink init` runs end-to-end on the new flow layer (`internal/flow/` composable steps returning `*huh.Form`/`*huh.Group`, threading one `FlowState`); `internal/cli/journey.go` no longer exists; wizard logic has moved out of `cmd_init.go` into a thin command + steps
  2. Headless `--yes`/`--json`/non-TTY `init` paths stay non-blocking and byte-stable (no live form ever blocks CI), and results/help/markdown render through glamour to a string emitted via `Printer` (ANSI auto-stripped under `--json`) — no raw `fmt.Println`
  3. A browser hand-off step opens a URL through the existing `shell.Runner` openURL/`shell.LookPath` opener (not `pkg/browser`'s `os/exec`) and a huh confirm resumes the flow when the user returns
  4. The OAuth/callback step runs a loopback server on `127.0.0.1` + an ephemeral random free port, validates `state`/`nonce` + PKCE before accepting, honors a `context` timeout and ctrl-c cancellation, shuts the server down after the callback, and returns the auth code into `FlowState`; the listener can never bind a non-loopback address (rejected at the config schema level — no YAML knob exposes it)
  5. Async/browser-wait steps show a cyan huh spinner inside a bordered padded container with the persistent steel footer hint; a hidden `gallery` / `--theme-preview` command renders the sample group under the Abyss theme without running the full flow

**Plans**: TBD
**UI hint**: yes

### Phase 36: Secure Memory & Audit HMAC-Key Rotation

**Goal**: Land the foundational in-memory secret handling (mlock/zeroize) and then the single highest-risk security item of the milestone — versioned audit-chain HMAC-key rotation that never flags pre-rotation history as TAMPERED
**Depends on**: Phase 33 (security track; independent of the TUI thread — but `SecureBytes` must precede rotation, so they ship together)
**Requirements**: MEM-01, MEM-02, ROT-01, ROT-02, ROT-03
**Success Criteria** (what must be TRUE):

  1. A `SecureBytes` type (memguard-backed, pure-Go) in `internal/secrets` holds in-memory secrets mlock'd + zeroized on free; when `RLIMIT_MEMLOCK` prevents locking it surfaces an honest WARN (never a silent no-op), and it is framed as defense-in-depth with no "never hits disk" claim; the audit HMAC key is cached as `SecureBytes` in `internal/audit/signed.go`
  2. After `abysslink rotate audit-hmac --apply`, the audit chain contains an in-chain rotation marker signed by the OLD key, a new key is generated and stored in the keychain, the chain is re-anchored, and old keys are retained (never deleted); the rotation secret is printed once and never stored
  3. Verifying a chain that spans multiple key epochs selects the key by per-entry epoch/key-ID and reports every pre-rotation entry as VALID — no false TAMPERED — proven by a multi-epoch regression test
  4. `sec-` doctor checks report mlock availability and the current key epoch + rotation health

**Plans**: TBD

**Notes:** DEEP RESEARCH FLAG — the audit chain has no key-ID field today, so naive rotation flags ALL history TAMPERED. Detailed epoch design (versioned key epochs, in-chain marker signed by the old key, per-entry key selection on verify, never delete old keys) plus multi-epoch regression tests must be resolved in writing at phase planning. `SecureBytes` is best-effort (Go GC moves buffers) — defense-in-depth framing only, no hard guarantee.

### Phase 37: Hardware-Backed Keys & Local Attestation

**Goal**: Add genuine hardware-backed key support (macOS Secure Enclave default, FIDO2 opt-in) and local boot/device attestation — all cgo-free shell-out through `shell.Runner`, all fail-closed — building on the Phase 36 secure secret handling
**Depends on**: Phase 36 (consumes `SecureBytes`/secure handling and the `sec-` doctor pattern)
**Requirements**: HWK-01, HWK-02, HWK-03, HWK-04, ATT-01, ATT-02
**Success Criteria** (what must be TRUE):

  1. A `HardwareKeyProvider` interface sits beside `KeychainStore`; the macOS Secure Enclave provider creates a non-exportable key via cgo-free shell-out (`ssh-keygen -w`/`sc_auth`) and the FIDO2 opt-in provider uses `ssh-keygen -t ed25519-sk` (OpenSSH ≥10 floor) — both routed through `shell.Runner`, no cgo, no `os/exec` bypass
  2. Hardware-key use fails closed — it never silently falls back to a software key; the active key kind is surfaced in `abysslink status` and a `sec-` doctor check
  3. `abysslink enroll` offers the hardware-key option inside the new flow (Phase 35)
  4. `internal/attest` reads local boot state only — macOS `csrutil`/SIP, Linux SecureBoot EFI var + TPM PCR via `tpm2_quote` (or `go-tpm`) — through `shell.Runner`, with no network and no SaaS verifier
  5. Attestation is fail-closed tri-state (tool missing/error ⇒ WARN, never false-OK) and surfaced in `doctor` + `--profile at-risk`

**Plans**: TBD

**Notes:** DEEP RESEARCH FLAG — `CGO_ENABLED=0` disqualifies every in-process FIDO2/PIV/Secure-Enclave binding (go-libfido2, sks, go-piv all need cgo); confirm the cgo-free per-platform shell-out path (`ssh-keygen -t ed25519-sk`, Secure-Enclave CLI, `csrutil`/`tpm2_quote`) at planning. Platform attestation + Secure-Enclave behavioral claims are pending real-hardware confirmation — fixture-driven + fail-closed until verified. Attestation is local-only by floor; the cloud/remote verifier is out of scope (no-SaaS/no-telemetry).

### Phase 38: Backlog Closure & Doctor Coverage

**Goal**: Clear the deferred MED backlog (B1/B2/B8) and guarantee the immutable guide rule for the whole milestone — every new v4.1 footgun has a paired `sec-` doctor check wired into `--profile at-risk` — as the independent, low-cost track
**Depends on**: Phase 33 (largely independent; sequenced after the security providers so the new footgun checks can reference them, but the B-item fixes themselves stand alone)
**Requirements**: BKLG-01, BKLG-02, BKLG-03, BKLG-04
**Success Criteria** (what must be TRUE):

  1. B1 — the Tailnet Lock WARN becomes a hard gate (no longer silently skippable), with an explicit override flag to consciously bypass it
  2. B2 — FileVault mid-encryption detection (`fdesetup`/`diskutil` string literals) fails closed; the real-hardware string-literal confirmation is flagged as a known gap until verified (fail-closed regardless)
  3. B8 — per-rig fleet HMAC framing is domain-separated so cross-rig audit entries cannot be confused or replayed across rigs
  4. Every new v4.1 footgun (decoy, hardware keys, attestation, rotation, mlock) has a paired `sec-` doctor check wired into `--profile at-risk`, and the at-risk profile tightens the new items to FATAL

**Plans**: TBD

**Notes:** DEEP RESEARCH FLAG (B2 only) — the FileVault mid-encryption `fdesetup`/`diskutil` string literals need real-hardware confirmation; until then the check is fixture-driven and fails closed. This phase carries the immutable guide rule (a `doctor` check for EVERY footgun) for the whole milestone, so it is sequenced after the Phase 36/37 security features land their footguns.

### Phase 39: Duress/Decoy & Post-Launch Polish

**Goal**: Ship the one cross-thread security feature — a non-destructive duress/decoy config that needs both the new flow (Phase 35) and the security providers/panic wiring — and fold in post-launch hardening and polish driven by real v4.0.0 launch feedback, holding every floor at milestone close
**Depends on**: Phase 35 (new flow), Phase 36/37 (security providers), Phase 38 (the paired-doctor-check rule + at-risk profile)
**Requirements**: DUR-01, DUR-02, DUR-03, POL-01, POL-02, POL-03
**Success Criteria** (what must be TRUE):

  1. An alternate (decoy) credential unlocks a benign rig view that hides the real fleet/session state; credential comparison is constant-time; no destructive wipe path exists anywhere
  2. The decoy is paired with the existing panic/kill-switch so degradation is real (not cosmetic), and a decoy-vs-real indistinguishability check guards against trivial detection; duress activation is audit-logged without leaking which credential was used
  3. Honest threat-model copy ships in docs + `doctor` — framed as the casual-coercion model, explicitly NOT forensic plausible-deniability
  4. An onboarding-friction pass keeps quickstart < 10 min for a fresh install, re-measured against the new TUI `init`; doctor-coverage gaps surfaced by the first real v4.0.0 installs are closed
  5. No-telemetry and no-scope-creep are held — polish only, with no new always-on network surface introduced

**Plans**: TBD

**Notes:** DEEP RESEARCH FLAG — the duress threat model (casual-coercion, NOT forensic plausible-deniability) must be designed in writing at phase planning; destructive duress wipe is DROPPED (security theater + self-DoS + detectable) — non-destructive decoy only. This is the milestone's only cross-thread join: it cannot start until the new flow AND the security providers exist. POL-02 specifics are captured from launch feedback at planning time.

---

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → … → 27 → 28 → 28.1 → 29 → 30 → 31 → 32 → 33 → 34 → 35 → 36 → 37 → 38 → 39. v4.1.0 (34–39): the TUI thread (34 → 35) and the security thread (36 → 37) are independent and parallelizable; Phase 38 (backlog closure) is largely independent but sequenced after 36/37 so the new-footgun doctor checks can reference the new features; Phase 39 (duress/decoy + polish) is the cross-thread join and must come last (it needs the new flow from 35 AND the security providers from 36/37).

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Repo Bootstrap | 3/3 | Complete | 2026-05-26 |
| 2. Core CLI Scaffold | 3/3 | Complete | 2026-05-26 |
| 3. Platform Abstraction | 3/3 | Complete | 2026-05-26 |
| 4. Tailscale Integration | 3/3 | Complete | 2026-05-26 |
| 5. Module System & Core Modules | 4/4 | Complete | 2026-05-26 |
| 6. Top-Level Commands | 3/3 | Complete | 2026-05-26 |
| 7. Optional Modules | 2/2 | Complete | 2026-05-26 |
| 8. Release Infrastructure | 3/3 | Complete | 2026-05-26 |
| 9. Verification & Polish | 3/3 | Complete | 2026-05-26 |
| 10. Journey & Rich TUI | 6/6 | Complete | 2026-05-29 |
| 11. Backend Abstraction Refactor | 3/3 | Complete    | 2026-05-31 |
| 12. Headscale Backend | 5/5 | Complete    | 2026-05-31 |
| 13. NetBird Backend | 5/5 | Complete   | 2026-06-01 |
| 14. Multi-Rig Fleet | 5/5 | Complete    | 2026-06-01 |
| 16. Supply-Chain Hardening & CI Gates | 4/4 | Complete    | 2026-06-02 |
| 17. Tamper-Evident Audit Log + Fuzzing | 3/3 | Complete    | 2026-06-02 |
| 18. Observability & Metrics | 4/4 | Complete    | 2026-06-02 |
| 19. Web UI Dashboard (opt-in) | 4/4 | Complete    | 2026-06-02 |
| 20. Security Audit Pass & Doctor Checks | 4/4 | Complete    | 2026-06-02 |
| 21. Optional Modules & Fleet Polish | 5/5 | Complete    | 2026-06-02 |
| 22. Network & Dependency Lockdown | 4/4 | Complete    | 2026-06-03 |
| 23. Doctor Honesty & Coverage | 4/4 | Complete   | 2026-06-03 |
| 23.1 Doctor Probe-Failure Honesty (INSERTED) | 4/4 | Complete | 2026-06-04 |
| 23.2 Doctor Probe-Failure Honesty round 2 (INSERTED) | 2/2 | Complete | 2026-06-04 |
| 24. v3.0.1 Security Closeout | 7/7 | Complete | 2026-06-04 |
| 25. Close v3.0.1 Debt | 5/5 | Complete | 2026-06-04 |
| 26. Init Journey Gating & First-Run Fixes | 3/3 | Complete | 2026-06-04 |
| 27. Session-Aware Notification Backbone | 9/9 | Complete   | 2026-06-10 |
| 28. Device Enrollment v2 & Tailnet Content Delivery | n/a (Fable build) | Complete | 2026-06-11 |
| 28.1 Device SSH CA sshd Integration | 2/2 | Complete   | 2026-06-14 |
| 29. Push Gateway & Outbox | 5/5 | Complete    | 2026-06-15 |
| 30. Phone Approve Loop | 5/5 | Complete    | 2026-06-17 |
| 31. Agent Kill-Switch ("Apoptosis") | 5/5 | Complete | 2026-06-18 |
| 32. Supply-Chain Depth & Trimmed Fortify | 7/7 | Complete (release-proofs at v4 tag) | 2026-06-20 |
| 33. Distribution & Public Launch | 3/3 | Complete (human-gated: LNCH-02/04/05/06 operator) | 2026-06-21 |
| 34. TUI Foundation | 0/? | Not started | - |
| 35. Browser Hand-off & Wizard Flow | 0/? | Not started | - |
| 36. Secure Memory & Audit HMAC-Key Rotation | 0/? | Not started | - |
| 37. Hardware-Backed Keys & Local Attestation | 0/? | Not started | - |
| 38. Backlog Closure & Doctor Coverage | 0/? | Not started | - |
| 39. Duress/Decoy & Post-Launch Polish | 0/? | Not started | - |

### Phase 23.1: Doctor probe-failure honesty — no false-OK on unknown or failed probes and no double-emit (INSERTED)

**Goal:** Close the four deferred honesty WARNINGs from the Phase 23 code review (23-REVIEW.md). A doctor/threat-model check must never render a green ✓ for a control it could not actually confirm: probe failures and unresolvable backend state must surface as a distinct unknown/warning, not OK; the ntfy bind check must catch IPv6 wildcards; and report-only OK findings must be emitted exactly once (no Detect+Verify duplication inflating the "N ok" count).
**Requirements**: DOC-05 (WR-02 funnel probe-failure false-OK), DOC-06 (WR-03 bind false-OK when tailnet IP unresolvable), DOC-07 (WR-04 ntfy IPv6 `[::]` wildcard miss), DOC-08 (WR-08 Detect+Verify double-emit dedup)
**Depends on:** Phase 23
**Success Criteria** (what must be TRUE):

  1. `funnelActive` (tailscale/module.go) distinguishes probe failure from confirmed-inactive: on exec error / non-zero exit it emits `SeverityWarning` ("could not determine Funnel state"), NOT a `SeverityOK` funnel finding; threat-model "No public exposure" row then renders `—`/`✗`, never a false ✓ (DOC-05 / WR-02)
  2. `metBindTailnetCheck` (cmd_doctor.go) emits `SeverityWarning` when `tailnetIP == ""` and a non-wildcard `bind_addr` is configured (cannot verify tailnet-scope — backend unavailable), instead of falling through to OK (DOC-06 / WR-03)
  3. ntfy `listen_address` check (ntfy/module.go) flags IPv6 wildcard binds (`[::]:PORT`, bare `::`) as non-compliant, mirroring the existing `0.0.0.0` / bare-`:PORT` detection; honors the immutable "ntfy binds tailnet IP only, never wildcard" default for externally-edited configs (DOC-07 / WR-04)
  4. Report-only `SeverityOK` findings appear exactly ONCE per `abysslink doctor` pass for lock/ssh/ntfy/acl/tailscale — either emitted in only one of Detect/Verify (hardening-module precedent) or deduped on `(Module, Check)` in `runner.Doctor`; the "N ok" count is no longer inflated and no duplicate ✓ rows render (DOC-08 / WR-08)
  5. `make lint test` green; new/updated tests cover each probe-failure → non-OK path and the single-emission/dedup guarantee

**Plans:** 5/5 plans complete

Plans:
**Wave 1** *(all plans independent — parallel execution)*

- [x] 23.1-01-PLAN.md — DOC-05 + DOC-08 (tailscale): funnelActive returns (bool, bool); probe-failure → SeverityWarning Check="funnel-probe-fail"; Verify calls only checkNoPublicExposure (no Detect delegation)
- [x] 23.1-02-PLAN.md — DOC-07 + DOC-08 (ntfy): hasWildcardListen extended for `[::]:PORT` and bare `::`; content-level `[::]` check added; ntfy Verify returns nil
- [x] 23.1-03-PLAN.md — DOC-06: metBindTailnetCheck tailnetIP="" + non-wildcard → SeverityWarning Check="met-bind-unknown"; findingFix entries for "funnel-probe-fail" and "met-bind-unknown"
- [x] 23.1-04-PLAN.md — DOC-08 (lock + ssh): lock Verify returns nil; ssh Verify returns nil; TestRunnerDoctor_NoDoubleEmit integration test (D-02)

### Phase 23.2: Doctor probe-failure honesty (round 2) — serve + metrics-listener probes must not report OK on unproven probes (INSERTED)

**Goal:** Close the two CRITICAL false-OK-on-unknown findings from the Phase 23.1 code review (23.1-REVIEW.md). The same anti-pattern fixed for `funnelActive` in 23.1 survives in two sibling probes: `serveActive` collapses a failed serve probe into "not active" (emitting no warning while the funnel ✓ already rendered), and `metDisabledListenerCheck` treats *any* dial error as proof the port is closed (reporting SeverityOK for a fail-closed security control it never actually verified). A doctor/threat-model check must never render ✓ for a control whose backing probe could not run.
**Requirements**: DOC-09 (CR-02 serveActive probe-failure false-OK), DOC-10 (CR-01 metDisabledListenerCheck false-OK on inconclusive dial error)
**Depends on:** Phase 23.1
**Source:** Phase 23.1 code review (`.planning/phases/23.1-doctor-probe-failure-honesty-no-false-ok-on-unknown-or-faile/23.1-REVIEW.md`) — CR-01, CR-02
**Success Criteria** (what must be TRUE):

  1. `serveActive` (tailscale/module.go) distinguishes serve-probe failure from confirmed-inactive: on exec error / non-zero exit, `checkNoPublicExposure` emits a distinct `serve-probe-fail` SeverityWarning ("could not determine Serve state"), NOT silence; the "No public exposure" promise never renders confirmed-clean when the serve probe could not run (DOC-09 / CR-02)
  2. `metDisabledListenerCheck` (cmd_doctor.go) returns SeverityOK only for a genuine closed port (`errors.Is(err, syscall.ECONNREFUSED)`); timeout, unreachable, and resolution-failure dial errors return a distinct `met-listener-unknown` SeverityWarning instead of falsely asserting "no stale metrics listener detected" (DOC-10 / CR-01)
  3. `findingFix` map gains human-readable remediation entries for both new check IDs (`serve-probe-fail`, `met-listener-unknown`), mirroring the 23.1 `funnel-probe-fail` / `met-bind-unknown` entries
  4. New tests cover each probe-failure → non-OK path: serve-probe exec error / non-zero exit asserts `serve-probe-fail` Warning (distinct from `funnel`); metrics probe against an unroutable address (e.g. `192.0.2.1:9` TEST-NET-1) asserts it does NOT return SeverityOK; existing closed-port-on-loopback ECONNREFUSED test still asserts SeverityOK
  5. `make lint test` green

**Plans:** 2/2 plans complete

Plans:
**Wave 1** *(both plans independent — parallel execution)*

- [x] 23.2-01-PLAN.md — DOC-09 (CR-02): serveActive returns (bool, bool); probe-failure emits SeverityWarning Check='serve-probe-fail'; findingFix entry; tests for exec-error + non-zero-exit + distinct-check-ID + serve-OK regression
- [x] 23.2-02-PLAN.md — DOC-10 (CR-01): metDisabledListenerCheck ECONNREFUSED gate; non-ECONNREFUSED errors emit SeverityWarning Check='met-listener-unknown'; findingFix entry; TestMetDisabledListener_UnroutableAddr (192.0.2.1:9) + ECONNREFUSED regression
