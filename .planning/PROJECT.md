# Abysslink

## What This Is

Abysslink is a Go CLI that automates a paranoid-by-default phone-to-laptop remote-control setup over Tailscale. One static binary for macOS and Linux. You run `abysslink up --apply` and it installs, configures, and verifies Tailscale SSH, tmux, mosh, and ntfy — then buzzes your phone whenever anything needs you. Marketed as "vibe-code Claude from your phone"; built as a generic phone-to-rig toolkit.

## Core Value

`abysslink up` — one command that produces a working, auditable, paranoid-by-default phone-to-laptop remote setup on any macOS or Linux machine.

## Current State

**Phase 26 complete (2026-06-04):** `abysslink init` is now a genuinely gated 8-stage interactive wizard — per-stage confirm gates, offer-to-run in stages 3–7 (`up --apply` / `lock init --apply` / `enroll phone` / `doctor` / new ACL stage `acl push --apply`), and three first-run bugs fixed (openURL probe → `shell.LookPath`, Stage 2 no longer duplicates RunE work with hardcoded autoYes, pmset annotated-output parsing). Gap closure 26-03 fixed the two UAT-reported interactive defects: sudo now routes through `RunInteractive` (visible prompt, tty credential-cache reuse → one password per run), power module short-circuits redundant `sudo pmset`, and `journeyOfferRun` restores terminal state before spawning children. Headless `--yes`/`--json`/non-TTY paths stay non-blocking. Verification 25/25; human UAT approved. Code review findings fixed post-review: CR-01 (sleep probe now reads the AC profile with three-state parse + exit-code check) and WR-01..05 (empty-argv guard, /dev/tty state restore, MockRunner ExitCode→error mapping). Folded into the v3.0.1 milestone close (incremental audit PASSED); commits land after the pushed `v3.0.1` tag.

**Shipped:** v3.0.1 — Network & Dependency Security Hotfix (2026-06-04). Closes every confirmed CRITICAL/HIGH finding from the 2026-06-03 full security audit across 7 phases / 29 plans (incl. post-ship Phase 26 init-journey fold-in): network/dependency lockdown (ntfy tailnet-only bind, NetBird https-only `server_url`, hostname/URL argv-injection guards, go1.26.4 + x/crypto v0.52.0 + CSRF→`net/http.CrossOriginProtection`), doctor/threat-model honesty (shared finding set, fail-closed disk encryption, nb-lock, minimum-versions table, probe-failure tri-state), tamper-evident audit hardening (HMAC-chained backups, anchor-every-append + keychain counter, cross-process flock, direction-aware verifyCounter), DoS bounding (limitio + WriteFilePath streaming), and a blocking govulncheck CI gate. 20/20 requirements verified. Audit PASSED. Local tag `v3.0.1`. Deferred: Phase 23 FileVault mid-encryption string literals (real-hardware confirmation; fail-closed regardless).

**Shipped:** v3.0.0 — Harden, Observe & Control (2026-06-03). Supply-chain hardening (cosign v3 / SLSA L2 / dual SBOM / reproducible builds), tamper-evident HMAC-chained audit log + fuzzing, opt-in tailnet-bound metrics/`GET /status`/`report`/fleet digest, opt-in `//go:build webui` Web UI dashboard (TLS/WhoIs/CSRF/CSP/read-only), security-audit pass (gosec+semgrep zero-unsuppressed, 18 sec-* doctor checks, per-backend threat model), and optional modules (WoL/atuin/sandbox/asciinema) + NetBird fleet parity. Audit PASSED (3 integration gaps closed). Local tag `v3.0.0` (not pushed). Live-env HUMAN-UAT deferred.

**Shipped:** v2.0.0 — Self-Hosted Backends & Fleet (2026-06-02). Abysslink is backend-pluggable (Tailscale / Headscale / NetBird behind one `internal/backend.Client` interface) and controls a multi-rig fleet from one phone with per-rig keychain, ntfy-topic, and ACL isolation. Audit PASSED (15/15 requirements). Tag `v2.0.0`.

- **v1.0.0** (2026-05-29): single-binary Tailscale CLI — init/up/doctor/repair/status, 11 core + 4 optional modules, rich guided TUI journey, release pipeline.
- **v2.0.0** (2026-06-02): backend abstraction + Headscale + NetBird self-hosted backends + multi-rig fleet.

Archived detail: `milestones/v2.0.0-ROADMAP.md`, `milestones/v2.0.0-REQUIREMENTS.md`, audit `v2.0.0-MILESTONE-AUDIT.md`.

## Next Milestone: v4.0.0 — Fortify (queued)

**v3.0.1 shipped 2026-06-04** (see Current State). The next milestone is v4.0.0 "Fortify" — at-risk-user threat model + MED gaps + supply-chain depth + external version floors (summary at the end of this section). Run `/gsd-new-milestone` to scope it.

<details>
<summary>Shipped milestone framing (v3.0.1 — Security Hotfix)</summary>

**Goal:** Close every confirmed CRITICAL + HIGH finding from the 2026-06-03 full security audit, fast — no new features, no security-floor regressions. Ships before v4.0.0.

**Source:** `.planning/research/SECURITY-AUDIT.md` (11-agent audit + govulncheck/gosec/semgrep + internet CVE research). Confirmed CRITICAL/HIGH findings A1–A12 only; MED gaps, at-risk features, and supply-chain depth deferred to v4.0.0.

**Target fixes (6 categories, 13 requirements):**
- **Network exposure (NET)** — A1 🔴 ntfy drop the `127.0.0.1` Docker publish (tailnet-bind only); A7 NetBird `server_url` must be https (stop cleartext PAT); A8 argv/flag-injection guard on config hostname/URL before `tailscale up`.
- **Dependency & toolchain (DEP)** — A2 build on go1.26.4 (closes 2 reachable stdlib CVEs) across go.mod + GOTOOLCHAIN + all CI; A3 `x/crypto` → v0.52.0 (13 SSH CVEs); A12 web UI CSRF off unmaintained `gorilla/csrf` (CVE-2025-47909) → stdlib `net/http.CrossOriginProtection`.
- **Doctor honesty & coverage (DOC)** — A4 `threat-model` derives ✓/✗ from the FULL doctor finding set (never ✓ for unrun checks); A5 disk-encryption fails CLOSED on tool error/unknown (Linux lsblk + macOS in-progress); A6 emit `nb-lock` WARN; C doctor minimum-versions table (ntfy ≥ 2.21 — unauth RCE CVSS 9.8 — FATAL).
- **Audit integrity (AUD)** — A9 backups recorded in the HMAC chain + restore verifies hash against a signed entry; A10 anchor refreshed on every append + monotonic counter in keychain (tail-truncation detected).
- **DoS resistance (DOS)** — A11 bound every attacker-influenced read (subprocess stdout cap, `MaxBytesReader` on daemon `/notify`, `io.LimitReader` on all backend REST decode/ReadAll).
- **CI gates (CI)** — govulncheck blocking in CI; `lint.yml`/`test.yml` actions SHA-pinned + harden-runner (catches A2/A3/A12 recurrence).

**Immutable floors (unchanged from v1/v2/v3):** lock-on-by-default, secrets printed once and never stored, ntfy + any listener bound to tailnet IP only (A1 restores this), public exposure / Tailscale Funnel rejected at schema level, FileVault/LUKS fail-closed (A5 restores this on Linux tool-error). No Claude coupling in core modules.

**Next milestone (queued):** v4.0.0 "Fortify" — at-risk-user threat model E1–E11 (duress credential, dead-man-switch, panic session-kill + key rotation, encrypt-at-rest, FIDO2/Secure-Enclave keys, content-free notifications, no-trace mode, `doctor --profile at-risk`, decoy config, mlock/zeroize, boot-attestation) + MED gaps (B) + supply-chain depth (D: Scorecard, SBOM/VEX, SLSA L3) + external version floors (NetBird 0.57, Tailscale 1.98.1, ET 6.2, OpenSSH 10). Full scope in SECURITY-AUDIT.md §B/§D/§E.

<details>
<summary>Previous milestone framing (v3.0.0 — Harden, Observe & Control)</summary>

**Goal:** Take Abysslink from a secure setup tool to a continuously-hardened, observable, remotely-controllable fleet platform — without weakening any v1/v2 security floor. Six tracks: security-audit & hardening pass, supply-chain hardening (cosign/SLSA/SBOM/reproducible), tamper-evident audit + fuzz, observability & metrics (tailnet-bound), opt-in Web UI dashboard, optional modules + fleet polish. Shipped 2026-06-03, local tag v3.0.0.
</details>

</details>

## Requirements

### Validated

**v2.0.0 (2026-06-02):**
- Generic `internal/backend.Client` interface — Tailscale, Headscale, NetBird interchangeable; v1 tailscale refactored in place behind it (BKND-01..05)
- Headscale backend (full) — server provisioning, HuJSON ACLs, admin API, hs-* doctor checks, permanent no-TKA flag (HS-01..03)
- NetBird backend (full) — REST-only client, server provisioning, nb-* doctor checks, AGPLv3 import guard (NB-01..04)
- Multi-rig fleet — enroll rig, fan-out status/doctor/notify/panic --all-rigs, per-rig keychain/ntfy/ACL isolation, mr-* checks (FLEET-01..03)

### Active

- [ ] Single static Go binary, cross-compiled for darwin/amd64, darwin/arm64, linux/amd64, linux/arm64
- [ ] `abysslink init` interactive wizard writes `~/.config/abysslink/abysslink.yaml`
- [ ] `abysslink up` runs the full module convergence loop (dry-run by default, `--apply` to mutate)
- [ ] `abysslink doctor` catches every footgun from the original 7-file setup guide
- [ ] `abysslink repair` fixes detected issues (with confirmation)
- [ ] `abysslink status` one-screen summary of tailnet, SSH, lock, ntfy, and disk-encryption state
- [ ] Tailscale module: install, configure SSH, enable Tailnet Lock, set ACL, hostname
- [ ] SSH module: disable OS Remote Login; enforce Tailscale SSH only (or hardened OpenSSH fallback)
- [ ] tmux module: install tmux, tmux-resurrect, tmux-continuum
- [ ] mosh module: install mosh, configure ACL UDP grant
- [ ] notify module: generic `Notifier` interface with `abysslink notify` CLI surface
- [ ] ntfy module: self-hosted ntfy bound to tailnet IP only, keychain-stored creds
- [ ] watch module: pane-idle, file-tail, and HTTP-change watchers in `abysslinkd`
- [ ] ACL module: HuJSON round-trip edit, admin API push, diff display
- [ ] Lock module: Tailnet Lock init, secrets printed once, never stored
- [ ] power module: macOS pmset + Linux systemd-inhibit keep-awake policies
- [ ] hardening module: FileVault/LUKS check, Application Firewall, stealth mode
- [ ] `abysslink enroll phone` QR flow + printable PDF runbook
- [ ] `abysslink panic` incident-response kill-switch (no confirmation prompt)
- [ ] `abysslink backup ls/restore` walk and restore mutation history
- [ ] `abysslink uninstall` reverses every mutation; `--purge` also removes packages
- [ ] `abysslink upgrade` with sigstore/cosign signature verification
- [ ] `abysslinkd` daemon with Unix socket, hot-reload, watch orchestration
- [ ] Platform abstraction for macOS (launchd, brew, security) and Linux (systemd-user, apt/dnf/pacman, libsecret)
- [ ] Audit log + backup on every file mutation (title only, never body content)
- [ ] Every external command through `internal/shell.Runner` (mockable in tests)
- [ ] golangci-lint clean; `make lint test` green on macOS 13/14 + Ubuntu 22.04/24.04 + Fedora 40
- [ ] claudecode module: detect `claude` on PATH, write `~/.claude/settings.json` hooks, keychain API key
- [ ] code-server module: VS Code in mobile Safari over tailnet
- [ ] ttyd module: browser terminal over tailnet with Tailscale-issued cert
- [ ] eternal-terminal module: ET server/client, ACL tcp/2022 grant
- [ ] goreleaser cross-compile pipeline, .deb/.rpm via nfpm, SBOM, sigstore signing
- [ ] `scripts/install.sh` POSIX install script with cosign verification
- [ ] Nix flake
- [ ] mkdocs-material docs site with quickstart, module pages, threat model, FAQ

### Out of Scope

- Custom mobile app in v1 — 6-12 month detour; Abysslink orchestrates existing apps (Tailscale + Blink/Termius/ConnectBot/Termux + ntfy)
- Windows in v1 — macOS + Linux only; re-evaluate after traction
- Vaultwarden secrets module — deferred (not in v2.0.0 scope)
- Tailscale Funnel / public exposure — permanently rejected at YAML schema level
- Proprietary cloud component / SaaS — CLI is local; no `api.abysslink.dev` calling home
- Telemetry — period
- Paid tier — deferred
- upsnap module — requires a second always-on tailnet node; deferred
- atuin module — deferred to 1.x
- sandbox / bubblewrap profiles — deferred to 1.x
- asciinema wrapper — deferred to 1.x
- Voice bridge — deferred to v3

## Context

Abysslink productizes a 7-file personal setup guide the author wrote to document his own paranoid phone-to-laptop rig. Every default in the guide is a hard floor — nothing may be weakened without explicit user consent. The original guide is the security source of truth; every footgun it documents must have a corresponding `abysslink doctor` check.

Marketing identity: "vibe-code Claude from your phone." Engineering identity: a generic phone-to-rig toolkit. The `claudecode` module is one opt-in consumer of `abysslink notify` — not a core dependency. Claude-specific logic must not leak into notify, watch, tailscale, ssh, tmux, or mosh modules.

The project is pre-alpha. DESIGN.md (49k) and IMPLEMENTATION-TASKS.md (32k) are the authoritative spec. Both live in `.mine/docs/` (private, gitignored).

## Constraints

- **Language**: Go 1.22+ — single static binary, official Tailscale SDK, goroutines for fan-out, Homebrew formula trivial
- **License**: Apache-2.0 — not MIT, not GPL
- **Platforms**: macOS 13+ and Linux (Debian/Ubuntu, Fedora/RHEL, Arch, NixOS) in v1
- **Module path**: `github.com/abysslink/abysslink`
- **Config format**: YAML (`abysslink.yaml`) — not TOML, not JSON
- **Secrets**: OS keychain only — never on argv, never in audit log
- **Mutations**: `--dry-run` default, `--apply` required — no silent mutations
- **Security**: FileVault (macOS) / LUKS (Linux) required — `doctor` fails closed if disk unencrypted
- **Networking**: ntfy binds to tailnet IP only, never 0.0.0.0; Tailscale Funnel permanently rejected
- **Tailnet Lock**: on by default; disablement secrets printed once, never stored on disk
- **SSH checkPeriod**: 12h default, settable down but never up without explicit `--accept-checkperiod-extension`

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Go not Python | Static binary, official Tailscale SDK, goroutines, Homebrew trivial | — Pending |
| Apache-2.0 | Permissive + patent grant; compatible with Tailscale (BSD-3) and Charm libs (MIT) | — Pending |
| ntfy as notify backend | Free, self-hostable, OSS, binds to tailnet IP only | — Pending |
| Tailscale-only v1 | Simplicity; Tailscale SSH is the safest path; Headscale/NetBird deferred | Superseded in v2.0.0 — backends generalized behind `internal/backend` |
| Generic `internal/backend` interface (v2) | Tailscale/Headscale/NetBird interchangeable; self-hosted control planes without forking core modules | — Pending |
| Self-host control server (Headscale + NetBird, v2) | Full data-plane sovereignty; no dependency on Tailscale SaaS coordinator | — Pending |
| OS keychain for secrets | No secrets on argv or in files; platform-native | — Pending |
| --dry-run default | Every destructive op requires --apply; audit every mutation | — Pending |
| Generic notify module | `claudecode` is one consumer; architecture stays generic for agent-vendor churn | — Pending |
| No mobile app v1 | 6-12 month detour; orchestrate existing apps via QR + runbooks instead | — Pending |
| CLAUDE.md is project instructions for Claude Code | Not GSD instruction file — project-specific override | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-06-04 — after Phase 26 (init journey gating & first-run fixes) complete; v4.0.0 (Fortify) queued
