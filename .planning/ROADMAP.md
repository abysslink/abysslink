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

Phases 22, 23, 23.1, 23.2, 24, 25 (6 phases, 26 plans) — closes the 2026-06-03 full security audit (11 agents): network/dependency lockdown (ntfy tailnet-only bind, NetBird https-only server_url, argv-injection guards, go1.26.4 / x/crypto v0.52.0 / CSRF→net/http.CrossOriginProtection), doctor/threat-model honesty (shared finding set, fail-closed disk encryption, nb-lock warning, minimum-versions table, probe-failure tri-state), tamper-evident audit hardening (HMAC-chained backups, anchor-every-append + keychain counter, cross-process flock, direction-aware verifyCounter), DoS bounding (limitio + WriteFilePath streaming), and a blocking govulncheck CI gate. All 20 requirements verified. Audit PASSED. Local tag `v3.0.1`. Deferred: Phase 23 FileVault mid-encryption `fdesetup` string literals (MED, real-hardware confirmation; fail-closed regardless).
→ Archived: [`milestones/v3.0.1-ROADMAP.md`](milestones/v3.0.1-ROADMAP.md) · [`milestones/v3.0.1-REQUIREMENTS.md`](milestones/v3.0.1-REQUIREMENTS.md) · audit [`milestones/v3.0.1-MILESTONE-AUDIT.md`](milestones/v3.0.1-MILESTONE-AUDIT.md)

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
**Plans:** 2/2 plans complete
Plans:
**Wave 1**

- [x] 26-01-PLAN.md — shell.LookPath + openURL B1 fix + checkACSleepDisabled B3 fix + regression tests

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 26-02-PLAN.md — B2 fix (Stage 2 no-dup) + 8-stage gated journey + per-stage gates + ACL stage + updated tests

**Cross-cutting constraints:**

- make lint test green

---

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 16 → 17 → 18 → 19 → 20 → 21 → 22 → 23

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

### Phase 23.1: Doctor probe-failure honesty — no false-OK on unknown or failed probes and no double-emit (INSERTED)

**Goal:** Close the four deferred honesty WARNINGs from the Phase 23 code review (23-REVIEW.md). A doctor/threat-model check must never render a green ✓ for a control it could not actually confirm: probe failures and unresolvable backend state must surface as a distinct unknown/warning, not OK; the ntfy bind check must catch IPv6 wildcards; and report-only OK findings must be emitted exactly once (no Detect+Verify duplication inflating the "N ok" count).
**Requirements**: DOC-05 (WR-02 funnel probe-failure false-OK), DOC-06 (WR-03 bind false-OK when tailnet IP unresolvable), DOC-07 (WR-04 ntfy IPv6 `[::]` wildcard miss), DOC-08 (WR-08 Detect+Verify double-emit dedup)
**Depends on:** Phase 23
**Source:** Phase 23 code review (`.planning/phases/23-doctor-honesty-coverage/23-REVIEW.md`) — WR-02, WR-03, WR-04, WR-08
**Success Criteria** (what must be TRUE):

  1. `funnelActive` (tailscale/module.go) distinguishes probe failure from confirmed-inactive: on exec error / non-zero exit it emits `SeverityWarning` ("could not determine Funnel state"), NOT a `SeverityOK` funnel finding; threat-model "No public exposure" row then renders `—`/`✗`, never a false ✓ (DOC-05 / WR-02)
  2. `metBindTailnetCheck` (cmd_doctor.go) emits `SeverityWarning` when `tailnetIP == ""` and a non-wildcard `bind_addr` is configured (cannot verify tailnet-scope — backend unavailable), instead of falling through to OK (DOC-06 / WR-03)
  3. ntfy `listen_address` check (ntfy/module.go) flags IPv6 wildcard binds (`[::]:PORT`, bare `::`) as non-compliant, mirroring the existing `0.0.0.0` / bare-`:PORT` detection; honors the immutable "ntfy binds tailnet IP only, never wildcard" default for externally-edited configs (DOC-07 / WR-04)
  4. Report-only `SeverityOK` findings appear exactly ONCE per `abysslink doctor` pass for lock/ssh/ntfy/acl/tailscale — either emitted in only one of Detect/Verify (hardening-module precedent) or deduped on `(Module, Check)` in `runner.Doctor`; the "N ok" count is no longer inflated and no duplicate ✓ rows render (DOC-08 / WR-08)
  5. `make lint test` green; new/updated tests cover each probe-failure → non-OK path and the single-emission/dedup guarantee

**Plans:** 4/4 plans complete

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
