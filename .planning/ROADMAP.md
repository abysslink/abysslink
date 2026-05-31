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

## v2.0.0 — Self-Hosted Backends & Fleet

- [x] **Phase 11: Backend Abstraction Refactor** - Generic `internal/backend.Client` interface with contract tests; Tailscale adapter wrapping v1; all modules migrated; zero v1 regression (completed 2026-05-31)
- [x] **Phase 12: Headscale Backend** - Full Headscale backend: client adapter (HuJSON reuse, deny-all baseline, lock WARN), server provisioning (TLS gate, non-root, cosign, embedded DERP), all hs-* doctor checks (completed 2026-05-31)
- [ ] **Phase 13: NetBird Backend** - Full NetBird backend: REST-only client adapter (Groups-as-tags, SSHCheck graceful degradation, AGPLv3 CI guard), server provisioning (v0.57.0 floor, ZITADEL CVE gate, non-root), all nb-* doctor checks
- [ ] **Phase 14: Multi-Rig Fleet** - `abysslink enroll rig`, fan-out status/doctor/notify/panic, per-rig keychain namespaces and ntfy topics, rig-to-rig ACL deny, multi-rig doctor checks

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

## v2.0.0 Phase Details

### Phase 11: Backend Abstraction Refactor

**Goal**: All Tailscale-specific call sites in the v1 codebase are moved behind a stable `internal/backend.Client` interface; the Tailscale adapter passes a complete contract test suite; v1 behaviour is 100% preserved with zero observable regression
**Depends on**: Phase 10 (v1 complete)
**Requirements**: BKND-01, BKND-02, BKND-03, BKND-04, BKND-05
**Success Criteria** (what must be TRUE):

  1. `internal/backend.Client` interface compiles; `backend.Capabilities` struct gates Lock, AdminAPI, SSHCheck, AuthKeys, FunnelRejection; `backend.New(cfg, runner)` factory resolves the correct adapter from config
  2. `internal/backend/contract_test.go` asserts three invariants against the Tailscale adapter: `IP()` returns non-empty after startup, `SSHConfig().CheckPeriod` is non-zero, `LockCapability()` returns `Full`; test must pass before merge
  3. Config YAML with the v1 `tailnet:` key loads without error and is transparently aliased to `backend.type: tailscale`; new `backend:`, `server:`, and `rig:` stanzas parse with strict-mode YAML
  4. All modules outside `internal/backend/` call only `Deps.Backend` (the `Client` interface); `go build ./...` fails if any module imports a concrete adapter package directly
  5. `make lint test` stays green; `abysslink up --dry-run` behaviour on a v1 config is byte-for-byte identical before and after the refactor

**Plans**: 3 plans
Plans:
**Wave 1**

- [x] 11-01-PLAN.md — Capture pre-refactor `up --dry-run` parity golden + behavior-neutral runner-injection seam (BKND-05)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 11-02-PLAN.md — Create internal/backend package (Client interface, neutral types, Capabilities, factory, adapter, contract + lockstep tests) + config backend/server/rig stanzas & tailnet: alias (BKND-01, BKND-02, BKND-03)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 11-03-PLAN.md — Migrate acl module + 6 CLI files to backend interfaces, wire Deps.Backend, enable depguard guard, assert byte-for-byte parity (BKND-04, BKND-05)

### Phase 12: Headscale Backend

**Goal**: Users running a self-hosted Headscale control plane can point Abysslink at it with `backend.type: headscale`; Abysslink provisions and hardens the Headscale server, manages ACLs in HuJSON, and surfaces all Headscale-specific doctor checks — while the absence of Tailnet Lock is permanently and loudly flagged
**Depends on**: Phase 11
**Requirements**: HS-01, HS-02, HS-03
**Success Criteria** (what must be TRUE):

  1. `abysslink init` wizard accepts `backend.type: headscale` + login server URL; `abysslink up --apply` enrolls the node against the Headscale server and pushes a deny-all baseline HuJSON ACL policy before the first node is admitted
  2. `abysslink server headscale init --apply` downloads a cosign-verified Headscale binary, writes a hardened `config.yaml` (TLS gate enforced — command refuses without a valid cert, `verify_client_url_fail_open: false`, embedded DERP), installs a systemd unit running as `User=headscale`, and creates a pre-auth key with an explicit short RFC3339 expiry
  3. Every pre-auth key creation call asserts a non-zero expiry in the API response; `doctor` check `hs-key-expiry` fails if any active key has no expiry (closes upstream Headscale issue #1579 vector)
  4. `abysslink doctor` emits `WARN: server-trust model only — Tailnet Lock (TKA) is not available on Headscale` for the `hs-lock` check; this check can never return PASS regardless of configuration
  5. All nine hs-* checks (`hs-tls`, `hs-bind`, `hs-api-auth`, `hs-key-expiry`, `hs-db-perms`, `hs-lock`, `hs-oidc-filter`, `hs-proc-user`, `hs-derp-failclosed`) report correct PASS/WARN/FAIL status; `make lint test` green with mock Headscale API fixtures

**Plans**: 5 plans
Plans:
**Wave 1**

- [x] 12-01-PLAN.md — Config schema extension (HeadscaleServer struct + Defaults) + test fixtures + contract_test.go update

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 12-02-PLAN.md — headscaleAdapter (Client + AdminAPI + ACLManager, not Locker) + factory.go case + contract/invariant tests

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 12-03-PLAN.md — headscale_config.go (surgical YAML merge) + headscale_doctor.go (nine hs-* checks)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 12-04-PLAN.md — cmd_server_headscale.go (init/status/upgrade/backup) + root.go wiring + cmd_doctor.go hs-* fix entries

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 12-05-PLAN.md — abysslink init wizard extension: backend.type headscale + server_url prompt (SC-1 / D-13)

### Phase 13: NetBird Backend

**Goal**: Users running a self-hosted NetBird control plane can point Abysslink at it with `backend.type: netbird`; Abysslink provisions the NetBird server at a safe version floor, verifies the ZITADEL CVE remediation, manages policies via REST JSON, and surfaces all NetBird doctor checks — with graceful degradation warnings for missing SSH check and lock capabilities; no NetBird AGPLv3 server packages are ever imported as Go dependencies
**Depends on**: Phase 11
**Requirements**: NB-01, NB-02, NB-03, NB-04
**Success Criteria** (what must be TRUE):

  1. `abysslink up --apply` with `backend.type: netbird` enrolls the node, removes the default "All" group policy, and pushes an initial deny-all policy via REST; `doctor` emits `WARN: SSHCheck not available on NetBird — checkPeriod enforcement disabled` at every run
  2. `abysslink server netbird init --apply` refuses to proceed if the downloaded binary version is below v0.57.0; after provisioning, it verifies that the default ZITADEL admin credential is rejected (POST with known defaults returns 401); management ports are bound to loopback or overlay IP only; systemd unit runs non-root
  3. After every ACL policy push, Abysslink re-reads the policy from the NetBird backend and diffs against the intended rule count; a mismatch (silently dropped rule) is a `FAIL`, not a warning
  4. CI linter (`golangci-lint` custom rule or `go vet` analysis pass) fails the build if any `github.com/netbirdio/netbird/management/...` package is imported; the v2.0.0 release checklist contains an explicit AGPLv3 legal review item
  5. All seven nb-* checks (`nb-tls`, `nb-version`, `nb-zitadel`, `nb-mgmt-bind`, `nb-key-type`, `nb-api-auth`, `nb-proc-user`) report correct status; `make lint test` green with mock NetBird API fixtures

**Plans**: TBD

### Phase 14: Multi-Rig Fleet

**Goal**: A user controlling multiple rigs from one phone can enroll each rig by name, target any single rig or all rigs with one command, and receive aggregated status and notifications; each rig is cryptographically isolated at the keychain, ntfy topic, and ACL layers
**Depends on**: Phase 13
**Requirements**: FLEET-01, FLEET-02, FLEET-03
**Success Criteria** (what must be TRUE):

  1. `abysslink enroll rig <name> --apply` adds the rig to `abysslink.yaml` under `rig:`, creates an isolated OS keychain namespace for it, creates a dedicated ntfy topic (cross-topic notification delivery is rejected at enrollment time), and enforces a rig-to-rig ACL deny rule; `abysslink rig ls` lists all enrolled rigs with backend and last-seen status
  2. `abysslink status --all-rigs` fans out to all enrolled rigs concurrently via `errgroup`; each rig respects its per-rig timeout; an offline rig is reported as `UNREACHABLE` without causing the command to fail; `--strict` opt-in makes any `UNREACHABLE` rig exit 1
  3. `abysslink doctor --all-rigs` and `abysslink notify --all-rigs` fan out identically to status; `abysslink panic --all-rigs` executes revocations on all rigs and completes within 10 seconds per rig
  4. `abysslink doctor` passes the three multi-rig isolation checks: `mr-rig-isolation` (rig-to-rig ACL deny present), `mr-topic-isolation` (no two rigs share an ntfy topic), `mr-key-uniqueness` (no two rigs share a keychain credential namespace)
  5. A notification event originating from Rig A is provably never delivered to Rig B's ntfy topic; fan-out notify includes a rig-identity header validated by the receiving subscriber

**Plans**: TBD

---

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14

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
| 13. NetBird Backend | 0/0 | Not started | - |
| 14. Multi-Rig Fleet | 0/0 | Not started | - |
