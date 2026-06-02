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

## v3.0.0 — Harden, Observe & Control

Phases 16–21 (6 phases) — supply-chain hardening + tamper-evident audit + observability/metrics + opt-in Web UI dashboard + security audit pass + optional modules & fleet polish. Every new listener is opt-in, tailnet-bound, auth-gated, and gets its own FATAL doctor checks. No immutable v1/v2 floor is weakened.

- [x] **Phase 16: Supply-Chain Hardening & CI Gates** - govulncheck, semgrep, dependency-review, SLSA L2, cosign v3 keyless, SPDX+CycloneDX SBOM, harden-runner, reproducible builds, `abysslink verify` (completed 2026-06-02)
- [x] **Phase 17: Tamper-Evident Audit Log + Fuzzing** - Hash-chained/HMAC-signed audit entries, external anchor, `abysslink audit` command surface, fuzz targets with seed corpus and gitleaks pre-commit hook (completed 2026-06-02)
- [x] **Phase 18: Observability & Metrics** - `internal/metrics.Registry`, tailnet-IP-bound Prometheus endpoint, `abysslink report`, daemon `GET /status`, fleet daily digest (completed 2026-06-02)
- [x] **Phase 19: Web UI Dashboard (opt-in)** - `//go:build webui` opt-in module, safeweb CSRF, WhoIs auth, TLS via Tailscale cert, read-only gate, CSP self, separate goreleaser artifact (completed 2026-06-02)
- [ ] **Phase 20: Security Audit Pass & Doctor Checks** - `abysslink audit [--pentest]`, gosec/semgrep zero findings, refreshed threat model per backend, 18+ new sec-* doctor checks
- [ ] **Phase 21: Optional Modules & Fleet Polish** - upsnap (WoL with --apply gate), atuin, sandbox (Linux-only Landlock), asciinema (credential warning), NetBird posture-check + events tail, scope-cut docs

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

## v3.0.0 Phase Details

### Phase 16: Supply-Chain Hardening & CI Gates

**Goal**: Every PR and release is automatically scanned for vulnerabilities and supply-chain tampering; release artifacts carry SLSA L2 provenance, cosign v3 keyless signatures, and dual-format SBOMs; two builds from the same tag are byte-identical
**Depends on**: Nothing (CI/build-layer only; no runtime binary changes)
**Requirements**: SCH-01, SCH-02, SCH-03, SCH-04, SCH-05, SCH-06, SCH-07
**Success Criteria** (what must be TRUE):

  1. Every PR CI run executes `govulncheck ./...` (module mode), `semgrep` OSS ruleset, and `actions/dependency-review-action`; a PR with a known reachable CVE or a new AGPL dependency fails to merge
  2. A tagged release produces a `.bundle` file (cosign v3 keyless) that passes `cosign verify-blob --bundle <file> --offline` without Rekor reachability; `scripts/install.sh` attempts online verification first and falls back to offline bundle, never fails open
  3. `goreleaser --snapshot` produces both SPDX and CycloneDX SBOMs per artifact; release workflow jobs are split into minimum-privilege roles (build/sign/attest), all third-party actions are pinned to full commit SHAs, and `step-security/harden-runner >= v2.17` is active on every job
  4. Building the binary twice from the same commit SHA produces identical SHA-256 outputs; `.goreleaser.yaml` uses `{{.CommitDate}}`, `-trimpath`, and `SOURCE_DATE_EPOCH`
  5. `abysslink verify` fetches and verifies the running binary's cosign signature and SLSA provenance on demand; `abysslink version --provenance` displays the embedded commit SHA and build metadata
  6. `supply-cosign-bundle` doctor check passes: offline bundle verification succeeds for the installed binary; `supply-slsa-source` check verifies the provenance `gitCommit` field matches the version tag's commit

**Plans**: 4 plans

Plans:

- [x] 16-01-PLAN.md — PR security scan gates: govulncheck (module mode), semgrep OSS, dependency-review-action, harden-runner, dependabot (SCH-01, SCH-05)
- [x] 16-02-PLAN.md — Reproducible builds: -trimpath + {{.CommitDate}} + SOURCE_DATE_EPOCH; dual SBOM (SPDX+CycloneDX via syft); repro-check CI job (SCH-04, SCH-06)
- [x] 16-03-PLAN.md — Release workflow hardening: split build/sign/attest jobs, cosign v3 bundle, actions/attest@v4 SLSA L2, pinned SHAs, harden-runner (SCH-02, SCH-03, SCH-05)
- [x] 16-04-PLAN.md — CLI: abysslink verify + version --provenance + cosign v3 upgrade path + supply-cosign-bundle/supply-slsa-source doctor checks + install.sh fail-closed (SCH-07)


### Phase 17: Tamper-Evident Audit Log + Fuzzing

**Goal**: The audit log is hash-chained and HMAC-signed so any deletion, modification, or truncation is detectable; fuzz tests on config, HuJSON, and HMAC parsers fail closed on malformed input; no secret body ever appears in the log
**Depends on**: Phase 16 (clean CI gates fuzz results)
**Requirements**: AUD-01, AUD-02, AUD-03, AUD-04, AUD-05, AUD-06, AUD-07, AUD-08
**Success Criteria** (what must be TRUE):

  1. `audit.Entry` gains `prev_hash` and `sig` (both `omitempty`) without breaking existing unsigned v1/v2 entries; `audit.NewSigned(logPath, kc)` is wired into the daemon and `up --apply` path; `audit.New` callers are unaffected
  2. `abysslink audit verify` walks the full chain and exits 2 with `CHAIN BROKEN at entry N` on any gap, fork, or HMAC mismatch; `abysslink audit tail/ls/export` emit entries through `Printer` with `--json` support; `abysslink backup verify` checks chain integrity
  3. A process-level mutex spans the entire read-compute-write sequence; a concurrent-write stress test (50 goroutines) produces exactly 50 entries each with a valid predecessor, with zero chain forks
  4. The HMAC signing input is type-restricted to `title string` + `diffHash [32]byte` only; no field named body, content, data, raw, or payload can be added to `AuditEntry` without a staticcheck/gosec violation; grepping the audit log after any `repair --apply` finds no keychain-handle values as field values
  5. An external anchor is written every 100 entries or 1 hour (whichever comes first), including the entry count; `audit-anchor-age` WARN fires if the newest anchor is older than 24 hours; `audit-count-vs-anchor` FATAL fires if the current entry count is less than the anchor's recorded count (truncation detected)
  6. `FuzzConfigLoad`, `FuzzHuJSONParse`, and `FuzzHMACVerify` fuzz targets each have a seed corpus covering empty, single-token, max-length, and known-malformed inputs; a `len(b) > 4096` guard prevents CI OOM; a gitleaks pre-commit hook blocks any real secret from entering `testdata/fuzz/`; running each target for 60s in CI does not produce a panic or hang

**Plans**: 3 plans

Plans:
- [x] 17-01-PLAN.md — audit library core: Entry extension, SignedAudit, anchor, chain verifier, forbidigo lint rule
- [x] 17-02-PLAN.md — CLI surface: audit verify/tail/ls/export, backup verify, doctor checks, daemon SignedAudit wiring
- [x] 17-03-PLAN.md — fuzz targets: FuzzHMACVerify, FuzzConfigLoad, FuzzHuJSONParse with seed corpora, gitleaks hook, fuzz.yml CI

### Phase 18: Observability & Metrics

**Goal**: `abysslinkd` can expose a tailnet-IP-bound, opt-in Prometheus metrics endpoint and a `GET /status` JSON endpoint; `abysslink report` exports a point-in-time security posture; a fleet daily digest fires via the existing Notifier; no module ever imports `prometheus/client_golang` directly
**Depends on**: Phase 17 (clean audit seams; CI gates)
**Requirements**: OBS-01, OBS-02, OBS-03, OBS-04, OBS-05, OBS-06, OBS-07, OBS-08
**Success Criteria** (what must be TRUE):

  1. `internal/metrics.Registry` interface and `NoopRegistry` are in `modules.Deps` (nil-safe); a depguard lint rule rejects any import of `github.com/prometheus/client_golang` outside `internal/daemon/metrics_server.go`; `make lint` fails on a violation
  2. Setting `observability.metrics.enabled: true` starts a tailnet-IP-bound listener on the configured port; `config.Validate` rejects `0.0.0.0` or `::` for `bind_addr` with the same error class as Funnel rejection; the `metrics-bind-tailnet` doctor check is FATAL
  3. Metric labels use a compile-time allowlist; label names `hostname`, `topic`, `user`, `node_id`, and `ip` are rejected at registration; `sanitizeLabel()` maps unlisted values to `other`; `met-label-audit` and `met-cardinality` doctor checks are active at daemon startup
  4. Disabling metrics in config and triggering a hot-reload closes the metrics TCP listener within 500 ms; `met-disabled-listener` doctor check confirms no process is listening on the configured port when `enabled: false`
  5. `abysslink report` emits a JSON + human posture snapshot (doctor findings, last N audit entries, per-rig reachability) via `Printer`; `--all-rigs` fans out via `fleet.FanOut`; exit codes 0/1/2 match finding severity
  6. Daemon `GET /status` endpoint returns a JSON object consumed by the Web UI (Phase 19); fleet daily digest fires once per day via the existing `Notifier` using a dedicated digest ntfy topic with opaque rig IDs and no cross-rig secret leak

**Plans**: 4 plans

Plans:

- [x] 18-01-PLAN.md — internal/metrics package (Registry, NoopRegistry, labels, allowlist), config.Observability struct, .golangci.yml depguard ban (OBS-01, OBS-03, OBS-04)
- [x] 18-02-PLAN.md — daemon metrics TCP listener (hand-rolled Prometheus text exposition) + GET /status handler (OBS-02, OBS-05, OBS-07)
- [x] 18-03-PLAN.md — fleet daily digest scheduler + abysslink report command + metrics doctor checks (OBS-04, OBS-05, OBS-06, OBS-08)
- [x] 18-04-PLAN.md — daemon entrypoint wiring (startMetricsServer + startDigestScheduler) + make lint test green + VALIDATION.md (OBS-02, OBS-05, OBS-07, OBS-08)

### Phase 19: Web UI Dashboard (opt-in)

**Goal**: An operator who explicitly enables the Web UI can view fleet status, doctor findings, and the audit log timeline in a browser over the tailnet — with TLS, Tailscale WhoIs auth, CSRF protection, and a read-only gate enforced at both the schema and HTTP layers; the base binary excludes the UI entirely
**Depends on**: Phase 17 (audit.ReadLog), Phase 18 (GET /status, metrics.Registry)
**Requirements**: WEB-01, WEB-02, WEB-03, WEB-04, WEB-05, WEB-06, WEB-07
**Success Criteria** (what must be TRUE):

  1. The base binary built without `--tags webui` contains zero bytes of Web UI code; goreleaser produces a separate `--tags webui` artifact; `webui.enabled: false` default means the listener never starts unless explicitly opted in
  2. `config.Validate` rejects `0.0.0.0`/`::` for the webui bind address and rejects `read_only: false`; `webui-bind`, `webui-funnel`, and `webui-mutations-disabled` doctor checks are all FATAL; the startup security note is printed to stderr on first enable
  3. TLS is required via `tailscale.com/client/local.Client.GetCertificate`; a `webui-tls` FATAL doctor check fires if TLS is disabled; no plaintext listener is permitted
  4. Every request passes through WhoIs auth middleware; a request from `127.0.0.1` (loopback) returns 403 — not trusted-local; `webui-auth` and `webui-whoami-local` doctor checks are active; an automated test asserts loopback → 403
  5. `tailscale.com/safeweb` CSRF is active on every non-GET endpoint from day one; a POST to any endpoint without a valid CSRF token returns 403; `webui-csrf` is a FATAL doctor check; a test issues an unauthenticated POST and asserts 403
  6. All templates use `html/template` (never `text/template`); htmx is embedded via `embed.FS` with a SHA-384 SRI attribute; CSP header is `default-src 'self'` with no `unsafe-inline` or CDN sources; `gosec G203` lint rule is active; `webui-csp` doctor check verifies the header on a live request
  7. Read-only views (fleet status, doctor findings, audit-log timeline without hashes or bodies, notify history ring of 100) are reachable and correct; WhoIs availability on Headscale/NetBird is resolved per the research findings (backend-conditional auth or disable path); startup prints a one-time loud security note

**Plans**: 4 plans

Plans:

- [x] 19-01-PLAN.md — WebUI config struct + ValidateWebUI + goreleaser abysslinkd-webui build entry (WEB-01, WEB-02 schema layer)
- [x] 19-02-PLAN.md — webui package skeleton: security core (server, WhoIs middleware, safeweb CSRF, ring buffer, audit projection, SRI) + base-binary isolation tests (WEB-01, WEB-03, WEB-04, WEB-05)
- [x] 19-03-PLAN.md — HTTP handlers + templates + static assets (htmx vendor, style.css, error-handler.js) + CSP tests (WEB-06, WEB-07)
- [x] 19-04-PLAN.md — 8 FATAL webui doctor checks + daemon wiring + make lint test green + VALIDATION.md (WEB-02, WEB-03, WEB-04, WEB-05, WEB-06, WEB-07)

### Phase 20: Security Audit Pass & Doctor Checks

**Goal**: `abysslink audit` aggregates all security findings; gosec and semgrep pass with zero unsuppressed results; a refreshed threat model covers all three backends plus every v3 surface; 18 or more new `sec-*` doctor checks are active and FATAL/WARN-classified
**Depends on**: Phase 16 (CI gates), Phase 18 (metrics surface), Phase 19 (Web UI surface)
**Requirements**: SEC-01, SEC-02, SEC-03, SEC-04
**Success Criteria** (what must be TRUE):

  1. `abysslink audit verify` (no flags) is read-only and aggregates doctor findings plus the audit chain check; `abysslink audit --fix` requires `--apply`; `abysslink audit --pentest` runs the full sec-* check suite and exits 2 on any FATAL finding; `--format=json` emits machine-parseable output through `Printer`
  2. `make lint` runs gosec and semgrep with zero unsuppressed findings; every suppression comment includes a justification; CI blocks merge on any new unsuppressed finding
  3. A refreshed threat-model document covers all three backends (Tailscale, Headscale, NetBird), the fleet, and every v3 surface (metrics endpoint, Web UI, audit chain); `abysslink threat-model --backend=<name>` renders the backend-specific section
  4. At least 18 new `sec-*` doctor checks are registered and produce the correct severity: `sec-ssh-permitroot` (FATAL), `sec-ssh-x11forwarding` (WARN), `sec-ssh-agentforwarding` (WARN), `sec-ssh-maxauthtries` (WARN), `sec-ssh-logingracetime` (WARN), `sec-ssh-ciphers` (WARN), `sec-audit-log-exists` (FATAL), `sec-audit-log-perms` (FATAL, mode 0600), `sec-no-world-readable-config` (FATAL), `sec-daemon-socket-perms` (FATAL), `sec-listener-bind` (FATAL), `sec-funnel-schema` (FATAL), `sec-disk-encryption` (FATAL), `sec-binary-signed` (WARN), `sec-upgrade-verified` (WARN), plus checks covering metrics-bind, webui-bind, and audit-anchor-age

**Plans**: 4 plans

Plans:
- [ ] 20-01-PLAN.md — gosec/semgrep zero-unsuppressed: nolintlint gate + fix real findings + annotate 95 bare directives + gosec CI job
- [ ] 20-02-PLAN.md — 18 new sec-* doctor checks (cmd_doctor_sec.go) wired into doctor RunE
- [ ] 20-03-PLAN.md — audit verify aggregate: --pentest/--fix/--format=json flags + exit 0/1/2 + tests
- [ ] 20-04-PLAN.md — threat-model doc refresh (per-backend + fleet + v3) + --backend rendering

### Phase 21: Optional Modules & Fleet Polish

**Goal**: The four previously-stubbed optional modules (upsnap, atuin, sandbox, asciinema) have real implementations with their hard-floor acceptance gates; NetBird posture-check management and event tailing close the Tailscale parity gap; scope-cut documentation is published
**Depends on**: Phase 17 (audit.WriteFile seams), Phase 18 (Notifier, fleet.FanOut)
**Requirements**: MOD3-01, MOD3-02, MOD3-03, MOD3-04, MOD3-05, MOD3-06
**Success Criteria** (what must be TRUE):

  1. `abysslink wol <rig>` without `--apply` prints a dry-run summary and sends no UDP packet; `abysslink wol <rig> --apply` sends the magic packet, writes an audit entry containing the rig name and MAC address, and is confirmed by the `wol-apply-gate` FATAL doctor check; `upsnap-bind` and `upsnap-no-public` checks are active
  2. `abysslink asciinema rec` emits a non-suppressible credential warning before starting any recording; the `asciinema-rec-warning` FATAL doctor check verifies the warning is present in the wrapper; no recording starts without the user passing the warning prompt
  3. The atuin module installs the client, writes `~/.config/atuin/config.toml` via `audit.WriteFile`, and activates shell integration; `atuin-bind` is FATAL and `atuin-key-backed-up` is WARN; the sandbox module applies Linux-only Landlock profiles via `audit.WriteFile` and returns `ErrNotSupported` on macOS; `sandbox-landlock-supported` is WARN on unsupported kernels
  4. `abysslink netbird posture list/create/delete` manages NetBird posture checks via the existing NetBird backend client; `abysslink netbird events [--follow]` tails the NetBird event stream; `nb-posture-active` is a WARN doctor check
  5. `docs/headscale-ha.md` and `docs/netbird-scim.md` are published explaining why Headscale PostgreSQL HA and NetBird SCIM are out of scope, with the known-workaround patterns documented; no implementation is attempted for either
  6. `make lint test` is green across all new module code; all shell calls in the four new module implementations go through `shell.Runner` with no bare `os/exec`; every file mutation goes through `internal/audit.WriteFile`

**Plans**: TBD
**Research needed**: WoL library selection (mdlayher/wol vs sabhiram/go-wol), Landlock distro/kernel compatibility matrix

---

## Out of Scope (v3.0.0)

- Headscale PostgreSQL HA — no upstream HA support; documented in `docs/headscale-ha.md` (MOD3-06)
- NetBird SCIM provisioning — commercial-edition-only; documented in `docs/netbird-scim.md` (MOD3-06)
- macOS sandbox/Landlock — private Apple API; Linux-only stub returns `ErrNotSupported` on macOS (MOD3-03)
- OpenTelemetry — 15-25 MB bloat; rejected
- tsnet embedded node — use `tailscale.com/client/local` instead
- Any new AGPL dependency — depguard-enforced rejection

---

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13 → 14 → 16 → 17 → 18 → 19 → 20 → 21

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
| 20. Security Audit Pass & Doctor Checks | 0/? | Not started | - |
| 21. Optional Modules & Fleet Polish | 0/? | Not started | - |
