---
gsd_state_version: 1.0
milestone: v3.0.0
milestone_name: Harden, Observe & Control
status: planning
last_updated: "2026-06-03T08:33:45.411Z"
last_activity: 2026-06-03
progress:
  total_phases: 12
  completed_phases: 1
  total_plans: 4
  completed_plans: 4
  percent: 8
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-30)

**Core value:** `abysslink up` — one command that produces a working, auditable, paranoid-by-default phone-to-laptop remote setup on any macOS or Linux machine
**Current focus:** Phase 23 — doctor honesty coverage

## Current Position

Phase: 23
Plan: Not started
Status: Ready to plan
Last activity: 2026-06-03

## Performance Metrics

**Velocity:**

- Total plans completed: 74 (v1.0.0)
- Average duration: -
- Total execution time: 2026-05-26 (v1 single session)

**By Phase:**

| Phase | Plans | Status |
|-------|-------|--------|
| 1. Repo Bootstrap | 3 | Complete |
| 2. Core CLI Scaffold | 3 | Complete |
| 3. Platform Abstraction | 3 | Complete |
| 4. Tailscale Integration | 3 | Complete |
| 5. Module System & Core Modules | 4 | Complete |
| 6. Top-Level Commands | 3 | Complete |
| 7. Optional Modules | 2 | Complete |
| 8. Release Infrastructure | 3 | Complete |
| 9. Verification & Polish | 3 | Complete |
| 10. Journey & Rich TUI | 6 | Complete |
| 11. Backend Abstraction Refactor | TBD | Not started |
| 12. Headscale Backend | TBD | Not started |
| 13. NetBird Backend | TBD | Not started |
| 14. Multi-Rig Fleet | TBD | Not started |
| Phase 11 P01 | 7m | 2 tasks | 4 files |
| Phase 11-backend-abstraction-refactor P02 | ~50 minutes | 3 tasks | 11 files |
| Phase 11 P03 | 60m | 3 tasks | 11 files |
| Phase 12-headscale-backend P02 | 5m | 2 tasks | 3 files |
| Phase 12 P03 | 12m | 2 tasks | 4 files |
| Phase 12 P04 | 35 | 4 tasks | 4 files |
| Phase 12-headscale-backend P05 | 5m | 1 tasks | 2 files |
| Phase 13 P01 | 12m | 3 tasks | 7 files |
| Phase 13 P02 | 25m | 2 tasks | 6 files |
| Phase 13 P03 | 22m | 2 tasks | 7 files |
| Phase 13 P04 | 25m | 1 tasks | 4 files |
| Phase 13 P04 | 25m | 1 tasks | 4 files |
| Phase 14-multi-rig-fleet P01 | 12m | 2 tasks | 5 files |
| Phase 14-multi-rig-fleet P02 | 6m | 2 tasks | 6 files |
| Phase 14-multi-rig-fleet P03 | 40m | 2 tasks | 5 files |
| Phase 16 P01 | 6m | 2 tasks | 2 files |
| Phase 16 P02 | 10m | 2 tasks | 3 files |
| Phase 16 P03 | ~8m | 2 tasks | 2 files |
| Phase 16 P04 | ~25m | 2 tasks | 9 files |
| Phase 17 P01 | ~18m | 3 tasks | 9 files |
| Phase 17 P02 | ~20m | 3 tasks | 22 files |
| Phase 17 P03 | ~15m | 2 tasks | 17 files |
| Phase 18 P01 | 6min | 2 tasks | 9 files |
| Phase 18 P02 | 4min | 2 tasks | 4 files |
| Phase 18 P03 | 12min | 3 tasks | 8 files |
| Phase 18 P04 | 5min | 2 tasks | 4 files |
| Phase 19 P01 | 6m | 2 tasks | 5 files |
| Phase 19 P02 | 8m | 16 tasks | 13 files |
| Phase 19 P03 | 12m | 2 tasks | 12 files |
| Phase 19 P04 | 15 | 2 tasks | 12 files |
| Phase 20 P02 | 22min | 2 tasks | 3 files |
| Phase 20 P04 | 420 | 2 tasks | 3 files |
| Phase 20 P01 | 38min | 3 tasks | 38 files |
| Phase 20 P03 | 18min | 2 tasks | 5 files |
| Phase 21 P01 | 18min | 2 tasks | 8 files |
| Phase 21 P02 | 14min | 2 tasks | 8 files |
| Phase 21 P03 | 12 | 1 tasks | 9 files |
| Phase 21 P04 | 9min | 2 tasks | 12 files |
| Phase 21 P05 | 7min | 2 tasks | 4 files |
| Phase 22 P01 | 5m | 2 tasks | 7 files |
| Phase 22 P03 | 5m | 2 tasks | 5 files |
| Phase 22 P04 | 8m | 2 tasks | 9 files |

## Accumulated Context

### Roadmap Evolution

- Phase 22 (Network & Dependency Lockdown) detail block added to ROADMAP.md during planning — NET-01/02/03, DEP-01/02/03 (v3.0.1).
- Phase 23 (Doctor Honesty & Coverage) added to ROADMAP.md — DOC-01/02/03/04 (v3.0.1). Plans TBD.
- v3.0.1 milestone continues with phases 24 (AUD-01/02, DOS-01) and 25 (CI-01) per REQUIREMENTS.md traceability — not yet added to roadmap.

### Decisions

- Roadmap: Phases follow IMPLEMENTATION-TASKS.md Phase 0–8 structure exactly (user explicit choice)
- Roadmap: Granularity is coarse — 9 phases, broad delivery boundaries, no horizontal layer splits
- Architecture: claudecode is one opt-in consumer of generic notify module; no Claude logic in core modules
- Security: macOS keychain via `security -i` stdin pipe — no secrets on argv
- Tailscale: CLI-based integration (shell.Runner) not heavy tailscale.com SDK — stays under 50MB binary budget
- Module naming: type `Module` not `<Pkg>Module` per revive stutter rule
- dry-run default: if neither --apply nor --dry-run set → dry-run=true in loadCmdContext
- v2.0.0: Backend abstraction uses adapter pattern — v1 tailscale code wrapped unchanged, new backends implement same interface
- v2.0.0: No new Go library deps for v2 — Headscale and NetBird driven via shell.Runner + net/http only
- v2.0.0: NetBird AGPLv3 server packages permanently excluded from Go imports; CI linter enforces this
- v2.0.0: Tailnet Lock absence on Headscale/NetBird is a permanent doctor WARN (hs-lock, nb-lock), never PASS
- v2.0.0: Phase order is abstraction → Headscale → NetBird → Fleet (research-validated; coarse granularity combines client+server per backend)
- v2.0.0: Security hardening (TLS gate, non-root, port binding) is acceptance criteria in each provisioning phase — no separate hardening phase
- [Phase ?]: Config schema + fixture foundation for Headscale backend
- [Phase ?]: macOS launchd _headscale service account (UID 399) + plist provisioning enabled after checkpoint approval
- [Phase ?]: setNestedKey refactored to shared config_helpers.go
- [Phase ?]: ZITADEL probe auth separation
- [Phase ?]: ZITADEL probe auth separation: admin API Bearer token (management/v1/users/_search) NOT NetBird Token header — prevents false PASS on non-ZITADEL deployments
- [Phase ?]: Backward compat for existing rig: yaml keys
- [Phase ?]: Prevents timing side-channel attacks
- [Phase ?]: Decision A1 (confirmed): Tailscale/Headscale HuJSON isolation = absence-of-grant; no explicit deny construct
- [2026-06-02 reconcile]: v1.0.0 phases 1-10 SHIPPED (commits ≤ 2026-05-29); ROADMAP `[x]` + Progress table + velocity table all mark them Complete. Their `.planning/phases/0X-*` dirs were cleaned (SUMMARYs removed; 4-9 have no dir), so `roadmap.analyze` mis-reports disk_status incomplete for 2-9. This is a stale-disk artifact, NOT pending work — unlike v2.0.0 (phases 11-14) which were archived to `milestones/v2.0.0-ROADMAP.md`, v1.0.0 was never formally archived inline. Autonomous run scoped `--from 16`; do NOT re-execute 2-9 (would overwrite shipped 68-file CLI scaffold). Safety branch: `backup/pre-autonomous-260602` @ 8c47187.
- [Phase ?]: Phase 16-01: harden-runner pinned to v2.17.0 per must_haves; semgrep uses renamed semgrep/semgrep-action@v1
- [Phase ?]: Phase 16-01: GitHub Actions pinned to verified full 40-char commit SHAs; plan-supplied SHAs were truncated/wrong, re-verified via git ls-remote against upstream tags
- [Phase ?]: Phase 16-02: reproducible goreleaser builds — {{.CommitDate}} + -trimpath all targets; dual SPDX+CycloneDX SBOMs; repro-check.yml CI gate asserts sha256 binary identity
- [Phase 16]: Phase 16-03: split release.yml into least-privilege build/sign/attest jobs; cosign v3 .bundle offline verify; actions/attest SLSA L2 bound to github.sha; actions/attest@v4.1.4 did not exist -> pinned v4.1.0 (59d89421)
- [Phase ?]: Phase 16-04: SCH-07 user-visible supply-chain — abysslink verify (cosign v3 --bundle --offline), version --provenance, upgrade v3 bundle path, doctor supply-cosign-bundle/supply-slsa-source (WARN), install.sh fail-closed; no new Go runtime deps
- [Phase 17]: Phase 17-01: Verify reconstructs the signed DiffHash by hex-decoding the stored Entry.Hash (round-trips Append); the plan's sha256([]byte(entry.Hash)) verify formula would never validate a legitimately signed entry (Rule 1 fix, commit 646c7bc)
- [Phase 17]: Phase 17-01: local audit.KeychainStore interface includes Delete to exactly match secrets.KeychainStore, avoiding the audit->secrets import cycle while letting MockStore/DarwinStore/LinuxStore satisfy it by assignment
- [Phase ?]: AuditWriter interface lets *Audit and *SignedAudit be injected interchangeably via Deps.Audit (ctx-less WriteFile for drop-in compat)
- [Phase ?]: backup verify and audit verify share the identical audit.Verify path (T-17-12); no separate weaker verification
- [Phase ?]: Phase 17-03: FuzzConfigLoad uses external config_test + temp YAML (Load is path-only); FuzzHMACVerify in-package for private verifyHMAC; FuzzHuJSONParse drives NewACLEditor (most direct HuJSON parse path)
- [Phase ?]: Phase 17-03: len(b)>4096 guard is first statement in every fuzz body (T-17-15); 12 seed corpus files use synthetic non-secret inputs so gitleaks does not flag them (AUD-08)
- [Phase ?]: Metrics are hand-rolled (no prometheus/client_golang); depguard total-ban enforces it (OBS-01)
- [Phase ?]: OBS-03 hard floor: observability.metrics.bind_addr rejects 0.0.0.0/:: in config.Validate
- [Phase 18]: 18-02: exported StartMetricsServer/RegisterOBS05Metrics so the external daemon_test package and Plan-04 main.go can call them
- [Phase 18]: 18-02: separate escapeHelp (backslash+newline) from escapeLabelValue (backslash+quote+newline) per Prometheus text-format spec; net.JoinHostPort for IPv6-safe addr
- [Phase ?]: Exported StartDigestScheduler so package main can launch the digest; helpers stay unexported (18-03)
- [Phase ?]: abysslink report reuses persistent root --all-rigs/--strict; rigReachability serialises opaque rig ids only (18-03)
- [Phase ?]: Phase 18 metrics wired at daemon startup; Registry selected by config in both main.go and buildDeps (NewMemRegistry/NoopRegistry)
- [Phase ?]: Phase 19-01: tailscale.com v1.98.5 pinned via //go:build webui blank-import placeholder; base binary links 0 tailscale.com packages (T-19-02)
- [Phase ?]: Phase 19-01: go directive bumped 1.23.0->1.26.3 (forced by tailscale.com v1.98.5 module floor)
- [Phase ?]: Phase 19-01: ValidateWebUI mirrors ValidateObservability bind-floor + rejects read_only:false (WEB-02 config-layer gate)
- [Phase ?]: Per-view html/template sets (base+view) because each view defines the content block
- [Phase 19]: htmx 2.0.10 vendored from unpkg npm mirror (GitHub release asset 404s); SHA-384 cross-verified against jsdelivr
- [Phase ?]: Phase 19 webui doctor checks use net.Dial/net.http probes (no tailscale import) to keep base binary SDK-free
- [Phase ?]: 20-02: sshd_config is the primary sec-ssh-* parse path; sshd -T only as root, never sudo
- [Phase ?]: 20-02: sec-* cross-ref aliases reuse pre-computed Phase-17/18/19 findings (run-once)
- [Phase ?]: threat-model --backend renders backend rows; unknown backend warns + renders base+v3 only (no error)
- [Phase ?]: v3SurfaceRows failChecks list both sec-* alias and original module check ID so rows reflect posture if alias naming evolves
- [Phase ?]: SEC-02 tooling gate: nolintlint allow-unused:true; standalone gosec -exclude FP families + #nosec for genuine G115/G402; G104 fixed at root
- [Phase ?]: WoL audit uses chain-correct Append (signed/unsigned), not WriteFile with a bogus sentinel path (W-02 correction)
- [Phase ?]: upsnap module rewritten as WoL enablement module; packet send lives in the CLI command behind the --apply HARD FLOOR, not in the module
- [Phase ?]: 21-03: go-landlock v0.8.1 used (no AGPL; psx LGPLv2+ acceptable)
- [Phase ?]: 21-04: NetBird posture/events via exported wrappers over netbirdAdapter.doRequest (no new client/interface); events --follow count-watermark dedup with 2s->30s bounded backoff, ctx-cancellable; nb-posture-active WARN gated on backend.type==netbird
- [Phase 21]: 21-05: mod3DoctorFindings wired into doctor RunE (after secDoctorFindings, before --all-rigs fan-out); all 9 Phase-21 checks now appear in abysslink doctor + --json. root.go needed no change (wol/asciinema/netbird already registered by plans 01/02/04)
- [Phase 21]: 21-05: Headscale HA + NetBird SCIM published as scope-cut docs (docs/headscale-ha.md, docs/netbird-scim.md) — out of scope, workarounds documented not implemented (MOD3-06). Phase 21 CLOSED: make lint test green, GOOS=linux Landlock build clean. Final phase of v3.0.0.
- [Phase ?]: 22-01 dependency lockdown
- [Phase ?]: ntfyOKFinding/ntfyFatalFinding set Module:'ntfy' not 'webui' — Phase-23 doctor-honesty grouping boundary
- [Phase ?]: DEP-03 path (b): drop safeweb; CrossOriginProtection + securityHeadersMiddleware replaces gorilla/csrf; both gorilla packages removed from go.mod after go mod tidy

### Pending Todos

None.

### Blockers/Concerns

- Phase 12 planning: ACME + embedded DERP port interaction needs targeted research sub-task (Caddy/nginx WebSocket forwarding config for DERP alongside Let's Encrypt ACME is MEDIUM confidence)
- Phase 13 SC-3 gap closed (commit 4e2cf8d): SetACL/PushPolicy now validates after every push — Phase 13 score 17/17
- Phase 13 planning: NetBird combined binary (non-Docker) config format stability across patch releases needs direct v0.71.4 deploy verification
- Phase 14 planning: Whether `abysslinkd` HTTP-over-socket protocol requires extension for fleet peer status polling is undetermined — address in Phase 14 planning

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260526-l51 | UX overhaul for abysslink up command: real-time per-module scan rows, rich plan preview with Explain text, live apply progress rows with step counters, final summary | 2026-05-26 | a0dc6c7 | [260526-l51-ux-overhaul-for-abysslink-up-command-rea](.planning/quick/260526-l51-ux-overhaul-for-abysslink-up-command-rea/) |
| 260528-5gs | Security hardening Slice 1 — foundation wiring: construct platform.Platform + keychain via build-tagged factories and inject through modules.Deps (kills dead platform layer + nil keychain); route tmux/ntfy/claudecode writes through internal/audit (backup+log); fail-closed disk-encryption gate in `up` (--force-unsafe); LUKS→Fatal | 2026-05-28 | 993eb91 | [260528-5gs-foundation-wiring](.planning/quick/260528-5gs-foundation-wiring/) |
| 260528-s2c | Security hardening Slice 2 — make `up` converge: route tmux/mosh/ntfy/tailscale installs through platform.InstallPackage (adds NixOS, sudo for apt/dnf/pacman); shell.RunInteractive for TTY auth; tailscale auto-install + interactive SSO login + --auto-update + Funnel/Serve refusal in Verify (Funnel→Fatal); tmux TPM bootstrap + 15-min continuum; mosh ~/.zshenv PATH fix | 2026-05-28 | 0a73bef | [260528-s2c-up-converge](.planning/quick/260528-s2c-up-converge/) |
| 260528-s3r | Security hardening Slice 3 — reversibility (Success Criteria #4): audit.Reverse/PlanReverse/MutatedTargets/Backups; real `backup ls/restore` + `uninstall` (restore-to-original or delete-created) with SHA-256 manifest; fixed backup timestamp collision (second→nanosecond) that lost originals | 2026-05-28 | 76f9c4f | [260528-s3r-reversibility](.planning/quick/260528-s3r-reversibility/) |
| 260528-s4a | Security hardening Slice 4 — ACL + Lock spine: acl Apply (admin-API push w/ ETag or manual clipboard+editor fallback) via tested ACLEditor; config Tailnet.Admin (secret via env, off-disk); cmd_lock init/status/sign/rotate with print-once secrets + attestation gate; checkPeriod>12h gate (--accept-checkperiod-extension); checkPeriod bounds in Validate | 2026-05-28 | d6f82b0 | [260528-s4a-acl-lock](.planning/quick/260528-s4a-acl-lock/) |
| 260530-8mf | fix(up): skip success summary when user declines ConfirmBlast; fix(acl): post-paste pause in applyManual so the flow waits for the user to save the ACL in the admin editor before returning | 2026-05-30 | a44bfd4 | [260530-8mf-fix-up-rune-so-user-no-on-confirmblast-a](.planning/quick/260530-8mf-fix-up-rune-so-user-no-on-confirmblast-a/) |
| 260530-8uz | fix(hardening) + fix(power): rewrite scan warnings to be honest about which findings abysslink auto-fixes — hardening firewall is report-only (manual fix paths provided); pmset auto-fix only runs when `power.closed_lid_ac: keep-awake` is set in abysslink.yaml | 2026-05-30 | 53c3199 | [260530-8uz-make-hardening-power-scan-warnings-hones](.planning/quick/260530-8uz-make-hardening-power-scan-warnings-hones/) |
| 260530-nl4 | feat(claudecode): add `abysslink claudecode disable` command that strips the abysslink notify hooks from ~/.claude/settings.json on demand (Stop + Notification), preserving all other hooks; dry-run default + --apply, writes via internal/audit | 2026-05-30 | 76aa21b | [260530-nl4-add-abysslink-claudecode-disable-command](.planning/quick/260530-nl4-add-abysslink-claudecode-disable-command/) |
| 260602-1nz | fix(init): gate ensureTailscaleAccount huh prompts behind headless flag — thread autoYes → journeyStages() → stage-1 closure → ensureTailscaleAccount(p, headless bool); both init --yes and init with non-TTY stdin now exit 0 | 2026-06-02 | 1af28a4 | [260602-1nz-fix-g1-non-tty-init-errors-on-huh-tty-op](.planning/quick/260602-1nz-fix-g1-non-tty-init-errors-on-huh-tty-op/) |

## Deferred Items

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| v2.x | NetBird posture-check management | Deferred | v2.0.0 roadmap |
| v2.x | Fleet daily digest | Deferred | v2.0.0 roadmap |
| v2.x | Headscale PostgreSQL HA | Deferred | v2.0.0 roadmap |
| v2.x | `netbird events` tail | Deferred | v2.0.0 roadmap |
| v2.x | SCIM | Deferred | v2.0.0 roadmap |
| v3 | Vaultwarden secrets module | Deferred | Roadmap |
| v3 | upsnap, atuin, sandbox, asciinema | Deferred | Roadmap |
| uat | phase-10 HUMAN-UAT (6 pending scenarios) | Deferred | v2.0.0 close 2026-06-02 |
| uat | phase-12 HUMAN-UAT (1 pending scenario) | Deferred | v2.0.0 close 2026-06-02 |
| verification | phase-10 VERIFICATION human_needed | Deferred | v2.0.0 close 2026-06-02 |
| verification | phase-12 VERIFICATION human_needed | Deferred | v2.0.0 close 2026-06-02 |
| quick-task | 4 dangling quick-task slugs (no files on disk; 260526-l51, 260530-8mf/8uz/nl4) | Deferred | v2.0.0 close 2026-06-02 |
| context | phase-11 CONTEXT 3 open questions (answered during planning) | Deferred | v2.0.0 close 2026-06-02 |
| tech-debt | TestUpDryRunParity environment-dependent golden (not a regression) | RESOLVED 2026-06-02 (3cbeb36 — notify.HealthProbe seam; golden now deterministic) | v2.0.0 close 2026-06-02 |
| issue | `init --yes </dev/null` (non-TTY) errors on TTY open instead of degrading gracefully (found in phase-10 UAT self-test; config writes OK, exit 1) | RESOLVED 2026-06-02 (e2cefa9 — headless guard in ensureTailscaleAccount; both init --yes and plain init now exit 0 on non-TTY) | v2.0.0 close 2026-06-02 |

## Session Continuity

Last session: 2026-06-03T08:33:45.406Z
Stopped at: Phase 23 context gathered
Resume file: .planning/phases/23-doctor-honesty-coverage/23-CONTEXT.md
