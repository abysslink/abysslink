---
gsd_state_version: 1.0
milestone: v2.0.0
milestone_name: Self-Hosted Backends & Fleet
status: planning
last_updated: "2026-05-30T19:38:32.738Z"
last_activity: 2026-05-30 — v2.0.0 roadmap created (phases 11-14)
progress:
  total_phases: 14
  completed_phases: 2
  total_plans: 12
  completed_plans: 9
  percent: 14
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-05-30)

**Core value:** `abysslink up` — one command that produces a working, auditable, paranoid-by-default phone-to-laptop remote setup on any macOS or Linux machine
**Current focus:** Milestone v2.0.0 — Phase 11: Backend Abstraction Refactor

## Current Position

Phase: 11 — Backend Abstraction Refactor
Plan: —
Status: Planning (roadmap created; awaiting first plan)
Last activity: 2026-05-30 — v2.0.0 roadmap created (phases 11-14)

```
v2.0.0 progress: [                    ] 0%
Phase 11 of 14 (v2 phases 11-14 = 0/4 complete)
```

## Performance Metrics

**Velocity:**

- Total plans completed: 33 (v1.0.0)
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

## Accumulated Context

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

### Pending Todos

None.

### Blockers/Concerns

- Phase 12 planning: ACME + embedded DERP port interaction needs targeted research sub-task (Caddy/nginx WebSocket forwarding config for DERP alongside Let's Encrypt ACME is MEDIUM confidence)
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

## Session Continuity

Last session: 2026-05-30T19:38:32.732Z
Stopped at: Phase 11 context gathered
Resume file: .planning/phases/11-backend-abstraction-refactor/11-CONTEXT.md
