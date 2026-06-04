# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v3.0.1 — Network & Dependency Security Hotfix

**Shipped:** 2026-06-04 (tag) · re-closed 2026-06-04 with post-ship Phase 26 fold-in
**Phases:** 7 (22, 23, 23.1, 23.2, 24, 25, 26) | **Plans:** 29

### What Was Built
- Network/dependency lockdown: ntfy tailnet-only bind, NetBird https-only `server_url`, argv-injection guards, go1.26.4 / x/crypto v0.52.0 / CSRF → `net/http.CrossOriginProtection`
- Doctor/threat-model honesty: shared finding set, fail-closed disk encryption, probe-failure tri-state (no false-OK on unproven probes), minimum-versions table, no double-emit
- Tamper-evident audit hardening: HMAC-chained backups, anchor-every-append + keychain counter, cross-process flock, direction-aware `verifyCounter`
- DoS bounding (`limitio` + `WriteFilePath` streaming) and a blocking `govulncheck` CI gate
- Phase 26 (post-ship): gated 8-stage init journey, sudo via `RunInteractive` (single password per run), terminal-state restore, three first-run bug fixes

### What Worked
- Incremental milestone audit (phases 22–25 archived audit + Phase 26 incremental audit with explicit `supersedes`) kept the re-close honest without re-auditing shipped work
- Gap-closure plan pattern (26-03 spawned directly from UAT blocker report) turned a vague "multiple passwords / stuck phase" report into three verified fixes in one session
- Code-review → fix loop caught CR-01/WR-01..05 after the phase looked done; review-after-verification continues to pay off
- Probe-failure tri-state pattern (OK / not-OK / unknown→Warning) established in 23.1 transferred directly to 23.2 and the pmset three-state parse in Phase 26

### What Was Inefficient
- Phase 26 executed after the v3.0.1 tag was pushed — milestone had to be re-closed and archives rewritten; the tag no longer matches the milestone records (17 commits post-tag)
- Stray `phases/22-network-dependency-lockdown/` PLAN-only dir survived the first close and had to be cleaned up at re-close
- UAT scenarios 2–6 were never individually exercised; coverage came indirectly via re-verification + HUMAN-UAT — fine in substance, but the artifacts disagreed with reality and tripped the close audit

### Patterns Established
- Probe-failure honesty: a doctor/threat-model check never renders ✓ for a control whose backing probe could not run
- Privileged sudo calls route through `RunInteractive` so the real tty backs the credential cache (one password per run)
- `cterm.GetState/Restore` sandwich around huh forms before spawning interactive children
- `journeyOfferRun`: non-fatal offer-to-run gate per journey stage; headless paths self-guard on `yes || !stdinIsTTY()`

### Key Lessons
1. Tag only after the milestone is genuinely closed — post-tag phases force a re-close and leave the tag pointing mid-milestone
2. When a HUMAN-UAT supersedes pending UAT scenarios, update the older artifact's status immediately; stale `[pending]` rows resurface at milestone close
3. Real-tty behaviours (sudo cache, raw-mode transitions) cannot be mock-verified — budget a human UAT pass for any interactive-terminal phase

### Cost Observations
- Model mix: not tracked
- Sessions: ~3 (Phase 26 plan/execute, gap closure + review fixes, milestone re-close)
- Notable: incremental audit avoided re-running the full 11-agent security audit for a 3-plan fold-in

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Key Change |
|-----------|--------|-------|------------|
| v1.0.0 | 10 | ~101 | Single-session bootstrap of the full v1 surface |
| v2.0.0 | 4 | 18 | Backend abstraction + fleet; deferred-items table introduced at close |
| v3.0.0 | 6 | 24 | Security audit pass became a phase; opt-in listeners pattern locked in |
| v3.0.1 | 7 | 29 | Incremental milestone audit for post-ship fold-in; probe-failure tri-state pattern |

### Cumulative Quality

| Milestone | Audit | Deferred at close |
|-----------|-------|-------------------|
| v2.0.0 | PASSED | 8 items (UAT/verification/quick-task) |
| v3.0.0 | PASSED (3 integration gaps closed) | live-env HUMAN-UAT |
| v3.0.1 | PASSED (+ incremental Phase 26) | 1 genuine (FileVault fdesetup literals) + 2 acknowledged Phase 26 artifact items |
