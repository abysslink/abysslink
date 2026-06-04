# Milestones

## v3.0.1 Network & Dependency Security Hotfix (Shipped: 2026-06-04)

**Phases completed:** 7 phases (22, 23, 23.1, 23.2, 24, 25, 26), 29 plans
**Requirements:** 20/20 verified (+ 5/5 Phase 26 phase-internal) · **Audit:** PASSED (incremental Phase 26 audit 2026-06-04) · **Tag:** `v3.0.1`

> Note: Phase 26 executed post-ship under this milestone; its 17 commits land **after** the pushed `v3.0.1` tag (left in place) and will ship in the next release tag.

**Key accomplishments:**

- **Network/dependency lockdown (NET-01/02/03, DEP-01/02/03):** ntfy tailnet-only bind enforced; NetBird `server_url` https-only at `config.Validate`; hostname/server_url argv-injection guards; go1.26.4 toolchain, x/crypto ≥ v0.52.0, CSRF migrated off gorilla to `net/http.CrossOriginProtection`.
- **Doctor/threat-model honesty (DOC-01..10):** one shared `collectDoctorFindings` set; fail-closed disk-encryption (FATAL → exit 2); unconditional nb-lock warning; minimum-versions table (ntfy ≥ 2.21 FATAL); probe-failure tri-state for funnel/serve/metrics listeners; ntfy IPv6 wildcard; no double-emit.
- **Tamper-evident audit hardening (AUD-01/02):** backups bound to the HMAC chain; anchor-every-append + keychain entry counter; cross-process flock + single anchor/counter refresh per write; direction-aware `verifyCounter` (no false truncation alarm on the append-before-write window).
- **DoS bounding (DOS-01):** every attacker-influenceable read bounded — `limitio.ReadLimited`/`ReadSnippet` across CLI + backends; binary installs stream via `WriteFilePath` (256 MiB ceiling) instead of full-file reads.
- **CI gate (CI-01):** `govulncheck ./...` is a blocking CI gate; lint/test workflows SHA-pinned + harden-runner.
- **Config fail-closed (phase 25):** `config.Load` now validates before returning; read-only `rig ls`/`export` degrade gracefully via `LoadForRead`.
- **Gated init journey (phase 26, post-ship):** `abysslink init` is a genuinely gated 8-stage wizard — per-stage confirm gates, offer-to-run in stages 3–7 (`up --apply` / `lock init --apply` / `enroll phone` / `doctor` / new ACL stage), three first-run bugs fixed (openURL probe → `shell.LookPath`, Stage 2 autoYes duplication, pmset annotated-output parse), sudo via `RunInteractive` (one password per run, tty credential-cache reuse), power short-circuit, terminal-state restore before child spawn. Headless `--yes`/`--json`/non-TTY stay non-blocking. Verification 25/25, human UAT approved, CR-01/WR-01..05 review findings fixed.

**Code review + verification:** 2 Critical + 7 Warning audit-core findings fixed and merged; 4 verification human-items converted to automated tests (counter-direction crash window, WriteFilePath race parity, rig-ls degradation, NetBird root-UID refusal). Full gate + `-race` green.

**Known deferred items at close:** 1 genuine (Phase 23 FileVault mid-encryption `fdesetup` string literals — real-hardware confirmation, fail-closed regardless) + 5 stale historical quick-task slugs. At Phase 26 fold-in: 2 acknowledged items (26-UAT scenarios 2–6 covered by re-verification + HUMAN-UAT pass; 26-VERIFICATION human_needed closed by HUMAN-UAT user approval). See STATE.md Deferred Items.

---
