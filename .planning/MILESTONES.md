# Milestones

## v3.0.1 Network & Dependency Security Hotfix (Shipped: 2026-06-04)

**Phases completed:** 6 phases (22, 23, 23.1, 23.2, 24, 25), 26 plans
**Requirements:** 20/20 verified · **Audit:** PASSED · **Tag:** `v3.0.1`

**Key accomplishments:**

- **Network/dependency lockdown (NET-01/02/03, DEP-01/02/03):** ntfy tailnet-only bind enforced; NetBird `server_url` https-only at `config.Validate`; hostname/server_url argv-injection guards; go1.26.4 toolchain, x/crypto ≥ v0.52.0, CSRF migrated off gorilla to `net/http.CrossOriginProtection`.
- **Doctor/threat-model honesty (DOC-01..10):** one shared `collectDoctorFindings` set; fail-closed disk-encryption (FATAL → exit 2); unconditional nb-lock warning; minimum-versions table (ntfy ≥ 2.21 FATAL); probe-failure tri-state for funnel/serve/metrics listeners; ntfy IPv6 wildcard; no double-emit.
- **Tamper-evident audit hardening (AUD-01/02):** backups bound to the HMAC chain; anchor-every-append + keychain entry counter; cross-process flock + single anchor/counter refresh per write; direction-aware `verifyCounter` (no false truncation alarm on the append-before-write window).
- **DoS bounding (DOS-01):** every attacker-influenceable read bounded — `limitio.ReadLimited`/`ReadSnippet` across CLI + backends; binary installs stream via `WriteFilePath` (256 MiB ceiling) instead of full-file reads.
- **CI gate (CI-01):** `govulncheck ./...` is a blocking CI gate; lint/test workflows SHA-pinned + harden-runner.
- **Config fail-closed (phase 25):** `config.Load` now validates before returning; read-only `rig ls`/`export` degrade gracefully via `LoadForRead`.

**Code review + verification:** 2 Critical + 7 Warning audit-core findings fixed and merged; 4 verification human-items converted to automated tests (counter-direction crash window, WriteFilePath race parity, rig-ls degradation, NetBird root-UID refusal). Full gate + `-race` green.

**Known deferred items at close:** 1 genuine (Phase 23 FileVault mid-encryption `fdesetup` string literals — real-hardware confirmation, fail-closed regardless) + 5 stale historical quick-task slugs. See STATE.md Deferred Items.

---
