# Abysslink Claims Audit

Every verifiable security claim in README.md and docs/ maps to a code file or doctor-check pointer here. Run `bash scripts/claims-check.sh` to validate all pointers resolve.

---

## Claims Register

| # | Claim (exact quote) | Source | Code Pointer | Status |
|---|---|---|---|---|
| C-01 | "ntfy binds exclusively to the tailnet IP (never `0.0.0.0`)" | README §Notifications | `internal/modules/ntfy/module.go` + `doctor:ntfy-bind` | ✓ |
| C-02 | "`abysslink doctor` exits `2` (fatal) if FileVault (macOS) / LUKS (Linux) is off" | README §Security hardening | `internal/modules/hardening/module.go` + `doctor:disk-encryption` | ✓ |
| C-03 | "audit log stores diff hashes only; no secrets on argv" | README §Threats & mitigations | `internal/audit/audit.go` | ✓ |
| C-04 | "Funnel rejected at the schema level; listeners never bind `0.0.0.0`" | README §Threats & mitigations | `internal/config/config.go` | ✓ |
| C-05 | "the push payload carries only routing metadata — no body, no secrets, no code" | README §Notifications | `internal/notifyv2/message.go` + `internal/push/gateway.go` | ✓ |
| C-06 | "every mutation is backed up and recorded in a hash-chained, optionally-signed audit log" | README §Safety & auditability | `internal/audit/audit.go` | ✓ |
| C-07 | "SSH re-check period (`checkPeriod`) that can be lowered but never silently raised" | README §Networking & access | `internal/modules/ssh/module.go` | ✓ |
| C-08 | "Tailnet Lock by default — every device that joins must be cryptographically signed" | README §Networking & access | `internal/modules/lock/module.go` | ✓ |
| C-09 | "Secrets are read from stdin or the OS keychain; the audit log records titles and diff hashes only" | README §Security hardening | `internal/audit/audit.go` + `internal/cli/cmd_panic.go` | ✓ |
| C-10 | "`abysslink panic` tears down the VPN session, revokes the phone's auth key, and destroys the local API key" | README §Security hardening | `internal/cli/cmd_panic.go` | ✓ |
| C-11 | "The binary makes no outbound calls except to your VPN's local API and your own ntfy server" | README §Design philosophy | `doctor:no-telemetry` | ✓ |
| C-12 | "SLSA provenance on every release" | README §Installation | `.github/workflows/release-build.yml` | ✓ |
| C-13 | "cosign signature + SLSA provenance verified on install/upgrade" | README §Threats & mitigations | `.github/workflows/release.yml` | ✓ |
| C-14 | "HMAC-chained backup on every file mutation" | README §Safety & auditability | `internal/audit/backup.go` | ✓ |
| C-15 | "topic entropy >= 128 bits" | docs/security.md + REQUIREMENTS | `internal/config/topic_entropy.go` | ✓ |
| C-16 | "agent kill-switch ships in shadow mode by default" | README §Safety & auditability | `internal/modules/budget/module.go` | ✓ |
| C-17 | "Disablement secrets are printed once to stdout and never written to disk" | README §Networking & access | `internal/modules/lock/module.go` | ✓ |
| C-18 | "Every mutation is backed up and recorded — nothing calls `os.WriteFile` outside `internal/audit`" | README §Design philosophy | `internal/audit/write.go` | ✓ |
