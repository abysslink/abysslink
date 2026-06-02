# Security

Landing page for Abysslink's security posture. For **reporting a vulnerability**, see [SECURITY.md](../SECURITY.md) (private disclosure, 90-day coordinated window, CVE coordination available).

- **Full threat model:** [security/threat-model.md](security/threat-model.md)
- **OS hardening guide:** [security/hardening.md](security/hardening.md)

## Threat model summary

Abysslink defends the path from a phone to a development rig over a hostile network, assuming the phone may be lost or stolen. It does **not** replace endpoint security on a fully-compromised laptop, and it does not audit the upstream tools (Tailscale, mosh, ntfy) it orchestrates — it configures them safely.

| Threat | Mitigation |
|---|---|
| Stolen phone | Revocable device keys (Tailnet Lock); `abysslink panic` revokes immediately. |
| Stolen laptop | Disk encryption enforced (doctor fails closed); ntfy/webui/metrics bind tailnet-only. |
| Compromised VPN account | Tailnet Lock — a rogue node cannot join without your signing key. |
| Secrets leaked via logs | Audit log stores diff hashes only; no secrets on argv; doctor scans for leaks. |
| Accidental public exposure | Funnel rejected at the config schema; listeners never bind `0.0.0.0`. |
| Supply-chain tampering | Reproducible builds; cosign signature + SLSA provenance verified on install/upgrade. |
| Injection via notification | ntfy is receive-only on the phone — no command-execution path back to the rig. |
| Unencrypted disk | `abysslink doctor` exits `2` (fatal). |

Run `abysslink threat-model` to print this table with the live ✓/✗ status of each defense on your machine.

## Guarantees

- **No public internet exposure.** All listeners bind to the tailnet IP; Tailscale Funnel is rejected at the YAML schema level.
- **No secrets on the command line or in logs.** Secrets are read from stdin or the OS keychain; the audit log records titles and diff hashes only.
- **Every mutation is backed up and recorded** in a hash-chained, optionally-signed audit log, and is reversible via `abysslink backup restore` / `abysslink uninstall`.
- **Dry-run by default.** Nothing is mutated without an explicit `--apply`.
- **Signed, reproducible binaries.** Verify with `abysslink verify` or `cosign verify-blob`.

## Explicit non-goals

- Protecting a laptop whose OS is already compromised (rootkit, malicious local user).
- Hardening the phone-side terminal app or the phone's OS.
- Auditing the security of Tailscale / Headscale / NetBird / mosh / ntfy themselves.
- Anonymity or traffic-shape obfuscation — Abysslink is about access control, not anti-surveillance.

## Supported versions

| Version | Supported |
|---|---|
| `v1.x` | ✅ |
| `< v1.0` | ❌ |

## CI security gates

Every change runs through `make lint` (golangci-lint incl. gosec + nolintlint), a standalone gosec pass with a single canonical exclude set, and semgrep (`p/r2c-security-audit`, `p/golang`). Releases are reproducibility-checked ([repro-check workflow](../.github/workflows/repro-check.yml)) and fuzz-tested ([fuzz workflow](../.github/workflows/fuzz.yml)).
