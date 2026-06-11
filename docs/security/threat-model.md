# Abysslink Threat Model

Abysslink's threat model is built around a single primary concern: **your laptop is accessible over the network while you are away from it**. Every default in the system is chosen to minimise the blast radius of a compromise.

As of v3.0.0, the threat surface has expanded to include per-backend trust models (Tailscale, Headscale, NetBird), a multi-rig fleet, and three new in-process surfaces (metrics endpoint, Web UI dashboard, tamper-evident audit chain).

## Assets

| Asset | Description |
|-------|-------------|
| Rig disk | Your laptop's filesystem, including source code, credentials, and keys |
| SSH access | Shell access to the rig |
| Tailnet membership | Ability to reach the rig over the mesh VPN |
| ntfy notifications | Push notification channel to your phone |
| Audit log | Record of all changes Abysslink has made |
| Metrics endpoint | Prometheus-format exposition; must be tailnet-scoped |
| Web UI dashboard | In-process HTTPS server; must be tailnet-scoped + WhoIs-authenticated |
| Audit signing key | HMAC key in OS keychain; controls audit chain integrity |
| Per-rig enrolled keys | Fleet enrolment tokens in keychain |

## Threats and Mitigations (Base)

| Threat | Mitigation |
|--------|-----------|
| Network attacker on the same network as the rig | Tailscale WireGuard encryption; services bind to tailnet IP only |
| Compromised Tailscale auth key | Tailnet Lock — new devices require signing by existing trusted key |
| SSH brute force | `PasswordAuthentication no`; public-key only; `checkPeriod 12h` |
| Stale SSH session left open | `ClientAliveInterval` + `ClientAliveCountMax` enforce session termination |
| ntfy exposed to internet | Hard enforced: ntfy binds to tailnet IP only; `0.0.0.0` rejected |
| Disk theft | FileVault (macOS) / LUKS (Linux) required — `doctor` fails if unencrypted |
| Tailscale Funnel accidentally enabled | Rejected at YAML schema level; cannot be configured |
| Secret leakage via audit log | Audit log records diff hash only, never content |
| Secret leakage via command line | No secrets on argv; read from env or stdin |
| Malicious shell injection via hooks | Hooks use `exec` with argv; no `sh -c` |
| Tampered release binary | SHA-256 checksum + cosign keyless signature verification on install |
| Metrics endpoint exposed to internet | `doctor` FATAL on 0.0.0.0/:: bind_addr (sec-metrics-bind); hard floor in config.Validate |
| Web UI exposed to internet or unauthenticated | `doctor` FATAL on 0.0.0.0/:: bind_addr (sec-webui-bind); WhoIs auth gate in handler; read_only:false rejected at schema level |
| Audit log tampered or truncated | HMAC-signed entries; anchor-age WARN after 24h; chain integrity checked by `abysslink audit verify` |

## Backend: Tailscale

### Trust Assumptions

- Control plane: Tailscale SaaS (trusted by default); mitigated by Tailnet Lock.
- Tailnet Lock: required by default; disablement secrets printed once, never stored.
- ACL policies: enforced by Tailscale control plane; `abysslink acl push --apply` pushes via admin API.

### Threat Rows (Tailscale-specific)

| Threat | Check | Severity |
|--------|-------|----------|
| Tailnet Lock disabled | lock_enabled | FATAL |
| ACL policy drift | acl_drift | WARN |
| Tailscale Funnel accidentally enabled | sec-funnel-schema | FATAL |
| New device joins without signing | lock_enabled | FATAL |

## Backend: Headscale

### Trust Assumptions

- Self-hosted: the operator controls the control plane; standard TLS + OIDC is the auth boundary.
- Tailnet Lock: absent on Headscale — permanent doctor WARN (hs-lock), not FATAL (per v2 decision).
- OIDC filter: misconfigured OIDC policy allows unintended users to join the tailnet.

### Threat Rows (Headscale-specific)

| Threat | Check | Severity |
|--------|-------|----------|
| Headscale API served without TLS | hs-tls | FATAL |
| Headscale API key unauthenticated | hs-api-auth | FATAL |
| No Tailnet Lock equivalent on Headscale | hs-lock | WARN (permanent) |
| OIDC allow-list misconfigured | hs-oidc-filter | WARN |

## Backend: NetBird

### Trust Assumptions

- Self-hosted: ZITADEL is the IdP; NetBird management API requires a valid management token.
- No Tailnet Lock equivalent — permanent doctor WARN (nb-lock).
- Version gate: nb-version check enforces minimum compatible server version.

### Threat Rows (NetBird-specific)

| Threat | Check | Severity |
|--------|-------|----------|
| NetBird management API without TLS | nb-tls | FATAL |
| NetBird server version below minimum | nb-version | WARN |
| ZITADEL admin token misconfigured | nb-zitadel | WARN |
| No Tailnet Lock equivalent on NetBird | nb-lock | WARN (permanent) |

## Fleet Threat Surface

| Threat | Mitigation |
|--------|-----------|
| Cross-rig ACL drift (one rig not in the same policy) | fleet doctor fan-out; per-rig acl_drift check |
| Rig key uniqueness (same SSH key across rigs) | enroll-rig generates per-rig key; doctor warns on shared keys |
| Fleet command lateral movement | fleet fan-out requires --apply; doctor --all-rigs is read-only |
| Stale rig token in keychain | keychain rotation check; periodic rig re-enrolment |

## v3 New Surfaces

| Surface | Check | Severity |
|---------|-------|----------|
| Metrics endpoint bind floor | sec-metrics-bind | FATAL |
| Web UI bind floor | sec-webui-bind | FATAL |
| Web UI read-only gate | webui-read-only | FATAL |
| Audit chain integrity | sec-audit-anchor-age | WARN (> 24h) |
| Audit log permissions | sec-audit-log-perms | FATAL (mode ≠ 0600) |
| Config file world-readable | sec-no-world-readable-config | FATAL |

## Out of Scope

| Threat | Reason deferred |
|--------|----------------|
| Compromised Tailscale control plane | Tailnet Lock partially mitigates; self-hosted Headscale / NetBird remove the SaaS control plane from the trust boundary |
| Side-channel attacks on the rig | Physical security is the user's responsibility |
| Compromised phone | Phone compromise is outside Abysslink's control boundary |

## Security Defaults You Must Not Weaken

The following defaults are **immutable** without explicit user override:

- SSH `checkPeriod` is 12h; can only be lowered, never raised without `--accept-checkperiod-extension`
- Tailnet Lock is on by default; rotation secrets printed once, never stored
- ntfy binds to tailnet IP only, never `0.0.0.0`
- Tailscale Funnel permanently rejected at schema level
- FileVault / LUKS required; `doctor` fails closed if disk is unencrypted
- All destructive commands default to `--dry-run`; `--apply` required

## Reporting Security Issues

See [SECURITY.md](https://github.com/abysslink/abysslink/blob/main/SECURITY.md) for the responsible disclosure process.
