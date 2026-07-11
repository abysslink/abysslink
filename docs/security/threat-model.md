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
| Stale SSH session left open | Tailscale SSH ACL `checkPeriod 12h` forces periodic re-authentication (openssh-fallback mode has no equivalent control) |
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
| Content store / credential pull exposed to internet | Hard floor: the content listener binds the tailnet IP only; `0.0.0.0`/`::` rejected by `config.ValidateContentStore` and re-checked at the listener seam (fail closed — no listener if the bind cannot be confirmed as the tailnet IP) |
| Bearer-less first-contact credential pull abused (`GET /enroll/{token}`) | The phone has no bearer at first contact, so the capability is a high-entropy (≥128-bit) single-use token carried only in the QR'd URL (operator screen → phone camera): consumed on first success (a second fetch 404s), a short separate TTL (`content_store.enroll_ttl_seconds`, default 300s), tailnet-only TLS bind. It is a distinct capability class from `/content` — a bearer-less `/enroll` fetch can never read a bearer-gated message body. The staged bundle lives only in transient daemon memory (never on disk); the URL, token, and bundle never appear in any log |

## Backend: Tailscale

### Trust Assumptions

- Control plane: Tailscale SaaS (trusted by default); mitigated by Tailnet Lock.
- Tailnet Lock: required by default; disablement secrets printed once, never stored.
- ACL policies: enforced by Tailscale control plane; `abysslink acl push --apply` pushes via admin API.

### Threat Rows (Tailscale-specific)

| Threat | Check | Severity |
|--------|-------|----------|
| Tailnet Lock disabled | lock_enabled | WARN (exit 1) |
| ACL policy drift | acl_drift | WARN |
| Tailscale Funnel accidentally enabled | sec-funnel-schema | FATAL |
| New device joins without signing | lock_enabled | WARN (exit 1) |

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

## v4 New Surfaces

The security sweep (`abysslink doctor`, or the full suite via `abysslink audit verify --pentest`) also runs these `sec-*` checks:

| Surface | Check | Severity |
|---------|-------|----------|
| Audit log missing / unreadable | sec-audit-log-exists | FATAL |
| Audit HMAC key-epoch health — a half-finished `rotate audit-hmac` (chain epoch ahead of the keychain pointer) makes appends fail closed | sec-audit-epoch | WARN (FATAL under `--profile at-risk`) |
| Secret-memory locking (mlock / SecureBytes, MEM-02) — defense-in-depth; the unlocked fallback still zeroizes on free | sec-mlock | WARN (never FATAL — a kernel `RLIMIT_MEMLOCK` the operator can't raise must not fail closed) |
| Disk encryption (FileVault / LUKS) off | sec-disk-encryption | FATAL (always — off or mid-encryption fails closed in every profile) |
| Listener bound to a non-tailnet / wildcard address | sec-listener-bind | FATAL |
| Daemon control-socket permissions | sec-daemon-socket-perms | FATAL |
| Installed binary cosign signature | sec-binary-signed | WARN |
| Self-update SLSA provenance verified | sec-upgrade-verified | WARN |
| Duress decoy enabled but inert (no keychain-stored decoy credential) | sec-duress | FATAL (inert) / WARN if the keychain cannot be reached to confirm (FATAL under `--profile at-risk`) |

`sec-mlock` and `sec-audit-epoch` remediation is covered in [Troubleshooting](../operations/troubleshooting.md#abysslink-doctor-failures); the audit-key rotation model behind `sec-audit-epoch` is described in [Hardening → Audit HMAC key rotation](hardening.md#audit-hmac-key-rotation).

## Duress decoy — what it defends, and what it deliberately does not

The duress decoy (opt-in, ships OFF) defends against **casual coercion**: the shoulder-glance, the border-guard or checkpoint officer who hands you your unlocked laptop and says "show me," the roommate who grabs the terminal. In that moment you enter the **decoy** credential instead of your real one. Two things happen at once: you are shown a **benign, plausible rig view** (a quiet machine with no fleet and no live sessions), and — the part that makes it real rather than cosmetic — your actual session is **degraded for real** through the same kill-switch the dead-man lockdown uses: armed agents are frozen and killed, and a persisted lockdown latch is set so nothing silently re-arms behind the decoy. The honest value is measured in **seconds to minutes**: it buys you the time and the cover story to hand over a device that looks empty while your real capability is already being torn down.

**It is NOT plausible deniability against a forensic adversary, and we do not pretend otherwise.** Your `abysslink.yaml` carries a `duress:` stanza, so anyone who images the disk learns the feature exists and is configured; `strings`, the audit log, the state dir, and backups can establish that a real fleet was present. This is the same lesson VeraCrypt hidden volumes keep teaching: the cryptography can be sound and the deniability still collapses on **behavior and system traces**. A determined examiner with the disk and time **will** find the real configuration. We claim nothing against that adversary — **full-disk encryption (FileVault / LUKS, enforced fail-closed by `abysslink doctor`) is the real at-rest control**, not the decoy. Concretely, two traces are left on activation and are out of scope by design: the persisted lockdown latch and audit entry carry a duress-specific reason (`session-degraded`), so a forensic reader can tell a duress activation from a routine dead-man timeout; and if a real fleet was armed, the decoy unlock spends a little longer tearing it down than a real idle unlock, so an adversary timing the command (not the *screen* — the benign view renders with the same latency, and the degradation runs silently) could infer that activity occurred. Neither is defended against: the threat model is the person glancing at your screen, not the lab with your disk and a stopwatch.

**We deliberately refuse to build a destructive duress-wipe.** For casual coercion a wipe is the wrong trade on three counts: it is **security theater** (a wiped device under coercion is itself loud evidence of intent, and the forensic adversary defeats it anyway), a **self-DoS** (a mistyped or shoulder-surfed decoy credential irreversibly destroys your own working state with no undo), and **detectable** (a blank or shutting-down device mid-inspection is exactly the tell a coercer notices). So there is, **by design and by test** (`internal/duress/nowipe_test.go`), **no code path in the duress feature that deletes or overwrites real data.** The decoy is pure read-substitution plus a real, **reversible** kill-switch degradation.

## Out of Scope

| Threat | Reason deferred |
|--------|----------------|
| Compromised Tailscale control plane | Tailnet Lock partially mitigates; self-hosted Headscale / NetBird remove the SaaS control plane from the trust boundary |
| Side-channel attacks on the rig | Physical security is the user's responsibility |
| Compromised phone | Phone compromise is outside Abysslink's control boundary |

## Security Defaults You Must Not Weaken

The following defaults are **immutable** without explicit user override:

- SSH `checkPeriod` is 12h; can only be lowered, never raised without `--accept-checkperiod-extension`
- Tailnet Lock is on by default; disablement secrets printed once, never stored
- ntfy binds to tailnet IP only, never `0.0.0.0`
- Tailscale Funnel permanently rejected at schema level
- FileVault / LUKS required; `doctor` fails closed if disk is unencrypted
- All destructive commands default to `--dry-run`; `--apply` required
- The duress decoy is non-destructive: no destructive duress-wipe exists, and duress credentials live only as keychain digests, never in config

## Reporting Security Issues

See [SECURITY.md](https://github.com/abysslink/abysslink/blob/main/SECURITY.md) for the responsible disclosure process.
