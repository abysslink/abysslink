# Threat Model

Abysslink's threat model is built around a single primary concern: **your laptop is accessible over the network while you are away from it**. Every default in the system is chosen to minimise the blast radius of a compromise.

## Assets

| Asset | Description |
|-------|-------------|
| Rig disk | Your laptop's filesystem, including source code, credentials, and keys |
| SSH access | Shell access to the rig |
| Tailnet membership | Ability to reach the rig over the mesh VPN |
| ntfy notifications | Push notification channel to your phone |
| Audit log | Record of all changes Abysslink has made |

## Threats and mitigations

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

## Out of scope (v1)

| Threat | Reason deferred |
|--------|----------------|
| Compromised Tailscale control plane | Tailnet Lock partially mitigates; full defense requires headscale (v2+) |
| Side-channel attacks on the rig | Physical security is user's responsibility |
| Compromised phone | Phone compromise is outside Abysslink's control boundary |
| Headscale / NetBird support | Deferred to v2+ |

## Security defaults you must not weaken

The following defaults are **immutable** without explicit user override:

- SSH `checkPeriod` is 12h; can only be lowered, never raised without `--accept-checkperiod-extension`
- Tailnet Lock is on by default; rotation secrets printed once, never stored
- ntfy binds to tailnet IP only, never `0.0.0.0`
- Tailscale Funnel permanently rejected at schema level
- FileVault / LUKS required; `doctor` fails closed if disk is unencrypted
- All destructive commands default to `--dry-run`; `--apply` required

## Reporting security issues

See [SECURITY.md](https://github.com/abysslink/abysslink/blob/main/SECURITY.md) for the responsible disclosure process.
