# Tailscale Module

The Tailscale module manages the rig's tailnet membership: installation, login, Tailscale SSH, hostname, and public-exposure checks.

## What it configures

- Installs Tailscale via the platform package manager when missing
- Runs `tailscale login` (interactive browser SSO) when the node needs auth,
  or `tailscale up` to reconnect a stopped daemon
- Enables Tailscale SSH via `tailscale set --ssh` (incremental — never
  re-states your other flags)
- Enables auto-update (best-effort; unsupported on some builds)
- Sets the MagicDNS hostname when `tailnet.hostname` differs from the current one
- Verifies **no public exposure**: an active Tailscale Funnel is a fatal doctor
  finding; an active Serve is a warning

!!! warning "Tailscale Funnel is permanently rejected"
    There is no `funnel:` key in the config schema, and the strict YAML decoder
    rejects any config that contains one. Funnel exposes services to the public
    internet — that is never appropriate for a remote rig. If Funnel is found
    *active* on the node, `abysslink doctor` fails closed (exit 2).

## Configuration

The module reads the top-level `tailnet:` block:

```yaml
tailnet:
  hostname: "my-rig"          # MagicDNS hostname (optional)
  ssh: true                   # enable Tailscale SSH (default: true)
  lock:
    enabled: true             # require Tailnet Lock (default: true)
    disablement_secrets: 2    # secrets generated at lock init (default: 2)
    share_with_support: false
  admin:
    tailnet: "you@github"     # admin-API tailnet name (optional)
    oauth_client_id: "..."    # NOT secret; the secret comes from env/keychain
```

## Tailnet Lock

Tailnet Lock prevents unauthorized devices from joining your tailnet even if
your Tailscale auth key is compromised. It is required by default
(`tailnet.lock.enabled: true`), but it is **never enabled automatically** —
initialization prints disablement secrets that you must record before closing
the terminal, so it is an explicit interactive step:

```sh
abysslink lock init --apply
```

This wraps `tailscale lock init` and prints the **disablement secrets once**;
they are never stored on disk. Save them in a password manager *and* on paper —
they are the only way to turn lock off later. `abysslink lock rotate` prints
guidance for rotating them. While lock is required but not yet enabled,
`abysslink up --apply` stops with an actionable error rather than silently
claiming success.

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `installed` — tailscale on PATH | **fatal** (`doctor` exits 2) |
| `running` / `needs_login` — daemon state | warning (`doctor` exits 1) |
| `ssh` — Tailscale SSH not enabled | warning |
| `ssh_sandboxed` — sandboxed macOS GUI build can't run the SSH server | warning |
| `funnel` — Funnel active | **fatal** (`doctor` exits 2) |
| `funnel-probe-fail` — Funnel state could not be determined | warning |
| `serve` — Tailscale Serve active | warning |
| `serve-probe-fail` — Serve state could not be determined | warning |
| `lock_enabled` (lock module) — lock required by config but off | warning |
| `lock_disabled` (lock module) — lock disabled in config *and* off | warning |

There is no key-expiry check — Abysslink does not manage Tailscale key expiry.

## Commands

```sh
abysslink status              # show tailscale status
abysslink up [--apply]        # install/login/enable SSH/set hostname
abysslink doctor              # run all health checks
abysslink lock status         # report Tailnet Lock state
abysslink lock init --apply   # initialise Tailnet Lock (prints secrets once)
```
