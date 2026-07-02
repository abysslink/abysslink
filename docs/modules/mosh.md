# mosh Module

The mosh module configures [mosh](https://mosh.org) as a more resilient alternative to SSH for mobile connections with unstable or high-latency networks.

## What it does

mosh uses UDP and a persistent server process to maintain the connection state. If your phone switches from WiFi to cellular, mosh reconnects automatically without dropping your session.

## What Abysslink configures

`abysslink up --apply`:

- Installs mosh when missing
- Makes `mosh-server` actually reachable — the two host-level gaps that
  otherwise produce "No response from Mosh server" at connect time:
    - **PATH (macOS):** Homebrew's bin dir is absent from the non-login PATH
      that Tailscale-SSH-spawned shells use, so `mosh-server` is "not found".
      The module symlinks it onto the system PATH.
    - **Firewall:** allows `mosh-server` through the macOS Application
      Firewall, and opens UDP 60000–61000 in an active Linux host firewall.

All steps are check-then-act and idempotent. `abysslink uninstall` removes the
PATH symlink and the Linux UDP rule; the macOS app-firewall allow is left in
place (it stores the resolved binary path, so precise removal isn't possible —
an extra allowed binary is inert).

The UDP port range **60000–61000** is compiled in and not configurable; it
matches the default `mobile.ports` ACL grant (`udp/60000-61000`).

## Configuration

```yaml
modules:
  mosh:
    enabled: true
```

`enabled` is the only key the schema accepts.

## Tailscale and mosh

mosh works over Tailscale. Connect with:

```sh
mosh user@my-rig.tail12345.ts.net
```

The mosh connection travels through your tailnet — it never touches the public internet.

## `abysslink doctor` checks

All mosh checks are **warnings** (`doctor` exits 1):

| Check | Meaning |
|-------|---------|
| `installed` | mosh-server not installed or not on PATH |
| `mosh_path` (macOS) | mosh-server not on the non-login system PATH — mosh over Tailscale SSH fails with "No response from Mosh server" |
| `mosh_firewall` | mosh-server blocked by the macOS Application Firewall, or UDP 60000–61000 closed in an active Linux firewall |

## Commands

```sh
abysslink up [--apply]   # install mosh + PATH link + firewall allow
abysslink doctor         # verify install + reachability
```
