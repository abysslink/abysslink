# eternal-terminal Module

The eternal-terminal module installs [Eternal Terminal](https://eternalterminal.dev) (ET) — a TCP-based remote shell that survives roaming and reconnects, for networks where mosh's UDP is blocked. Optional; disabled by default.

## What it configures

`abysslink up --apply` (with the module enabled):

- Installs the ET package when either binary (`et` client or `etserver`) is
  missing
- Installs a user-level background service (`dev.abysslink.etserver`) running
  `etserver --port 2022`
    - Linux: `~/.config/systemd/user/dev.abysslink.etserver.service`
    - macOS: `~/Library/LaunchAgents/dev.abysslink.etserver.plist`
- Reminds you to grant `tcp/2022` in the tailnet ACL (plan output)

ET rides on SSH for authentication; access is gated by the tailnet ACL like
every other rig port.

## Configuration

```yaml
modules:
  eternal_terminal:
    enabled: true
```

`enabled` is the only key the schema accepts. The port (2022) is fixed.

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `et_client_installed` — `et` missing | **fatal** (`doctor` exits 2) |
| `et_server_installed` — `etserver` missing | **fatal** (`doctor` exits 2) |
| `et_service_unit_installed` — service unit not installed | warning (`doctor` exits 1) |

## Commands

```sh
abysslink enable eternal-terminal   # flip modules.eternal_terminal.enabled
abysslink up [--apply]              # install + service on tcp/2022
et user@my-rig.tail12345.ts.net     # connect from a tailnet device
```
