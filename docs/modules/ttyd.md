# ttyd Module

The ttyd module runs [ttyd](https://github.com/tsl0922/ttyd) — a web terminal in the browser — bound to the tailnet IP only. Optional; disabled by default.

!!! warning "No basic auth — the tailnet ACL is the only access control"
    ttyd has no stdin credential path (only `--credential` on argv, which the
    no-secrets-on-argv rule forbids), so the abysslink-managed ttyd runs
    **without basic auth** and without its own TLS. The tailnet (WireGuard) is
    the encrypted transport and the tailnet ACL is the only access control for
    `tcp/7681`. Never expose this port beyond the tailnet. This trade-off is
    surfaced as a standing doctor warning (`ttyd_no_auth`), not hidden.

## What it configures

`abysslink up --apply` (with the module enabled):

- Installs ttyd via the platform package manager when missing
- Installs a background service (`dev.abysslink.ttyd`) running
  `ttyd -W -i <tailnet-ip> -p 7681 bash`
    - `-i <tailnet-ip>` — binds the tailnet IP only (ttyd's default without
      `-i` is `0.0.0.0`)
    - `-W` — writable terminal (ttyd ≥ 1.7 is read-only by default)

## Configuration

```yaml
modules:
  ttyd:
    enabled: true
```

`enabled` is the only key the schema accepts. The port (7681) is fixed.

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `ttyd_installed` | **fatal** (`doctor` exits 2) |
| `ttyd_no_auth` — standing reminder of the auth trade-off | warning (`doctor` exits 1) |
| `ttyd_bind_tailnet` — a running ttyd process has no `-i` flag (0.0.0.0 default) or is bound to a wildcard/loopback address | warning |

The bind check inspects each running ttyd process's argv, so a ttyd started
manually without `-i` is caught too.

## Commands

```sh
abysslink enable ttyd            # flip modules.ttyd.enabled
abysslink up [--apply]           # install + service bound to the tailnet IP
abysslink doctor                 # verify bind posture
```
