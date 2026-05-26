# Tailscale Module

The Tailscale module manages your tailnet configuration including Tailnet Lock, key expiry, and SSH access control.

## What it configures

- Verifies Tailscale is installed and running
- Enables Tailnet Lock if not already active
- Sets key expiry to the value in `abysslink.yaml` (default: 90 days)
- Disables Tailscale Funnel (permanently blocked at the schema level)
- Verifies the device is registered in the tailnet

## Configuration

```yaml
tailscale:
  tailnet: "my-tailnet.ts.net"
  key_expiry: "90d"
  tailnet_lock: true          # must be true; cannot be disabled without a flag
```

!!! warning "Tailscale Funnel is permanently disabled"
    Abysslink rejects any config that enables Tailscale Funnel. Funnel exposes
    services to the public internet — that is never appropriate for a remote rig.

## Tailnet Lock

Tailnet Lock prevents unauthorized devices from joining your tailnet even if your Tailscale auth key is compromised. Abysslink enables it by default and prints the rotation secret **once** at setup time. The secret is never stored on disk.

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| Tailscale running | `doctor` exits 1 |
| Tailnet Lock enabled | `doctor` exits 1 |
| Key not expired | `doctor` exits 1 |
| Funnel disabled | `doctor` exits 1 |

## Commands

```sh
abysslink status          # show tailscale status
abysslink up [--apply]    # configure tailscale
abysslink doctor          # run all health checks
```
