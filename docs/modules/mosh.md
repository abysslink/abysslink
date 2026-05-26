# mosh Module

The mosh module configures [mosh](https://mosh.org) as a more resilient alternative to SSH for mobile connections with unstable or high-latency networks.

## What it does

mosh uses UDP and a persistent server process to maintain the connection state. If your phone switches from WiFi to cellular, mosh reconnects automatically without dropping your session.

## What Abysslink configures

- Verifies mosh is installed on the rig
- Confirms the required UDP ports (60000–61000) are not blocked by the local firewall
- Adds a mosh server startup to the session bootstrap if `enable: true`

## Configuration

```yaml
mosh:
  enable: true
  udp_port_range: "60000-61000"
```

## Tailscale and mosh

mosh works over Tailscale. Connect with:

```sh
mosh --ssh="ssh -i ~/.ssh/my-rig" user@my-rig.tail12345.ts.net
```

The mosh connection travels through your tailnet — it never touches the public internet.

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| mosh installed (if enabled) | `doctor` exits 1 |
| UDP ports reachable | warning |

## Commands

```sh
abysslink up [--apply]   # configure mosh
abysslink doctor         # verify mosh availability
```
