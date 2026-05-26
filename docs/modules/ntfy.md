# ntfy Module

The ntfy module runs a self-hosted [ntfy](https://ntfy.sh) notification server on your rig and configures it to send push notifications to your phone.

## Security: tailnet-IP binding

!!! danger "ntfy must never bind to 0.0.0.0"
    Abysslink enforces that ntfy binds **only** to your Tailscale tailnet IP address.
    Binding to `0.0.0.0` or a public IP would expose your notification server to
    the internet. `abysslink doctor` fails closed if this check fails.

The listen address is derived automatically from `tailscale ip --1` at startup.

## What it configures

- Installs and starts ntfy (via system service manager or Docker)
- Writes `/etc/ntfy/server.yml` with:
  - `listen-http: "<tailnet-ip>:2586"`
  - `base-url: "http://<tailnet-ip>:2586"`
  - Authentication disabled (tailnet membership is the auth boundary)
- Creates a default topic named `abysslink`

## Configuration

```yaml
ntfy:
  port: 2586
  topic: "abysslink"
  # listen_ip is derived from tailscale at runtime; do not set manually
```

## Phone setup

Install the ntfy app on your phone ([Android](https://play.google.com/store/apps/details?id=io.heckel.ntfy), [iOS](https://apps.apple.com/app/ntfy/id1625396347)) and subscribe to:

```
http://<your-rig-tailnet-ip>:2586/abysslink
```

The subscription only works when your phone is on your tailnet (Tailscale connected).

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| ntfy running | `doctor` exits 1 |
| Listen address is tailnet IP | `doctor` exits 1 |
| Not bound to 0.0.0.0 | `doctor` exits 1 |
| Port reachable from tailnet | warning |

## Commands

```sh
abysslink notify "hello from my rig"   # send a test notification
abysslink up [--apply]                  # configure ntfy
abysslink doctor                        # verify ntfy binding
```
