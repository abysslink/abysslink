# ntfy Module

The ntfy module runs a self-hosted [ntfy](https://ntfy.sh) notification server on your rig and configures it to send push notifications to your phone.

## Security: tailnet-IP binding

!!! danger "ntfy must never bind to 0.0.0.0"
    Abysslink enforces that ntfy binds **only** to your Tailscale tailnet IP address.
    Binding to `0.0.0.0` or a public IP would expose your notification server to
    the internet. A wildcard bind is a **fatal** `abysslink doctor` finding (exit 2).

The listen address is derived from `tailscale ip --4` at apply time.

## What it configures

**Native mode (Linux):**

- Installs ntfy via the system package manager
- Writes `~/.config/ntfy/server.yml` with:
  - `listen-http: "<tailnet-ip>:2586"`
  - `base-url: "http://<tailnet-ip>:2586"`
  - `auth-file: ~/.local/state/abysslink/ntfy/user.db`
  - `auth-default-access: "deny-all"`
- Installs a user service (`dev.abysslink.ntfy`, managed via `systemctl --user`)

**Docker mode (macOS, when Docker Desktop is available):**

- Writes `~/.config/ntfy/server-docker.yml` and runs the `abysslink-ntfy`
  container (image pinned by digest, not a floating tag)
- ntfy listens on `0.0.0.0:80` *inside* the container; the host binding is
  restricted to the tailnet IP via `docker run -p <tailnet-ip>:2586:80`
- `base-url` uses the MagicDNS hostname so phone URLs survive IP changes

**Authentication** is enabled in both modes: `auth-default-access: "deny-all"`,
with an `admin` user whose password is generated on first apply and stored in
the OS keychain (never written to disk or placed on argv). Rotate it with
`abysslink rotate ntfy-creds --apply`.

No topic is pre-created — ntfy topics are implicit. The notify module's default
topic is `rig` (`modules.notify.default_topic`).

## Configuration

```yaml
modules:
  ntfy:
    enabled: true
    port: 2586        # optional; 2586 is the default
```

Those are the only two keys the schema accepts — the config loader uses strict
decoding, so unknown keys under `modules.ntfy` fail the whole config load.

## Phone setup

Because the server runs deny-all auth, an anonymous subscription to a topic URL
is rejected. Enroll the phone instead:

```sh
abysslink enroll phone --apply
```

This mints a tagged auth key and walks through pairing step by step (install
Tailscale → join tailnet → subscribe → save credentials), delivering the
per-device credentials the phone needs. Add `--qr` to render the credentials as
scannable QR codes. The server is reachable only while the phone is on your
tailnet.

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `installed` — ntfy present | fatal on Linux (`doctor` exits 2); warning on macOS (Docker installs it on apply, or Docker Desktop is missing) |
| `config_exists` — `~/.config/ntfy/server.yml` present | warning (`doctor` exits 1) |
| `listen_address` — config binds a wildcard (`0.0.0.0`, `[::]`, `:PORT`) | **fatal** (`doctor` exits 2); skipped in Docker mode, where the `-p` flag enforces the tailnet binding |
| `reachable` — ntfy answers `GET /v1/health` on `<tailnet-ip>:<port>` | warning; catches the Docker-Desktop-for-Mac trap where the container runs but the port never publishes |

## Commands

```sh
abysslink notify "hello" "from my rig"   # send a test notification
abysslink up [--apply]                    # install/configure ntfy
abysslink doctor                          # verify binding + reachability
abysslink rotate ntfy-creds --apply       # rotate the keychain-held admin password
```
