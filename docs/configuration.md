# Configuration reference

Abysslink reads `~/.config/abysslink/abysslink.yaml` (override with `--config`, or set `XDG_CONFIG_HOME`). YAML is parsed in **strict mode** — unknown keys are rejected. Defaults come from `config.Defaults()` (`internal/config/config.go`, per `DESIGN.md §4.2`). See the annotated [abysslink.yaml.example](../abysslink.yaml.example).

## Top level

| Key | Type | Default | Notes |
|---|---|---|---|
| `version` | int | `1` | Only `1` is accepted. |
| `backend.type` | string | `tailscale` | `tailscale` \| `headscale` \| `netbird`. |

## `tailnet`

| Key | Type | Default | Notes |
|---|---|---|---|
| `ssh` | bool | `true` | Enable VPN-native SSH. |
| `lock.enabled` | bool | `true` | Tailnet Lock — cryptographic device authorization. |
| `lock.disablement_secrets` | int | `2` | Printed once; never stored on disk. |
| `lock.share_with_support` | bool | `false` | |

## `mobile`

| Key | Type | Default | Notes |
|---|---|---|---|
| `tag` | string | `mobile` | ACL tag granted to the phone. |
| `ports` | list | `[tcp/22, udp/60000-61000]` | Ports the phone may reach. |
| `ssh_check_period` | duration | `12h` | Lowerable; never silently raised. |

## `modules`

| Key | Type | Default | Notes |
|---|---|---|---|
| `ssh.enabled` / `ssh.mode` | bool / string | `true` / `tailscale` | |
| `tmux.enabled` / `tmux.session` | bool / string | `true` / `main` | |
| `mosh.enabled` | bool | `true` | |
| `notify.enabled` / `notify.default_topic` | bool / string | `true` / `rig` | |
| `ntfy.enabled` / `ntfy.port` | bool / int | `true` / `2586` | Binds to the tailnet IP only. |
| `watch.enabled` / `watch.panes` | bool / list | `true` / `[main]` | Plus `files:` and `http:` watchers. |
| `code_server`, `ttyd`, `eternal_terminal`, `syncthing`, `upsnap`, `atuin`, `sandbox`, `asciinema` | bool | `false` | Optional modules (`enabled: true`). |

## `claudecode`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Opt-in. |
| `api_key_source` | string | `keychain` | `keychain` \| `env`. Never on argv. |
| `notify_on.notification` | bool | `true` | Push on Claude's Notification hook. |
| `notify_on.stop_after` | duration | `60s` | Push when Claude is idle this long. |

## `hardening`

| Key | Type | Default | Notes |
|---|---|---|---|
| `filevault` | string | `required` | `required` → `doctor` fails closed if off (macOS). |
| `luks` | string | `required` | Same, Linux. |
| `firewall_stealth` | bool | `true` | macOS stealth mode. |
| `ufw_default_deny` | bool | `true` | Linux UFW default-deny. |
| `disable_macos_sshd` | bool | `true` | Disable the system SSH daemon (Tailscale SSH used instead). |

## `webui`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Listener never starts unless opted in; also gated behind the `webui` build tag. |
| `read_only` | bool | `true` | **Enforced** — `false` is rejected at validation. |
| `bind_addr` | string | tailnet IP | Resolved to the tailnet IP when empty; never `0.0.0.0`. |
| `port` | int | `8443` | TLS listen port. |
| `allow_notify` | bool | `false` | Scaffolded; default off. |

## `observability`

| Key | Type | Default | Notes |
|---|---|---|---|
| `metrics.enabled` | bool | `false` | Prometheus metrics, tailnet-only listener. |
| `metrics.bind_addr` / `metrics.port` | string / int | tailnet IP / — | |
| `digest.enabled` | bool | `false` | Scheduled daily ntfy posture digest. |
| `digest.hour` / `digest.ntfy_topic` | int / string | — | |

## `content_store`

Tailnet-only HTTPS store served by `abysslinkd`: token-keyed, TTL'd notification bodies fetched by enrolled devices, plus the first-contact one-scan credential pull used by `enroll phone --apply`. `enabled` is the single gate for both — disabling it makes `enroll phone` degrade to the inline secret box.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | On by default; `false` disables the listener and the one-scan pull. |
| `port` | int | `2587` | TLS listen port (`0`/unset → `2587`). |
| `ttl_seconds` | int | `600` | Content-token lifetime; clamped to `[30, 3600]` (out of range is rejected). |
| `enroll_ttl_seconds` | int | `300` | First-contact bootstrap-token lifetime; clamped to `[30, 900]`. Independent of `ttl_seconds`. |
| `bind_addr` | string | tailnet IP | Literal tailnet IP only; never `0.0.0.0`/`::`. Must equal the resolved tailnet IP. |

## Self-hosted backends — `server`

Used only when `backend.type` is `headscale` or `netbird`. See [headscale-ha.md](headscale-ha.md) and [netbird-scim.md](netbird-scim.md).

| Key | Default | Notes |
|---|---|---|
| `server.headscale.binary_path` | `/usr/local/bin/headscale` | |
| `server.headscale.config_path` | `/etc/headscale/config.yaml` | |
| `server.headscale.db_path` | `/var/lib/headscale/db.sqlite` | |
| `server.headscale.pre_auth_key_expiry` | `1h` | Paranoid-safe default. |
| `server.headscale.cert_expiry_warn_days` | `30` | |
| `server.netbird.mgmt_bind_addr` | `127.0.0.1:443` | |
| `server.netbird.metrics_addr` | `127.0.0.1:9090` | |
| `server.netbird.setup_key_expiry` | `24h` | |
| `server.netbird.config_path` | `/etc/netbird/config.yaml` | |

## `identity`

Written by `init`; identifies the operator and the local account.

| Key | Type | Default | Notes |
|---|---|---|---|
| `email` | string | — | Operator email (tailnet account / notifications). |
| `unix_user` | string | — | Local UNIX user the modules are configured for. |

## `power`

| Key | Type | Default | Notes |
|---|---|---|---|
| `closed_lid_ac` | string | `keep-awake` | Lid-closed-on-AC behaviour (`caffeinate` / `systemd-inhibit`) so the rig stays reachable. |

## `rig` and `rigs` (fleet)

`rig.name` is this machine's logical name. `rigs:` is the enrolled fleet — entries are **managed by `abysslink enroll rig`**, not hand-edited.

| Key | Type | Notes |
|---|---|---|
| `rig.name` | string | This machine's logical rig name (used by fleet commands). |
| `rigs[].name` | string | Logical rig name; basis of the keychain service + ntfy topic. |
| `rigs[].hostname` | string | Tailscale hostname — the SSH target. |
| `rigs[].ntfy_topic` | string | `abysslink-<name>-<8char>` notification topic. |
| `rigs[].backend` | string | Backend type recorded at enrollment. |
| `rigs[].last_seen` | string | RFC3339 UTC; updated by fan-out status. |
| `rigs[].mac` | string | Hardware MAC for Wake-on-LAN; empty disables WoL for that rig. |
