# Configuration reference

Abysslink reads `~/.config/abysslink/abysslink.yaml` (override with `--config`, or set `XDG_CONFIG_HOME`). YAML is parsed in **strict mode** — unknown keys are rejected. Defaults come from `config.Defaults()` (`internal/config/config.go`, per `DESIGN.md §4.2`). See the annotated [abysslink.yaml.example](https://github.com/abysslink/abysslink/blob/main/abysslink.yaml.example).

## Top level

| Key | Type | Default | Notes |
|---|---|---|---|
| `version` | int | `1` | Only `1` is accepted. |
| `backend.type` | string | `tailscale` | `tailscale` \| `headscale` \| `netbird`. |

## `tailnet`

| Key | Type | Default | Notes |
|---|---|---|---|
| `hostname` | string | — | **Required** — this rig's tailnet hostname; DNS-safe lowercase (`[a-z0-9]` + internal hyphens/dots). |
| `ssh` | bool | `true` | Enable VPN-native SSH. |
| `lock.enabled` | bool | `true` | Tailnet Lock — cryptographic device authorization. |
| `lock.disablement_secrets` | int | `2` | Printed once; never stored on disk. |
| `lock.share_with_support` | bool | `false` | |
| `admin.tailnet` | string | — | Tailnet name for the admin API, e.g. `you@github`, or `-` for the default. |
| `admin.oauth_client_id` | string | — | NOT secret — the OAuth client secret comes from `ABYSSLINK_TS_OAUTH_SECRET` (env/keychain). Empty = manual clipboard + browser mode. |

## `mobile`

| Key | Type | Default | Notes |
|---|---|---|---|
| `tag` | string | `mobile` | ACL tag granted to the phone. |
| `ports` | list | `[tcp/22, tcp/2586, tcp/2587, udp/60000-61000]` | **Informational only** — documents the ports the phone may reach (SSH, ntfy, content store, mosh). The authoritative tailnet ACL grant is a fixed set in `internal/tailscale/acl.go`; editing this field does **not** change the ACL. |
| `ssh_check_period` | duration | `12h` | Lowerable freely (validated range `1m`–`168h`). Raising it above `12h` is not silent: `abysslink up --apply` refuses the widened Tailscale-SSH `checkPeriod` unless you pass `--accept-checkperiod-extension`. |

## `modules`

| Key | Type | Default | Notes |
|---|---|---|---|
| `ssh.enabled` / `ssh.mode` | bool / string | `true` / `tailscale` | |
| `tmux.enabled` / `tmux.session` | bool / string | `true` / `main` | |
| `mosh.enabled` | bool | `true` | |
| `notify.enabled` / `notify.default_topic` | bool / string | `true` / `rig` | |
| `notify.click_url` | string | `""` | URL a notification opens on tap (ntfy `X-Click`). Set to an `ssh://` deep link matching your saved terminal-app host (e.g. `ssh://me@rig.tailnet-name.ts.net`) so tapping connects with saved creds instead of a new connection. Empty → daemon composes `ssh://<user>@<short-hostname>`. |
| `ntfy.enabled` / `ntfy.port` | bool / int | `true` / `2586` | Binds to the tailnet IP only. `port` is currently **fixed at 2586** — the mobile→laptop ACL grant only opens tcp/2586, so a non-default value is rejected at config load (fail-closed) rather than silently ACL-blocking the phone. |
| `watch.enabled` / `watch.panes` | bool / list | `true` / `[main]` | Plus `files:` and `http:` watchers — see below. |
| `code_server`, `ttyd`, `eternal_terminal`, `syncthing`, `upsnap`, `atuin`, `sandbox`, `asciinema` | bool | `false` | Optional modules (`enabled: true`). |

### `modules.watch` details

Timing knobs use `0` = compiled-in default.

| Key | Default | Notes |
|---|---|---|
| `pane_poll_secs` / `pane_idle_secs` / `pane_cool_off_secs` | `0` = 5 / 30 / 300 s | Pane-watcher poll cadence, idle threshold, re-notify cool-off. |
| `files[]` | — | Entries take `path`, `grep` (regexp), `label`, `poll_secs` (`0` = 2 s). |
| `http[]` | — | Entries take `url`, `expect` (status code), `label`, `interval_secs` (`0` = 60 s). |

## `claudecode`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Opt-in. |
| `api_key_source` | string | `keychain` | `keychain` \| `env` \| `none`. Never on argv. |
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
| `digest.hour` | int | `8` | Unset = 08:00; an explicit `0` means midnight; valid 0–23. |
| `digest.ntfy_topic` | string | — | |

## `content_store`

Tailnet-only HTTPS store served by `abysslinkd`: token-keyed, TTL'd notification bodies fetched by enrolled devices, plus the first-contact one-scan credential pull used by `enroll phone --apply`. `enabled` is the single gate for both — disabling it makes `enroll phone` degrade to the inline secret box.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | On by default; `false` disables the listener and the one-scan pull. |
| `port` | int | `2587` | TLS listen port (`0`/unset → `2587`). Currently **fixed at 2587** — the mobile→laptop ACL grant only opens tcp/2587, so a non-default value is rejected at config load (fail-closed) rather than silently ACL-blocking the phone. |
| `ttl_seconds` | int | `600` | Content-token lifetime; clamped to `[30, 3600]` (out of range is rejected). |
| `enroll_ttl_seconds` | int | `300` | First-contact bootstrap-token lifetime; clamped to `[30, 900]`. Independent of `ttl_seconds`. |
| `bind_addr` | string | tailnet IP | Literal tailnet IP only; never `0.0.0.0`/`::`. Must equal the resolved tailnet IP. |

## `session_registry`

Daemon-side tmux session registry — powers `needs_input` detection. **Enabled by default.** Timing knobs use `0` = compiled-in default.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | |
| `ignore_sessions` | list | `[]` | Session names exempted from the `needs_input` heuristic. |
| `idle_secs` | int | `0` = 30 | No-output threshold before a prompt-shaped pane is `needs_input`; values below the 10 s floor are clamped up. |
| `poll_active_secs` | int | `0` = 5 | Poll cadence while any pane is active. |
| `poll_idle_secs` | int | `0` = 15 | Backed-off cadence when all panes are idle. |
| `prompt_regex` | string | — | Extends the built-in prompt sentinels; must compile (validated at load). Empty = sentinels only. |
| `cooldown_secs` | int | `0` = 300 | Per-(pane, kind) re-notify suppression window. |

## `gateway`

Push-gateway legs. APNs and FCM are **experimental** and disabled by default; UnifiedPush/ntfy is the default path.

| Key | Type | Default | Notes |
|---|---|---|---|
| `unifiedpush.enabled` | bool | `true` | Sovereign ntfy/UnifiedPush wake path. |
| `apns.enabled` | bool | `false` | Experimental. |
| `apns.bundle_id` | string | — | **Required** when `apns.enabled: true`. |
| `apns.key_source` | string | `keychain` | `keychain` \| `file` — how the `.p8` signing key is retrieved. |
| `apns.cred_file_path` | string | — | `.p8` key path when `key_source: file`. |
| `fcm.enabled` | bool | `false` | Experimental. |
| `fcm.creds_source` | string | `keychain` | `keychain` \| `file` — how the GCP service-account JSON is retrieved. |
| `fcm.cred_file_path` | string | — | Service-account JSON path when `creds_source: file`. |

## `gate`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enforcing` | bool | `false` | Shadow mode by default; `true` blocks tool executions through the phone approve loop. |

## `approval`

| Key | Type | Default | Notes |
|---|---|---|---|
| `timeout_seconds` | int | `120` | Phone approve window; valid 10–3600. |
| `extra_critical` | list | `[]` | Extra action-name substrings forced to the critical tier — add-only, may only tighten. |

## `quorum`

The quorum-sensing action gate (see [agent-safety.md](agent-safety.md#the-quorum-action-gate)). Evaluation and shadow auditing are **on by default**; enforcement rides `gate.enforcing` — quorum has no arm switch of its own. **Every knob is tighten-only**: lists are add-only unions with the compiled defaults (no remove/override syntax exists), numeric values looser than the shipped defaults are a config *load error* (rejected, never clamped), and tier overrides are raise-only.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | Evaluation + shadow audit. `false` with an enforcing gate falls back to approval-for-**every**-exec (strictly tighter). |
| `protected_paths` | list | `[]` | Add-only extra protected filesystem scopes, unioned with the compiled defaults (`~/.ssh`, `/etc`, the audit-log dir, the abysslink config dir, keychain paths, tailscale state dirs). |
| `protected_branches` | list | `[]` | Add-only extra protected git branches, unioned with the compiled `main`, `master`. |
| `extra_patterns` | list | `[]` | Add-only extra syntactic patterns (substring match); matches are forced to tier ≥ sensitive. |
| `canary_paths` | list | `[]` | Add-only extra canary tripwire markers; any argv token containing one is an instant deny + alert. |
| `spend_threshold_usd` | float | `0` = 50 | Only values in (0, 50] accepted — raising above the shipped default is a load error. **Not yet active:** the shipped daemon wires no spend source, so the V3 spend-threshold rule is inert until one is (`quorum.WithSpendFunc`); lowering this knob has no effect today. |
| `rate_max_ops` | int | `0` = 10 | Destructive ops per window; only (0, 10] accepted. |
| `rate_window_seconds` | int | `0` = 300 | Only values ≥ 300 accepted (a longer window is tighter), capped at ~100 years so the internal duration cannot overflow and silently disable the rate cap. |
| `tier_overrides` | map | `{}` | Raise-only per-rule-code tier map, e.g. `{force-push: critical}`. Lowering a shipped tier or naming an unknown rule code is a load error. |

Overridable rule codes: `force-push`, `force-push-protected`, `drop-table`, `shred`, `recursive-chmod-system`, `rm-recursive-force`, `git-reset-hard`, `git-clean-force`, `git-checkout-dot`, `rsync-delete`, `find-delete`, `kubectl-delete`, `terraform-destroy`, `pipe-to-shell`, `decode-and-exec`, `extra-pattern`, `protected-path-write`, `ambiguous-scope`, `non-ascii-path`, `parse-gap`, `rate-window`, `velocity`, `dry-run-first`, `spend-threshold`, `no-undo`, `no-undo-protected`.

Deliberately-absent keys (their presence in YAML is a fatal decode error — the Funnel pattern): `quorum.floor`, `quorum.disable_floor`, `quorum.remove_patterns`, `quorum.dry_run_first`, `quorum.verifier_timeout`, `quorum.enforcing`. The compiled deny-floor (Funnel invocation, disk-encryption disable, audit-log destruction, Tailnet-Lock disable, ntfy all-interface bind — `0.0.0.0`, empty host, or `::`/`[::]`, canary tripwires) cannot be removed or disabled from configuration. The floor and V1 are evaluated against the **effective** command, so a floor/catastrophe action cloaked behind a privilege/exec wrapper (`sudo`, `env`, `timeout`, …) or a shell interpreter `-c` payload is judged on what it actually runs, not on `argv[0]`.

## `budget`

Kill-switch thresholds used by `abysslink arm`. Shadow mode by default — the SIGSTOP→kill ladder is opt-in via `ladder: true`. Numeric knobs use `0` = compiled-in default.

| Key | Type | Default | Notes |
|---|---|---|---|
| `wall_clock_minutes` | int | `30` | Wall-clock run limit; floor 1. |
| `loop_n` | int | `8` | Identical-command repeats in the window that count as a loop; floor 2. |
| `loop_window` | int | `20` | Command-count sliding window; floor 5. |
| `ladder` | bool | `false` | `true` enables the notify → SIGSTOP → kill escalation ladder. |
| `kill_grace_seconds` | int | `5` | SIGTERM→SIGKILL grace; valid 1–30. |
| `minimize_agent_env` | bool | `false` | Spawn the armed agent with a minimized allowlist env (opt-in — breaks agents that read API keys from env). |
| `token_tiers` | map | off | Opt-in token-spend observation: `jsonl_path` (required to enable), `warn_tokens`, `stop_tokens`. |

## `deadman`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Opt-in no-contact lockdown timer hosted by `abysslinkd`. |
| `interval_hours` | int | `0` = 24 | No-contact window before lockdown; floor 1 h when enabled. |

## Self-hosted backends — `server`

Used only when `backend.type` is `headscale` or `netbird`. See [headscale-ha.md](headscale-ha.md) and [netbird-scim.md](netbird-scim.md).

| Key | Default | Notes |
|---|---|---|
| `server.hostname` | — | FQDN of the Headscale / NetBird server (kept for compat). |
| `server.headscale.server_url` | — | **Required** when `backend.type: headscale`; `https://` only — plaintext `http` is rejected (would leak the API key / pre-auth key). |
| `server.headscale.binary_path` | `/usr/local/bin/headscale` | |
| `server.headscale.config_path` | `/etc/headscale/config.yaml` | |
| `server.headscale.db_path` | `/var/lib/headscale/db.sqlite` | |
| `server.headscale.acme` | `false` | Opt-in Let's Encrypt automatic cert. |
| `server.headscale.tls_cert_path` / `tls_key_path` | — | BYO TLS certificate + private key. |
| `server.headscale.pre_auth_key_expiry` | `1h` | Paranoid-safe default. |
| `server.headscale.cert_expiry_warn_days` | `30` | |
| `server.headscale.user` | — | Headscale user for pre-auth key creation. |
| `server.netbird.server_url` | — | **Required** when `backend.type: netbird`; `https://` only — plaintext `http` is rejected (would leak the PAT). |
| `server.netbird.binary_path` | — | Pre-built `netbird-server` binary path (Linux only). |
| `server.netbird.mgmt_bind_addr` | `127.0.0.1:443` | |
| `server.netbird.metrics_addr` | `127.0.0.1:9090` | |
| `server.netbird.setup_key_expiry` | `24h` | |
| `server.netbird.accept_no_sshcheck` | `false` | Persisted `--accept-no-sshcheck` opt-in (acknowledges SSHCheck degradation). |
| `server.netbird.tls_cert_file` / `tls_key_file` | — | BYO TLS certificate + private key. |
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
