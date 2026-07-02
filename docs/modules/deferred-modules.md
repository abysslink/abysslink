# Deferred Modules (v2 candidates)

Five optional modules — **syncthing, upsnap, atuin, sandbox, asciinema** — are labelled *v2 candidates* in the codebase: they were deferred from the v1 scope and have received less hardening attention than the core modules. They are nonetheless present in the binary today: each is accepted by the config schema, toggleable with `abysslink enable <name>` / `abysslink disable <name>`, disabled by default, and has a working `Detect`/`Plan`/`Apply` as described below. Treat them as lighter-touch conveniences, not core security surfaces.

```yaml
modules:
  syncthing:  { enabled: false }
  upsnap:     { enabled: false }
  atuin:      { enabled: false }
  sandbox:    { enabled: false }
  asciinema:  { enabled: false }
```

Each takes only `enabled` (strict decoding rejects other keys).

## syncthing

File sync between your devices, GUI bound to the tailnet.

- **Apply:** installs syncthing when missing; installs a user service
  (`dev.abysslink.syncthing`) running `syncthing --no-browser
  --gui-address=<tailnet-ip>:8384`.
- **Doctor:** `installed` (fatal, exit 2); `gui_bind_tailnet` — GUI bound to
  all interfaces (warning); `gui_password` — the GUI ships with no password,
  so any tailnet peer reaching `:8384` has full GUI/API control (warning). Set
  a GUI password yourself (Actions → Settings → GUI); the tailnet ACL is the
  outer boundary.

## upsnap

Wake-on-LAN enablement. Despite the name, no UpSnap service is managed — the
module's job is detecting that WoL is configured and surfacing doctor findings.
The actual magic-packet send is the CLI command, gated behind `--apply`:

```sh
abysslink wol <rig> --apply
```

- **Config:** add `mac: <MAC>` to a rig entry under `rigs:` in `abysslink.yaml`.
- **Doctor:** `wol-no-rig-mac` — module enabled but no rig has a usable `mac:`
  field (warning).
- **Apply:** no-op (WoL is a manual per-command action).

## atuin

Shell history with search — configured **local-only**, no cloud sync.

- **Apply:** installs atuin when missing; writes a local-only
  `~/.config/atuin/config.toml` (`auto_sync = false`, empty `sync_address`,
  `secrets_filter = true`) when none exists; if an existing config actively
  points at the public cloud (`api.atuin.sh`), it is rewritten to local-only
  mode (other customisations preserved); appends the atuin shell-init line to
  `~/.zshrc`/`~/.bashrc` (audited write, idempotent).
- **Doctor:** `installed` (warning); `no_cloud_sync` — config actively syncs
  with the public cloud (warning).

## sandbox

Kernel-native process isolation via the Linux **Landlock** LSM (kernel ≥ 5.13).
Linux-only; on macOS the module reports the capability is unavailable.

!!! note "Currently probe-only — no restriction is enforced yet"
    No Landlock path rules are configurable today, and applying an *empty*
    Landlock ruleset would be an irreversible deny-all for the abysslink
    process itself. So `Apply` deliberately applies **no ruleset**: the module
    truthfully reports whether the kernel could enforce a future profile, and
    nothing more. Do not count the sandbox module as an active mitigation.

- **Doctor:** `sandbox-landlock-supported` — module enabled but Landlock
  unavailable (non-Linux, kernel < 5.13, or Landlock disabled) — warning.

## asciinema

Terminal recording with a credential-safety guardrail.

- **Module Apply:** installs asciinema when missing; writes a privacy-safe
  `~/.config/asciinema/config` with cloud uploads disabled; if an existing
  config actively uploads to `asciinema.org`, the URL line is commented out
  (under audit) rather than left active.
- **Doctor:** `installed` (warning); `no_cloud_upload` — config actively
  uploads to asciinema.org (warning).

The **`abysslink asciinema rec` command is fully implemented** (independent of
the module toggle):

```sh
abysslink asciinema rec [file]
```

It shows a **non-suppressible credential warning** before recording — terminal
recordings capture every secret that scrolls past — and refuses to run in
non-interactive contexts (`--yes`, `--json`, piped stdin, CI), because the
warning cannot be shown without a live TTY. There is no flag or environment
variable to skip it. After acknowledgement it execs `asciinema rec` directly
(discrete argv, no `sh -c`).
