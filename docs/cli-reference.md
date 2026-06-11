# CLI reference

Complete command surface for `abysslink`. For the common 80%, see the [README usage section](../README.md#usage). Flags below are the command's **local** flags; every command also accepts the [global flags](#global-flags). Run `abysslink <command> --help` for the authoritative, build-current details.

## Global flags

Persistent flags on the root command, available to every subcommand:

| Flag | Default | Description |
|---|---|---|
| `--config <path>` | `~/.config/abysslink/abysslink.yaml` | Path to the config file (`XDG_CONFIG_HOME` honoured). An explicitly passed path that does not exist is a hard error. |
| `--dry-run` | `true` | Show planned changes without applying. |
| `--apply` | `false` | Execute planned changes. |
| `--yes` | `false` | Skip interactive confirmations. |
| `--json` | `false` | Machine-readable JSON output. |
| `-v`, `--verbose` | `false` | Debug logging. |
| `--explain` | `false` | Annotate each planned action with its rationale. |
| `--rig <name>` | — | Target a single enrolled rig. |
| `--all-rigs` | `false` | Fan out to every enrolled rig. |
| `--strict` | `false` | Exit `2` if any targeted rig is unreachable. |

**Exit codes** (`doctor`, `up`, `verify`): `0` ok · `1` warning · `2` fatal / fail-closed. An unknown or misspelled subcommand exits `1` with a "did you mean" suggestion. `upgrade --check` exits `3` when a newer release is available.

## Setup

| Command | Local flags | Description |
|---|---|---|
| `init` | `--yes`, `--resume` | Interactive bootstrap → `abysslink.yaml`; `--resume` continues from the last completed stage. |
| `up` | `--force-unsafe`, `--accept-checkperiod-extension`, `--accept-no-sshcheck` | Converge the system to match config (dry-run by default). The `--accept-*` flags are required acknowledgements for weakening a hardened default. |
| `status` | — | One-screen health summary (`--json` for machines). |
| `doctor` | `--offline` | Exhaustive verification of all modules and security posture; `--offline` skips checks that need network access. |
| `report` | `--tail <n>` | Read-only security-posture snapshot; include the last N audit entries. |
| `repair` | — | Auto-fix failures detected by `doctor` (needs `--apply`). |
| `enroll phone` | — | Mint a tagged auth key, show a QR, walk through pairing. Dry-run by default — pairing requires `--apply` (`--yes` to skip the pause stops). |
| `enroll rig <name>` | — | Enroll another laptop as a named rig in the fleet. |

## Operations

| Command | Local flags | Description |
|---|---|---|
| `notify [title] [body]` | `--stdin`, `--priority <min\|low\|default\|high\|max>` (`urgent` = `max`), `--tag <s>`, `--topic <s>`, `--kind <needs_input\|command_done\|approval_request\|watch_fired\|agent_stopped>`, `--pane <%N>` | Send a push; `notify -- <cmd>` wraps a command and pushes on exit. `--kind`/`--pane` force a session-typed v2 notification (pane autodetected from `$TMUX_PANE`). |
| `watch add` | `--pane <p>` · `--file <path> --grep <re> [--poll <s>]` · `--http <url> [--expect <code>] [--interval <s>]` · `--label <s>` | Add an idle-pane / file-tail / HTTP-change watcher. |
| `watch remove` | `--pane <p>`, `--file <path>`, `--http <url>` | Remove a watcher by its identifier. |
| `watch list` | — | List configured watchers. |
| `acl pull\|push\|validate\|diff` | — | Manage the tailnet ACL (HuJSON round-trip). |
| `lock init\|status\|sign\|rotate` | — | Manage Tailnet Lock. |
| `rotate anthropic-key\|ntfy-creds` | — | Rotate a secret stored in the OS keychain (needs `--apply`). |
| `logs` | `--since <dur>` (`24h`), `--module <s>` | Show the audit log, filtered by age and module. |
| `backup ls\|verify` | — | List / verify backups of changed files. |
| `backup restore <path>` | `--original`, `--accept-unverified-backup` | Restore a file (by its path) from its most recent backup; `--original` restores the earliest (pre-abysslink) backup. |
| `audit verify` | `--pentest`, `--fix`, `--format json` | Verify the chain; `--pentest` runs the full `sec-*` suite, `--fix` applies safe permission fixes. |
| `audit tail` | `--n <count>` (`20`) | Show the most recent audit entries. |
| `audit ls\|export` | — | List every entry / export as raw JSONL. |
| `upgrade` | `--check`, `--apply` | Self-update with cosign + SLSA verification; `--check` only reports, exiting `3` when a newer release is available. |
| `verify` | `--json`, `--bundle <path>`, `--version <v>` | Verify the installed binary's cosign signature and provenance. |
| `version` | `--provenance`, `--json` | Print version (and SLSA provenance / cosign bundle URLs). |
| `daemon start\|stop\|enable\|disable\|status` | — | Manage the `abysslinkd` background daemon (lifecycle subcommands need `--apply`). |
| `server headscale init\|upgrade\|status\|backup` | `--version <v>` | Provision / manage a self-hosted Headscale control server. |
| `server netbird init\|status\|upgrade\|backup` | `--binary-path <path>` | Provision / manage a self-hosted NetBird control server. |
| `rig ls` | — | List enrolled rigs (`--json` for an array). |
| `rig export` / `rig import <file>` | — | Export the `rigs:` config section as YAML (no secrets) / merge a rigs YAML doc into local config (`-` reads stdin; needs `--apply`). |

## Advanced

| Command | Local flags | Description |
|---|---|---|
| `claudecode disable` | — | Remove the abysslink notify hooks from `~/.claude/settings.json` (needs `--apply`). Hooks are installed via `enable claudecode --apply` + `up --apply`. |
| `enable <module>` / `disable <module>` | — | Toggle an optional module (needs `--apply`). |
| `threat-model` | `--backend <tailscale\|headscale\|netbird>` | Print the threat model with live ✓/✗ status. |
| `wol <rig>` | — | Wake an enrolled rig over the LAN (Wake-on-LAN); needs `--apply` to actually send the packet. |
| `asciinema rec` | — | Record a terminal session (non-suppressible credential warning first). |
| `netbird posture create` | `--name <s>`, `--description <s>`, `--checks <json>` | Create a NetBird posture check. |
| `netbird posture list\|delete <id>` | — | List / delete posture checks. |
| `netbird events` | `--follow` | Tail NetBird audit events (`--follow` streams). |
| `uninstall` | `--purge` | Reverse every change; `--purge` also removes config + state (audit log + backups). |

## Emergency

| Command | Local flags | Description |
|---|---|---|
| `panic` | — | Disconnect, revoke the phone, destroy the local API key — **no confirmation**. |

**Module names** accepted by `enable`/`disable`: `ssh`, `tmux`, `mosh`, `ntfy`, `notify`, `watch`, `claudecode`, `code-server`, `ttyd`, `eternal-terminal`, `syncthing`, `upsnap`, `atuin`, `sandbox`, `asciinema`. (The web dashboard is configured via the `webui` stanza, not `enable`.)
