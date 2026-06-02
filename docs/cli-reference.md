# CLI reference

Complete command surface for `abysslink`. For the common 80%, see the [README usage section](../README.md#usage). Flags below are the command's **local** flags; every command also accepts the [global flags](#global-flags). Run `abysslink <command> --help` for the authoritative, build-current details.

## Global flags

Persistent flags on the root command, available to every subcommand:

| Flag | Default | Description |
|---|---|---|
| `--config <path>` | `~/.config/abysslink/abysslink.yaml` | Path to the config file (`XDG_CONFIG_HOME` honoured). |
| `--dry-run` | `true` | Show planned changes without applying. |
| `--apply` | `false` | Execute planned changes. |
| `--yes` | `false` | Skip interactive confirmations. |
| `--json` | `false` | Machine-readable JSON output. |
| `-v`, `--verbose` | `false` | Debug logging. |
| `--explain` | `false` | Annotate each planned action with its rationale. |
| `--rig <name>` | — | Target a single enrolled rig. |
| `--all-rigs` | `false` | Fan out to every enrolled rig. |
| `--strict` | `false` | Exit `1` if any targeted rig is unreachable. |

**Exit codes** (`doctor`, `up`, `verify`): `0` ok · `1` warning · `2` fatal / fail-closed.

## Setup

| Command | Local flags | Description |
|---|---|---|
| `init` | `--yes`, `--resume` | Interactive bootstrap → `abysslink.yaml`; `--resume` continues from the last completed stage. |
| `up` | `--force-unsafe`, `--accept-checkperiod-extension`, `--accept-no-sshcheck` | Converge the system to match config (dry-run by default). The `--accept-*` flags are required acknowledgements for weakening a hardened default. |
| `status` | — | One-screen health summary (`--json` for machines). |
| `doctor` | — | Exhaustive verification of all modules and security posture. |
| `report` | `--tail <n>` | Read-only security-posture snapshot; include the last N audit entries. |
| `repair` | — | Auto-fix failures detected by `doctor` (needs `--apply`). |
| `enroll phone` | — | Mint a tagged auth key, show a QR, walk through pairing (`--yes` to auto-accept). |
| `enroll rig <name>` | — | Enroll another laptop as a named rig in the fleet. |

## Operations

| Command | Local flags | Description |
|---|---|---|
| `notify <title> [body]` | `--stdin`, `--priority <low\|default\|high\|urgent>`, `--tag <s>`, `--topic <s>` | Send a push; `notify -- <cmd>` wraps a command and pushes on exit. |
| `watch add` | `--pane <p>` · `--file <path> --grep <re> [--poll <s>]` · `--http <url> [--expect <code>] [--interval <s>]` · `--label <s>` | Add an idle-pane / file-tail / HTTP-change watcher. |
| `watch remove` | `--pane <p>`, `--file <path>`, `--http <url>` | Remove a watcher by its identifier. |
| `watch list` | — | List configured watchers. |
| `acl pull\|push\|validate\|diff` | — | Manage the tailnet ACL (HuJSON round-trip). |
| `lock init\|status\|sign\|rotate` | — | Manage Tailnet Lock. |
| `rotate anthropic\|ntfy` | — | Rotate a secret stored in the OS keychain (needs `--apply`). |
| `logs` | `--since <dur>` (`24h`), `--module <s>` | Show the audit log, filtered by age and module. |
| `backup ls\|verify` | — | List / verify backups of changed files. |
| `backup restore <ts>` | `--original` | Restore a file; `--original` restores the earliest (pre-abysslink) backup. |
| `audit verify` | `--pentest`, `--fix`, `--format json` | Verify the chain; `--pentest` runs the full `sec-*` suite, `--fix` applies safe permission fixes. |
| `audit tail` | `--n <count>` (`20`) | Show the most recent audit entries. |
| `audit ls\|export` | — | List every entry / export as raw JSONL. |
| `upgrade` | `--check`, `--apply` | Self-update with cosign + SLSA verification; `--check` only reports a newer version. |
| `verify` | `--json`, `--bundle <path>`, `--version <v>` | Verify the installed binary's cosign signature and provenance. |
| `version` | `--provenance`, `--json` | Print version (and SLSA provenance / cosign bundle URLs). |
| `daemon status\|...` | — | Manage the `abysslinkd` background daemon. |
| `server headscale init\|upgrade\|status` | `--version <v>` | Provision / manage a self-hosted Headscale control server. |
| `server netbird init\|status\|upgrade\|backup` | `--binary-path <path>` | Provision / manage a self-hosted NetBird control server. |
| `rig list` | — | List enrolled rigs (`--json` for an array). |

## Advanced

| Command | Local flags | Description |
|---|---|---|
| `claudecode [disable]` | — | Manage the AI-agent (Claude Code) hook integration. |
| `enable <module>` / `disable <module>` | — | Toggle an optional module (needs `--apply`). |
| `threat-model` | `--backend <tailscale\|headscale\|netbird>` | Print the threat model with live ✓/✗ status. |
| `wol` | — | Wake a rig over the LAN (Wake-on-LAN); target with `--rig`. |
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
