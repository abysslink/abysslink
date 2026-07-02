# claudecode Module

The claudecode module wires [Claude Code](https://claude.ai/claude-code) hooks to Abysslink's notification pipeline so your phone buzzes when Claude stops or is waiting for input.

!!! note "Architecture note"
    The claudecode module is one opt-in consumer of the generic `notify`
    module. Claude Code is not a core dependency of Abysslink — the
    underlying architecture is a generic phone-to-rig toolkit. This module
    just wires Claude Code's hook system to Abysslink's notification pipeline.

## What it configures

Abysslink **merges** JSON hook entries directly into `~/.claude/settings.json`.
There is no hooks directory and no wrapper script. The merge:

- preserves every existing user hook (only abysslink's own entries are replaced),
- is idempotent — repeated `up --apply` runs never duplicate entries,
- is an audited write (backup + audit-log entry; the log records a hash, never the file body),
- refuses to overwrite a `settings.json` that is not valid JSON.

The hook commands embed the absolute path of the running `abysslink` binary
when it is safe to do so, because Claude Code's hook environment frequently
lacks the user's interactive `PATH`.

### Hooks written

| Hook event | Command | When written |
|------------|---------|--------------|
| `Stop` | `abysslink notify "Claude stopped" "Session ended"` | always |
| `Notification` | `abysslink notify "Claude needs you" "waiting for input"` | when `notify_on.notification: true` |
| `PreToolUse` | `abysslink approve --check --blocking` | only when `gate.enforcing: true` |
| `PermissionRequest` | `abysslink approve --permission-request` | only when `gate.enforcing: true` |

Notification titles are **generic by design** — no task summary, error text, or
tool arguments are ever placed in a push payload (opaque-payload invariant).
The `PreToolUse` hook blocks tool execution pending phone or TTY approval;
`PermissionRequest` is a fast non-blocking notification trigger. Both are
written only when the approve gate is enforcing (it ships in shadow mode).

## Configuration

`claudecode:` is a top-level key (not under `modules:`):

```yaml
claudecode:
  enabled: true               # default: false
  api_key_source: keychain    # keychain | env | none (default: keychain)
  notify_on:
    notification: true        # write the Notification hook
    stop_after: "60s"         # accepted by the schema; reserved — the Stop hook currently fires on every session end
```

The config loader uses strict decoding — keys other than these fail the whole
config load.

## API key handling

With `api_key_source: keychain`, `abysslink up --apply` seeds the Anthropic API
key from the `$ANTHROPIC_API_KEY` environment variable into the OS keychain
(service `abysslink`, account `anthropic-api-key`). The value is read from the
environment and delivered to the keychain via stdin — never placed on argv and
never logged. Rotate it later with:

```sh
ABYSSLINK_NEW_ANTHROPIC_KEY=<key> abysslink rotate anthropic-key --apply
```

## `abysslink doctor` checks

All claudecode checks are **warnings** (`doctor` exits 1):

| Check | Meaning |
|-------|---------|
| `api_key_present` | no key in the keychain — set `$ANTHROPIC_API_KEY` and re-run `up --apply` |
| `api_key_keychain` | keychain not readable (login keychain may be locked after reboot) |
| `claude_dir_exists` | `~/.claude/` missing — Claude Code not installed |
| `settings_json_exists` / `settings_json_readable` | `~/.claude/settings.json` missing or unreadable |
| `stop_hook_configured` / `notification_hook_configured` | abysslink notify hooks missing |
| `approve_pretooluse_hook_configured` / `approve_permissionrequest_hook_configured` | approve hooks missing (checked only when `gate.enforcing: true`) |

## Removal

`abysslink disable claudecode` stops future applies; uninstall (and the
module's config-reversal path) surgically strips only the abysslink entries
from `~/.claude/settings.json`, leaving every other user setting intact.

## Usage flow

1. Start a Claude Code session from your phone (SSH into your rig, run `claude`)
2. Walk away — your phone receives a push notification when Claude stops or needs input
3. Reconnect from the phone and continue the session

This is the "vibe-code Claude from your phone" workflow that Abysslink was built to enable.
