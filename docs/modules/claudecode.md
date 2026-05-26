# claudecode Module

The claudecode module integrates with [Claude Code](https://claude.ai/claude-code) hooks to send push notifications to your phone when Claude finishes a task, encounters an error, or requires your attention.

!!! note "Architecture note"
    The claudecode module is one opt-in consumer of the generic `notify` and
    `watch` modules. Claude Code is not a core dependency of Abysslink — the
    underlying architecture is a generic phone-to-rig toolkit. This module
    just wires Claude Code's hook system to Abysslink's notification pipeline.

## What it configures

Abysslink writes hooks to `~/.config/claude-code/hooks/` (or the path Claude Code uses on your platform). Each hook calls `abysslink notify` with a structured payload.

### Supported hooks

| Hook event | Notification sent |
|------------|------------------|
| `Stop` | "Claude finished: {task summary}" |
| `Error` | "Claude error: {error message}" |
| `Notification` | forwarded as-is to ntfy |

## Configuration

```yaml
claudecode:
  enable: true
  hooks:
    - event: Stop
      notify: true
      topic: "abysslink"
    - event: Error
      notify: true
      topic: "abysslink"
```

## Hook file format

Abysslink writes a shell wrapper at `~/.config/claude-code/hooks/abysslink-notify.sh`:

```sh
#!/bin/sh
# Written by abysslink — do not edit manually
exec abysslink notify --from-hook "$@"
```

The wrapper calls `abysslink notify` via `exec` (no `sh -c`, no shell injection surface).

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| Claude Code installed (if enabled) | warning |
| Hook files exist and are executable | warning |
| ntfy running and reachable | `doctor` exits 1 |

## Commands

```sh
abysslink up [--apply]       # install claude code hooks
abysslink doctor             # verify hook configuration
abysslink notify "test"      # send a test notification
```

## Usage flow

1. Start a Claude Code session from your phone (SSH into your rig, run `claude`)
2. Walk away — your phone receives a push notification when Claude finishes
3. Review the result on your phone; reply if needed
4. Claude receives your reply via the next session

This is the "vibe-code Claude from your phone" workflow that Abysslink was built to enable.
