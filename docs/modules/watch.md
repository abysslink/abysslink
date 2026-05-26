# watch Module

The watch module monitors filesystem paths and process events on your rig and triggers notifications or hooks when conditions are met.

## What it does

- Watches specified filesystem paths for changes (create, modify, delete)
- Monitors process lifecycle events (start, exit, crash)
- Fires configured hooks (ntfy notification, webhook, shell command) on match
- Runs as a background daemon (`abysslinkd`)

## Configuration

```yaml
watch:
  paths:
    - path: "~/projects"
      events: ["create", "modify"]
      hook: notify
      topic: "abysslink"
  processes:
    - name: "claude"
      events: ["exit"]
      hook: notify
      message: "Claude finished"
```

## Hook types

| Hook | Description |
|------|-------------|
| `notify` | Send ntfy push notification |
| `webhook` | POST to a configured URL |
| `shell` | Execute a shell command (no `sh -c`; argv only) |

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `abysslinkd` running | warning |
| Watch paths exist | warning |

## Commands

```sh
abysslink watch list             # list configured watchers
abysslink watch status           # show daemon status
abysslink up [--apply]           # configure watchers
```
