# watch Module

The watch module runs watchers inside the `abysslinkd` daemon and sends their events through the notify pipeline (ntfy/push). There are three watcher types — pane-idle, file-tail, and HTTP status-change. There is no process watcher, and watchers have no webhook or shell hooks: **every event flows to notify**.

## Watcher types

| Watcher | How it works |
|---------|-------------|
| **Pane idle** | Polls each named tmux pane with `capture-pane`. When the pane content stops changing for the idle threshold *and* the last line looks like a prompt, it notifies "waiting for input". A cool-off suppresses repeat notifications. |
| **File tail** | Polls a file for newly appended lines and notifies on each line matching the `grep` regexp. Rotation/truncation is handled (a shrunk file resets the offset). |
| **HTTP** | Polls a URL and notifies when the status code changes from `expect` (or from the previous observation when `expect` is unset). |

## Configuration

```yaml
modules:
  watch:
    enabled: true
    panes: ["main"]            # tmux panes/sessions to watch (default: ["main"])
    pane_poll_secs: 5          # optional; defaults: poll 5s
    pane_idle_secs: 30         #   idle threshold 30s
    pane_cool_off_secs: 300    #   cool-off 300s
    files:
      - path: "~/build.log"
        grep: "ERROR|FAILED"   # regexp; required
        label: "build"         # optional; used in the notification
        poll_secs: 2           # optional; default 2
    http:
      - url: "http://100.x.y.z:8080/health"
        expect: 200            # optional; 0 = notify on any change
        label: "api"           # optional
        interval_secs: 60      # optional; default 60
```

These are the only keys the schema accepts — strict decoding rejects anything
else (there is no `paths:` or `processes:` list).

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `panes_configured` — module enabled but no panes listed | warning (`doctor` exits 1) |

## Commands

```sh
abysslink watch list             # list configured watchers
abysslink watch add              # add a pane/file/HTTP watcher (--apply to write)
abysslink watch remove           # remove a watcher (--apply to write)
abysslink daemon status          # show daemon status
```

Watchers run inside `abysslinkd`, which reads the config at startup — restart
the daemon after changing watcher config.
