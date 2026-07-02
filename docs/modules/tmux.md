# tmux Module

The tmux module makes sure a suitable tmux is installed and configured for persistent remote work.

## What it configures

- Installs tmux via the platform package manager when missing or older than 3.2
- Appends an abysslink-managed block to `~/.tmux.conf` (only if not already
  present — existing user config is preserved; the write is audited with a backup):

```
# --- abysslink managed ---
set -g mouse on
set -g history-limit 50000
set -g default-terminal "screen-256color"
set -g base-index 1
setw -g pane-base-index 1
set -g renumber-windows on
# Resurrect
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-resurrect'
set -g @plugin 'tmux-plugins/tmux-continuum'
set -g @continuum-restore 'on'
set -g @continuum-save-interval '15'
run '~/.tmux/plugins/tpm/tpm'
# --- end abysslink managed ---
```

- Bootstraps TPM (tmux plugin manager) into `~/.tmux/plugins/tpm`, cloned
  pinned to the `v3.1.0` release tag — never floating HEAD (supply chain) — so
  the resurrect/continuum plugins can load

The module does **not** create a tmux session. The `session` config key names
the session other components reference (the watch module's pane watcher
defaults to `panes: ["main"]`); you create and attach to it yourself.

## Configuration

```yaml
modules:
  tmux:
    enabled: true
    session: main     # session name referenced by other modules (default: main)
```

Those are the only two keys the schema accepts — strict decoding rejects
anything else under `modules.tmux`.

## Usage

Create/attach the persistent session (idempotent):

```sh
tmux new -A -s main
```

Or from the phone in one hop:

```sh
ssh user@my-rig.tail12345.ts.net -t tmux new -A -s main
```

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `installed` — tmux on PATH | warning (`doctor` exits 1) |
| `version` — tmux ≥ 3.2 | warning |

## Commands

```sh
abysslink up [--apply]   # install tmux + write the managed conf block
abysslink status         # show rig status
```
