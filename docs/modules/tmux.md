# tmux Module

The tmux module creates and manages a persistent named session on your rig so your remote work survives network interruptions.

## What it configures

- Creates a persistent tmux session named `abysslink` (configurable)
- Sets a scrollback buffer appropriate for remote use (default: 10,000 lines)
- Configures status bar with hostname and Tailscale IP
- Writes a minimal `~/.tmux.conf` that does not override user settings

## Configuration

```yaml
tmux:
  session_name: "abysslink"
  scrollback: 10000
  start_on_boot: true
```

## Usage

After `abysslink up --apply`, connect and attach to the persistent session:

```sh
ssh user@my-rig.tail12345.ts.net tmux attach -t abysslink
```

Or open a shell and attach manually:

```sh
tmux attach -t abysslink
```

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| tmux installed | warning (non-fatal) |
| Session exists | warning (non-fatal) |

## Commands

```sh
abysslink up [--apply]   # configure tmux session
abysslink status         # show tmux session status
```
