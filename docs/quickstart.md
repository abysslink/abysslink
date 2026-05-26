# Quickstart

Get Abysslink running in five minutes on macOS or Linux.

## Prerequisites

- A machine you want to control remotely (the "rig")
- A Tailscale account (<https://tailscale.com>)
- macOS 13+ or Linux (Ubuntu 22.04+, Debian 12+, Fedora 40+)
- FileVault (macOS) or LUKS (Linux) enabled — Abysslink refuses to proceed if disk is unencrypted

## 1. Install

```sh
curl -fsSL https://abysslink.dev/install.sh | sh
```

The installer downloads the binary, verifies its SHA-256 checksum, optionally verifies the cosign signature if `cosign` is available, and installs to `~/.local/bin/` (non-root) or `/usr/local/bin/` (root).

Alternatively, install via package manager:

```sh
# Homebrew (macOS / Linux)
brew install abysslink/tap/abysslink

# Debian / Ubuntu
sudo apt install abysslink

# Fedora
sudo dnf install abysslink
```

Or build from source:

```sh
go install github.com/abysslink/abysslink/cmd/abysslink@latest
```

## 2. Initialize

Run the interactive setup wizard on your rig:

```sh
abysslink init
```

This creates `~/.config/abysslink/abysslink.yaml` with safe defaults. Review it before proceeding.

## 3. Validate (dry run)

See what `abysslink up` would do without making any changes:

```sh
abysslink up
```

All commands default to dry-run mode. Output shows every change that would be made.

## 4. Apply

When you're happy with the plan:

```sh
abysslink up --apply
```

This will:

1. Verify Tailscale is running and Tailnet Lock is enabled
2. Harden `sshd_config` (backup written to `~/.local/share/abysslink/backups/`)
3. Start the ntfy notification server bound to your tailnet IP
4. Configure tmux with safe defaults
5. Set up file watchers

## 5. Health check

Verify all components are healthy:

```sh
abysslink doctor
```

`doctor` checks disk encryption, SSH config, Tailscale status, ntfy binding, and more. It exits non-zero if any check fails.

## 6. Connect from your phone

Install the Tailscale app on your phone and join your tailnet. Then:

1. Open an SSH client (e.g. [Blink Shell](https://blink.sh) or [Termius](https://termius.com))
2. Connect to your rig's Tailscale hostname (e.g. `ssh user@my-rig.tail12345.ts.net`)
3. Your persistent tmux session is waiting

## Next steps

- Read the [module docs](modules/tailscale.md) to understand what each component configures
- Review the [threat model](security/threat-model.md)
- Set up [Claude Code hooks](modules/claudecode.md) to get notifications when Claude finishes a task
