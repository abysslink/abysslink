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

The installer downloads the release tarball, verifies its SHA-256 against the signed checksum manifest, verifies the cosign signature bundle when `cosign` is available, and installs both `abysslink` and the `abysslinkd` daemon to `/usr/local/bin/` (when run as root) or `~/.local/bin/` (otherwise).

Two environment knobs:

```sh
# Pin a specific release instead of the latest
curl -fsSL https://abysslink.dev/install.sh | ABYSSLINK_VERSION=v3.0.0 sh

# Fail closed when cosign is not installed (instead of warning and continuing)
curl -fsSL https://abysslink.dev/install.sh | ABYSSLINK_REQUIRE_COSIGN=1 sh
```

Or build from source:

```sh
go install github.com/abysslink/abysslink/cmd/abysslink@latest
go install github.com/abysslink/abysslink/cmd/abysslinkd@latest   # daemon — needed for watchers & notify
```

> `go install` builds report their version as `dev (unknown)`, so
> `abysslink upgrade --check` and `abysslink verify` won't work on them.
> Use the installer or a release tarball for signed, upgradable binaries.

> Package-manager installs (`brew install abysslink/tap/abysslink`, `apt`, `dnf`)
> are **planned** but not yet published. Use the installer or `go install` for now.
> Check for newer releases any time with `abysslink upgrade --check`.

## 2. Initialize

Run the interactive setup wizard on your rig:

```sh
abysslink init
```

This creates `~/.config/abysslink/abysslink.yaml` with safe defaults. Review it before proceeding.

### Optional: admin API for full automation

To let Abysslink push the tailnet ACL and mint phone auth keys automatically,
create a Tailscale **OAuth client** at
<https://login.tailscale.com/admin/settings/oauth> with the `devices` and
`auth_keys` scopes. Put the non-secret parts in `abysslink.yaml`:

```yaml
tailnet:
  admin:
    tailnet: you@github          # your tailnet name, or "-" for the default
    oauth_client_id: kxxxxxxxxx  # NOT secret
```

Then export the secret (it is never written to disk):

```sh
export ABYSSLINK_TS_OAUTH_SECRET=tskey-client-xxxxxxxx
```

Without this, `abysslink acl` and `abysslink enroll phone` fall back to manual
mode (clipboard + browser).

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

## 6. Enroll your phone

```sh
abysslink enroll phone
```

This installs Tailscale on the phone (QR to the download page), mints a
single-use tagged auth key and shows it as a QR to scan, waits for the phone to
join the tailnet, shows a QR to subscribe in the ntfy app, and writes a
printable runbook (`~/Documents/abysslink-runbook-*.md`) covering the manual SSO
hardening steps (passkey, disabling SMS 2FA, lock-screen previews).

Then connect from an SSH client:

1. iOS: [Blink Shell](https://blink.sh) (best mosh support) or [Termius](https://termius.com). Android: ConnectBot, or Termux from F-Droid for mosh.
2. Connect to your rig's Tailscale hostname (e.g. `mosh user@my-rig.tail12345.ts.net -- tmux new -A -s main`)
3. Your persistent tmux session is waiting

## Next steps

- Read the [module docs](modules/tailscale.md) to understand what each component configures
- Review the [threat model](security/threat-model.md)
- Set up [Claude Code hooks](modules/claudecode.md) to get notifications when Claude finishes a task
