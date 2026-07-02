# Abysslink

**Vibe-code Claude from your phone.**

Abysslink automates a paranoid-by-default phone-to-laptop remote-control setup over Tailscale. One command to set it all up, one command to bring it up every morning.

```sh
abysslink up --apply
```

## What it does

Abysslink orchestrates the full stack required to securely control your development machine from a phone:

- **Tailscale** — mesh VPN, Tailnet Lock, key expiry management; self-hosted [Headscale](headscale-ha.md) and NetBird control planes are supported backends too
- **SSH** — hardened `sshd_config`, device SSH certificates (CA-signed, revocable), `checkPeriod` enforcement
- **tmux / mosh** — persistent sessions that survive network interruptions
- **ntfy** — push notifications bound to the tailnet IP only, never the open internet
- **abysslinkd** — background daemon: watchers, notify socket, tailnet content store + credential pull, session registry, phone approve loop
- **watch** — filesystem and process event monitoring
- **claudecode** — Claude Code hook integration for remote AI-assisted coding sessions
- **Agent safety** — phone approve loop, `arm` kill-switch (shadow mode by default), opt-in dead-man switch, `panic` lockdown
- **Fleet** — enroll and control multiple rigs from one phone (`--rig` / `--all-rigs`)
- **Optional modules** — code-server, ttyd, Eternal Terminal, Syncthing, UpSnap, Atuin, sandbox, asciinema

See the [CLI reference](cli-reference.md) and [configuration reference](configuration.md) for the full surface.

## Why Abysslink?

Setting up a secure remote rig by hand takes hours and leaves footguns everywhere. The original 7-file setup guide that inspired this project documented every pitfall: Tailscale Funnel accidentally enabled, ntfy bound to `0.0.0.0`, SSH `checkPeriod` set too high, disk encryption skipped. Abysslink encodes every safety check as a first-class `abysslink doctor` assertion that fails closed.

## Quick links

- [Quickstart](quickstart.md) — install and run in five minutes
- [Security / Threat Model](security/threat-model.md) — what we protect against
- [Contributing](contributing.md) — how to contribute

## Status

Abysslink ships signed, tagged releases — see the [Releases page](https://github.com/abysslink/abysslink/releases) for the current version. All destructive commands default to `--dry-run`; pass `--apply` to make changes.
