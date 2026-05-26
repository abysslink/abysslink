# Hardening

Abysslink enforces a minimum security baseline. This page documents each requirement and how to satisfy it.

## Disk encryption (required)

`abysslink doctor` fails closed if disk encryption is not active.

### macOS — FileVault

Check status:

```sh
fdesetup status
```

Enable:

```sh
sudo fdesetup enable
```

FileVault must be fully enabled (not just "encryption in progress") for `doctor` to pass.

### Linux — LUKS

Check status:

```sh
lsblk -o NAME,TYPE,MOUNTPOINT | grep crypt
# or
sudo dmsetup status
```

LUKS must be the encryption layer for the root filesystem or the partition that contains `/home`. Abysslink checks `/proc/mounts` and `/proc/crypto` to verify.

!!! warning
    Abysslink does not support eCryptfs, VeraCrypt, or other non-LUKS Linux
    encryption solutions in v1. Use LUKS.

## Tailscale hardening

### Tailnet Lock

Tailnet Lock prevents unauthorized devices from joining your tailnet even with a valid auth key. Enable it in the Tailscale admin console or via CLI:

```sh
tailscale lock init
```

Print the rotation secret once and store it securely offline:

```sh
tailscale lock status
```

Abysslink prints the rotation secret **once** at setup time and never stores it.

### Key expiry

Set key expiry to 90 days or less in the Tailscale admin console. Abysslink checks key expiry at startup and warns if expiry is within 7 days.

## SSH hardening

Abysslink writes a hardened `sshd_config` fragment. Key settings:

```
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
AllowUsers <configured user>
ClientAliveInterval 120
ClientAliveCountMax 3
```

A backup of the original `sshd_config` is written before any modification.

## ntfy hardening

ntfy must bind to the Tailscale tailnet IP only. Abysslink derives this address
at runtime using `tailscale ip --1` and writes it to the ntfy server config.

Never configure ntfy to bind to `0.0.0.0` — `abysslink doctor` will fail if it detects this.

## Audit log

All file mutations go through `internal/audit`, which writes:

1. A backup of the original file to `~/.local/share/abysslink/backups/`
2. An audit log entry with timestamp, operation, target path, and diff hash

Secrets are never written to the audit log.
