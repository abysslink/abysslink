# SSH Module

The SSH module hardens `sshd_config` with paranoid-by-default settings.

## What it configures

- Disables password authentication (`PasswordAuthentication no`)
- Disables root login (`PermitRootLogin no`)
- Sets `ClientAliveInterval` and `ClientAliveCountMax` for session keepalive
- Sets `checkPeriod` to 12 hours (cannot be increased without `--accept-checkperiod-extension`)
- Restricts `AllowUsers` to the configured user
- Enables `AuthorizedKeysFile` pointing to a single controlled key file

## Configuration

```yaml
ssh:
  check_period: "12h"   # minimum enforced; cannot be raised without explicit flag
  allow_users:
    - myuser
  authorized_keys_file: "~/.ssh/authorized_keys"
```

## Backup and audit

Every modification to `sshd_config` is preceded by a backup written to
`~/.local/share/abysslink/backups/` with a timestamp in the filename. The
audit log records the diff hash (never the content).

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `PasswordAuthentication no` | `doctor` exits 1 |
| `PermitRootLogin no` | `doctor` exits 1 |
| `checkPeriod` ≤ 12h | `doctor` exits 1 |
| Authorized keys file exists | `doctor` exits 1 |

## Commands

```sh
abysslink up [--apply]           # apply SSH hardening
abysslink backup --component ssh # backup current sshd_config
abysslink doctor                 # verify SSH config
```
