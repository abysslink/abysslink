# SSH Module

The SSH module hardens `sshd_config` with paranoid-by-default settings.

## What it configures

- Disables password authentication (`PasswordAuthentication no`)
- Disables root login (`PermitRootLogin no`)
- Sets `ClientAliveInterval` and `ClientAliveCountMax` for session keepalive
- Sets `checkPeriod` to 12 hours (cannot be increased without `--accept-checkperiod-extension`)
- Restricts `AllowUsers` to the configured user
- Enables `AuthorizedKeysFile` pointing to a single controlled key file

## Device SSH certificate trust & revocation

On the OpenSSH-fallback backend, enrolled devices (`abysslink enroll phone`)
authenticate with an SSH **certificate** minted by an in-process, keychain-held
device CA — not a static key. `abysslink up --apply` wires that CA into `sshd`
automatically, so a freshly enrolled device works with **no manual copy-paste**:

- The device CA public key is installed to `/etc/ssh/abysslink_device_ca.pub`
  and referenced by `TrustedUserCAKeys` in the hardened drop-in (DEVC-05).
- An OpenSSH **Key Revocation List** built from the store's revoked serials
  (via `ssh-keygen -k`) is installed to `/etc/ssh/abysslink.krl` and referenced
  by `RevokedKeys` (DEVC-06). After `abysslink panic`, `abysslink device revoke`,
  or a re-enroll rotation, the next `up --apply` rebuilds the KRL and `sshd`
  rejects the revoked certificate serials.

Both files install **before** the drop-in that references them, the staged
config is validated with `sshd -t` before the privileged install, and an empty
revocation set still produces a *valid empty* KRL (an unreadable `RevokedKeys`
target would make `sshd` refuse all public-key auth — it never fails open). If
no device CA is enrolled the directives are simply omitted (the legacy hardened
drop-in is installed; `up` is never blocked). These directives are **additive** —
the immutable hardening above is never weakened.

> Tailscale-SSH machines don't use this path: Tailscale brokers device identity
> itself, so no `/etc/ssh` CA-trust or KRL file is installed.

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
| Device CA-trust file matches the enrolled CA | warns (`ca-trust-drift` / `ca-trust-missing`) — run `up --apply` |
| Installed KRL matches the store's revoked serials | warns (`krl-drift` / `krl-missing`) — run `up --apply` |

The two device-cert checks are **report-only drift checks** (warn, never exit 1)
and run only when a device CA is enrolled. When `ssh-keygen` can't decode the
installed KRL the check reports `devssh-unknown` rather than a misleading OK —
it never renders a green ✓ for a control it could not actually verify.

## Commands

```sh
abysslink up [--apply]           # apply SSH hardening (backs up sshd_config first)
abysslink backup ls              # list backups, including sshd_config
abysslink doctor                 # verify SSH config
```
