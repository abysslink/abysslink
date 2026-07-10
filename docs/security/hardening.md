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

LUKS must be the encryption layer for the root filesystem or the partition that contains `/home`. Abysslink runs `lsblk -J -o NAME,TYPE` and scans the device tree for a `TYPE=crypt` device to verify.

!!! warning
    Abysslink does not support eCryptfs, VeraCrypt, or other non-LUKS Linux
    encryption solutions in v1. Use LUKS.

## Tailscale hardening

### Tailnet Lock

Tailnet Lock prevents unauthorized devices from joining your tailnet even with a valid auth key. Enable it with:

```sh
abysslink lock init --apply
```

This wraps `tailscale lock init --gen-disablement=N` and prints the **disablement secrets once** — they are never stored on disk and cannot be recovered from `lock status`. Store them securely offline; losing them risks permanent lockout.

To generate fresh disablement secrets, run `abysslink lock rotate` — it walks you through a manual disable + re-init (intentionally manual, so the secrets are never stored).

### Key expiry

Set key expiry to 90 days or less in the Tailscale admin console. This is a manual step — Abysslink does not check or manage key expiry.

## SSH hardening

In openssh-fallback mode, Abysslink installs a hardened sshd drop-in at `/etc/ssh/sshd_config.d/99-abysslink.conf`, validated with `sshd -t` before reload:

```
# Managed by abysslink — hardened sshd (openssh-fallback mode). Do not edit.
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
AllowUsers <configured user>
```

When the device SSH CA is wired, two additive directives are appended: `TrustedUserCAKeys` and `RevokedKeys` (KRL). In Tailscale SSH mode, session freshness is enforced by the ACL `checkPeriod` (12h) instead.

A timestamped backup is written alongside any mutated file (as `<file>.bak.<timestamp>`) before modification.

## ntfy hardening

ntfy must bind to the Tailscale tailnet IP only. Abysslink derives this address
at runtime using `tailscale ip --4` and writes it to the ntfy server config.

Never configure ntfy to bind to `0.0.0.0` — `abysslink doctor` will fail if it detects this.

## Audit log

All file mutations go through `internal/audit`, which writes:

1. A timestamped backup of the original file, alongside it as `<file>.bak.<timestamp>`
2. An audit log entry (`~/.local/state/abysslink/audit.log`) with timestamp, operation, target path, and diff hash

Secrets are never written to the audit log.

The audit log is a hash-chained, HMAC-signed chain (verify it with `abysslink audit verify`). For an externally verifiable, ed25519-signed export you can hand to an auditor, see [Audit evidence bundles](../operations/audit-evidence.md).

### Audit HMAC key rotation

The HMAC signing key lives in the OS keychain and can be rotated to a fresh **key epoch**:

```sh
abysslink rotate audit-hmac            # preview (dry-run)
abysslink rotate audit-hmac --apply    # rotate
```

The rotation is designed so pre-rotation history stays verifiable:

- The **old key is retained** in the keychain and an in-chain **rotation marker** (signed by the old key) records the hand-off.
- Only entries appended after the rotation are signed under the new key. Verification selects the key by epoch, so a rotated chain still verifies end to end.
- The command never prints the key material (the HMAC key never leaves the machine) — only the new key's **SHA-256 fingerprint**.

The key never leaves the machine, so it also never leaves in-memory unprotected: in-memory secrets are held in mlock'd, zeroized-on-free buffers (`SecureBytes`, MEM-01/02). The `sec-mlock` doctor check reports whether memory locking is available on the host (defense-in-depth; the unlocked fallback still zeroizes on free).

If a rotation is interrupted after the in-chain marker is written but before the keychain pointer advances, subsequent appends **fail closed** and the `sec-audit-epoch` doctor check warns. Re-run `abysslink rotate audit-hmac --apply` to complete the half-finished rotation — see [Troubleshooting](../operations/troubleshooting.md#abysslink-doctor-failures).
