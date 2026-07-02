# SSH Module

The SSH module manages the rig's SSH transport in one of two modes:

- **`mode: tailscale`** (default) — Tailscale SSH is the transport. The module
  turns the OpenSSH daemon *off* (macOS Remote Login, or the `sshd`/`ssh`
  systemd unit on Linux) so there is exactly one SSH listener, brokered by
  tailnet identity.
- **`mode: openssh-fallback`** — the module installs a hardened sshd drop-in
  (below) for setups that keep OpenSSH running.

## The hardened drop-in (openssh-fallback mode)

Installed at `/etc/ssh/sshd_config.d/99-abysslink.conf`, validated with
`sshd -t` *before* the privileged install (an invalid staged config is removed
so a later sshd restart can never fail because of it):

```
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
AllowUsers <your-user>
```

When a device CA is enrolled, two additive lines are appended (see below):
`TrustedUserCAKeys /etc/ssh/abysslink_device_ca.pub` and
`RevokedKeys /etc/ssh/abysslink.krl`.

The drop-in contains no `ClientAlive*` directives. Session freshness on the
Tailscale backend is enforced by the ACL `checkPeriod` (12h re-authentication);
the openssh-fallback mode has no equivalent control.

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
modules:
  ssh:
    enabled: true
    mode: tailscale        # or: openssh-fallback

mobile:
  ssh_check_period: "12h"  # Tailscale SSH ACL checkPeriod (not an sshd setting)
```

`ssh_check_period` is enforced as the `checkPeriod` attribute of the Tailscale
SSH ACL rule that `abysslink acl` pushes — it forces re-authentication of
phone sessions every 12 hours. It can be lowered freely; raising it above 12h
requires the explicit `--accept-checkperiod-extension` flag.

## Backup and audit

Every file the module mutates is first backed up as a sidecar
`<file>.bak.<timestamp>` in the same directory as the original. The audit log
at `~/.local/state/abysslink/audit.log` records the diff hash — never the
content.

## `abysslink doctor` checks

Module checks (all warnings — `doctor` exits 1):

| Check | Meaning |
|-------|---------|
| `remote_login` (macOS) | Remote Login is On while `mode: tailscale` — macOS sshd should be off |
| `remote_login_unknown` (macOS) | Remote Login state could not be determined; check System Settings manually |
| `sshd_running` (Linux) | sshd is active while `mode: tailscale` |
| `fallback_config` | `mode: openssh-fallback` but the hardened drop-in is not installed |

Security sweep checks (`sec-ssh-*`, run in every doctor pass; they parse the
effective sshd config and degrade to OK when sshd is not installed):

| Check | Failure behaviour |
|-------|------------------|
| `sec-ssh-permitroot` — `PermitRootLogin yes` | **fatal** (`doctor` exits 2) |
| `sec-ssh-x11forwarding` — `X11Forwarding yes` | warning |
| `sec-ssh-agentforwarding` — `AllowAgentForwarding yes` | warning |
| `sec-ssh-maxauthtries` — `MaxAuthTries > 4` | warning |
| `sec-ssh-logingracetime` — `LoginGraceTime > 60s` | warning |
| `sec-ssh-ciphers` — weak cipher configured | warning |

Device-certificate drift checks (run only when a device CA is enrolled):

| Check | Failure behaviour |
|-------|------------------|
| Device CA-trust file matches the enrolled CA | warns (`ca-trust-drift` / `ca-trust-missing`) — run `up --apply` |
| Installed KRL matches the store's revoked serials | warns (`krl-drift` / `krl-missing`) — run `up --apply` |

The two device-cert checks are **report-only drift checks** (warn, never fatal).
When `ssh-keygen` can't decode the installed KRL the check reports
`devssh-unknown` rather than a misleading OK — it never renders a green ✓ for a
control it could not actually verify.

## Commands

```sh
abysslink up [--apply]           # apply SSH mode (backs up mutated files first)
abysslink backup ls              # list backups
abysslink doctor                 # verify SSH state + sec-ssh-* sweep
```
