# Troubleshooting

Common issues and their resolutions. Run `abysslink doctor` first — it catches most problems automatically.

## `abysslink doctor` failures

### `disk_encryption: FAIL — FileVault not enabled`

FileVault is not active on your Mac. Enable it:

```sh
sudo fdesetup enable
```

Then reboot and wait for encryption to complete before retrying.

### `disk_encryption: FAIL — LUKS not detected`

Your Linux root filesystem is not LUKS-encrypted. Abysslink cannot help you encrypt an already-running system. You must reinstall with LUKS encryption enabled. Most Linux distributions offer this as an option in their installer.

### `tailscale: FAIL — Tailscale not running`

Start Tailscale:

```sh
# macOS
open -a Tailscale

# Linux (systemd)
sudo systemctl start tailscaled
tailscale up
```

### `tailscale: FAIL — Tailnet Lock not enabled`

Enable Tailnet Lock:

```sh
tailscale lock init
```

Follow the prompts. Store the rotation secret securely.

### `ssh: FAIL — PasswordAuthentication is enabled`

Abysslink's SSH hardening has not been applied, or was manually reverted. Re-apply:

```sh
abysslink up --apply
```

Then verify sshd reloaded the config:

```sh
sudo systemctl reload sshd   # Linux
sudo launchctl kickstart -k system/com.openssh.sshd  # macOS
```

### `ntfy: FAIL — bound to 0.0.0.0`

ntfy is bound to all interfaces. Edit `/etc/ntfy/server.yml` and set:

```yaml
listen-http: "<your-tailnet-ip>:2586"
```

Get your tailnet IP:

```sh
tailscale ip --1
```

Then restart ntfy and re-run `doctor`.

### `ntfy: FAIL — ntfy not running`

Start ntfy:

```sh
sudo systemctl start ntfy
```

Or re-run `abysslink up --apply` to install and start ntfy.

## Connection issues

### SSH connection refused

1. Verify Tailscale is running on both devices: `tailscale status`
2. Verify sshd is running: `sudo systemctl status sshd` (Linux) or `sudo launchctl list com.openssh.sshd` (macOS)
3. Verify your public key is in `~/.ssh/authorized_keys`
4. Check sshd logs: `journalctl -u sshd --since "10 minutes ago"` (Linux) or `/var/log/secure` (macOS)

### mosh connection fails

mosh requires UDP ports 60000–61000. If you are behind a corporate firewall, these may be blocked. Fall back to SSH:

```sh
ssh user@my-rig.tail12345.ts.net
```

### ntfy notifications not arriving

1. Verify your phone is connected to Tailscale
2. Verify ntfy is running: `abysslink doctor`
3. Verify the ntfy topic subscription URL matches the tailnet IP: `http://<tailnet-ip>:2586/abysslink`
4. Send a test notification: `abysslink notify "test"`

## Getting more information

Enable verbose logging:

```sh
abysslink --log-level debug doctor
```

Check the audit log:

```sh
abysslink logs
```

Check the daemon logs:

```sh
journalctl -u abysslinkd --since "1 hour ago"   # Linux
log show --predicate 'process == "abysslinkd"' --last 1h  # macOS
```
