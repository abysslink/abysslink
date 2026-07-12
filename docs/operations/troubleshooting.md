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

ntfy is bound to all interfaces. The simplest fix is to re-run `abysslink up --apply`, which regenerates the managed config with the tailnet-only bind.

To fix by hand, edit `~/.config/ntfy/server.yml` (native Linux) or `~/.config/ntfy/server-docker.yml` (Docker mode, used on macOS) and set:

```yaml
listen-http: "<your-tailnet-ip>:2586"
```

Get your tailnet IP:

```sh
tailscale ip --4
```

Then restart ntfy and re-run `doctor`:

```sh
systemctl --user restart dev.abysslink.ntfy   # Linux (user unit)
docker restart abysslink-ntfy                 # macOS (Docker container)
```

### `ntfy: FAIL — ntfy not running`

Start the managed ntfy service:

```sh
systemctl --user start dev.abysslink.ntfy   # Linux (user unit)
docker start abysslink-ntfy                 # macOS (Docker container)
```

Or re-run `abysslink up --apply` to install and start ntfy.

### `sec-audit-epoch: WARN — audit key rotation is incomplete … appends fail closed`

A previous `abysslink rotate audit-hmac` recorded the in-chain rotation marker but did not advance the keychain key-epoch pointer (the documented rotation crash window). Until it is completed, every new audit append **fails closed**. Complete the half-finished rotation:

```sh
abysslink rotate audit-hmac --apply
```

The command detects the interrupted state and finishes it (advances the pointer, re-anchors). Then confirm with `abysslink audit verify`.

### `sec-mlock: WARN — cannot lock secret memory (RLIMIT_MEMLOCK too low)`

This is a defense-in-depth posture warning, never fatal — in-memory secrets still fall back to unlocked, zeroized-on-free buffers. To restore the mlock protection, raise the locked-memory limit:

```sh
ulimit -l unlimited                 # current shell (or a specific KB value)
```

In a container, pass `--ulimit memlock=-1` (Docker) or the equivalent. On systemd services, set `LimitMEMLOCK=infinity` in the unit. The `at-risk` profile does **not** escalate this to FATAL, since the operator may be unable to raise a host kernel limit.

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
3. Verify the phone is enrolled: `abysslink device ls`. The rig's ntfy server runs deny-all auth, so a manually-added anonymous topic subscription is rejected — the phone must hold the per-device credentials from `abysslink enroll phone --apply`
4. Send a test notification: `abysslink notify "test"`

### Push delivery problems (`push-gateway` doctor group)

`abysslink doctor` runs a dedicated `push-gateway` group of checks (gateway credentials in the daemon, credential-file permissions and location, stale device push tokens, experimental APNs/FCM flags, ntfy.sh third-party routing, content-store bind). Fix any FATAL findings there first.

Then watch the delivery counters while sending a test:

1. `abysslink notify "test"`
2. `abysslink status` — `wake_sent` should increment when the wake is delivered, and `ack_received` after the phone fetches the content

The daemon-side outbox counters `gateway_queued` (should increment within ~30 s of the notify) and `gateway_sent` (within one retry cycle, ~5 s, after that) are exposed on the daemon's `/status` endpoint; the [real-device test runbook](../testing/push-real-device.md) walks the full check, including what to do when either counter stays at 0.

### `enroll phone` shows credentials inline instead of one pull QR

The one-scan credential pull needs the `abysslinkd` daemon and a tailnet HTTPS certificate:

1. `abysslink daemon status` — expect `service: running · socket: reachable`; if not, `abysslink daemon enable --apply`
2. MagicDNS + HTTPS Certificates must be enabled for your tailnet (Tailscale admin → DNS). Verify on the rig with `tailscale cert <node>.<tailnet>.ts.net` — with certs off the phone's fetch fails the TLS handshake ("server stopped responding")
3. The staged pull QR is single-use and expires after `content_store.enroll_ttl_seconds` — re-run `abysslink enroll phone --apply` if it lapsed

### Approve prompts never reach the phone / tools are denied

- The approve loop is hosted by the daemon. `abysslink approve --check` denies (exit 2) when the daemon socket is unreachable — check `abysslink daemon status`
- `gate.enforcing` defaults to `false` (shadow mode): nothing blocks until you set it to `true` in `abysslink.yaml`
- An unanswered request times out to a deny after `approval.timeout_seconds` (default 120 s)

### Dead-man switch questions

- `abysslink deadman status` shows the time remaining; `abysslink deadman heartbeat` resets the deadline
- The timer is hosted by `abysslinkd` and is restart-safe. After `deadman enable --apply`, restart the daemon (`abysslink daemon stop --apply` then `abysslink daemon start --apply`) to pick up the change
- If `status` reports the deadline has elapsed, lockdown fires on the next daemon tick

## Getting more information

Enable verbose logging:

```sh
abysslink -v doctor
```

Check the audit log:

```sh
abysslink logs
```

Check the daemon logs:

```sh
journalctl --user -u dev.abysslink.abysslinkd --since "1 hour ago"   # Linux
log show --predicate 'process == "abysslinkd"' --last 1h  # macOS
```

## First-run stumbles

Things people hit in the first ten minutes. None of them mean anything is broken.

### Fresh machine: `doctor` exits 2 with a DANGER box pointing at `repair`

On a machine that has never run `abysslink up --apply`, `abysslink doctor` exits 2 and ends in a red DANGER box telling you to run `repair --apply`.

**Cause:** the audit log does not exist until the first apply, and its absence is scored as a fatal finding — even though there is nothing to repair yet.

**Fix:** ignore the box on a fresh machine. Run the normal setup instead:

```sh
abysslink init
abysslink up --apply
```

The first apply creates the audit log and the finding clears. (The box text is being improved to say this itself.)

### `abysslink --version` errors with an unknown flag

The version is a subcommand, not a flag:

```sh
abysslink version
```

### `notify` fails with `daemon client: notify rejected: HTTP 502`

The daemon is up and accepted the request, but its ntfy backend isn't reachable — typically because ntfy has not been converged yet, or its service is down.

**Fix:** confirm the daemon first, then converge ntfy:

```sh
abysslink daemon status
abysslink up --apply
```

If you don't want the ntfy module at all, turn it off instead:

```sh
abysslink disable ntfy --apply
```

### macOS 26: `doctor` says "Application Firewall is disabled" when it is enabled

Known false positive: macOS 26 changed the JSON keys `system_profiler` emits for the firewall state, so the check misreads an enabled firewall as disabled. The fix is tracked in the issue tracker.

**Fix:** verify the real state manually and disregard the finding when it reports enabled:

```sh
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
```

### `abysslink version` prints `dev (unknown)`

Expected for source builds (`go install`, `go build`): release version and provenance metadata are injected only by the release pipeline. Everything works except `abysslink verify` and `abysslink upgrade`, which need a released binary — use the installer script, Homebrew, or a release tarball for signed, upgradable binaries.
