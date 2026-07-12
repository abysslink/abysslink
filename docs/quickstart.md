# Quickstart

Get Abysslink running in well under ten minutes on macOS or Linux.

> **Onboarding time budget (re-measured for v4.1 against the current TUI `init`).**
> Walking the documented steps below on a fresh install:
>
> | Step | What you do | Time |
> |---|---|---|
> | 1. Install | one `curl \| sh` (downloads + verifies + installs both binaries) | ~1 min |
> | 1b. Daemon | `abysslink daemon enable --apply` | ~30 s |
> | 2. Initialize | `abysslink init` — the guided TUI probes tools, asks backend/email/hostname, previews the config (`--yes` non-interactive is faster) | ~2–4 min |
> | 3–4. Validate + Apply | `abysslink up` then `abysslink up --apply` | ~1 min |
> | 5. Health check | `abysslink doctor` | ~15 s |
> | 6. Enroll phone | `abysslink enroll phone --apply` (QR scans + phone joins) | ~2 min |
>
> **Core setup (steps 1–5) lands in ~5 minutes; the full flow including phone enrolment is ~7–8 minutes — inside the 10-minute budget.** The largest variable is the interactive `init` wizard; a non-interactive `abysslink init --yes --email you@example.com` cuts it to ~30 s. The numbers assume Tailscale is already installed and signed in; a first-ever Tailscale login adds a browser round-trip.

## Prerequisites

- A machine you want to control remotely (the "rig")
- A Tailscale account (<https://tailscale.com>)
- **MagicDNS + HTTPS Certificates enabled** for your tailnet (Tailscale admin → [DNS](https://login.tailscale.com/admin/dns)). The daemon serves the tailnet content store, the phone **credential pull**, and the web dashboard over HTTPS with a Tailscale-issued `*.ts.net` certificate (`GetCertificate`); with certificates disabled the TLS handshake fails and the phone sees *"server stopped responding."* Verify on the rig with `tailscale cert <node>.<tailnet>.ts.net` (succeeds when enabled; 500 "does not support getting TLS certs" when not).
- macOS 13+ or Linux (Ubuntu 22.04+, Debian 12+, Fedora 40+)
- FileVault (macOS) or LUKS (Linux) enabled — Abysslink refuses to proceed if disk is unencrypted

## 1. Install

```sh
curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/install.sh | sh
```

The installer downloads the release tarball, verifies its SHA-256 against the signed checksum manifest, verifies the cosign signature bundle when `cosign` is available, and installs both `abysslink` and the `abysslinkd` daemon to `/usr/local/bin/` (when run as root) or `~/.local/bin/` (otherwise).

Two environment knobs:

```sh
# Pin a specific release instead of the latest
curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/install.sh | ABYSSLINK_VERSION=v4.0.1 sh

# Fail closed when cosign is not installed (instead of warning and continuing)
curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/install.sh | ABYSSLINK_REQUIRE_COSIGN=1 sh
```

Or build from source:

```sh
go install github.com/abysslink/abysslink/cmd/abysslink@latest
go install github.com/abysslink/abysslink/cmd/abysslinkd@latest   # daemon — watchers, notify, content store, credential pull
```

(From a source checkout, `make build` produces both `./abysslink` and `./abysslinkd`, and `make install` installs both to `GOBIN`.)

> `go install` builds report their version as `dev (unknown)`, so
> `abysslink upgrade --check` and `abysslink verify` won't work on them.
> Use the installer or a release tarball for signed, upgradable binaries.

> Prefer a package manager? Every release from v4.0.1 on attaches `.deb` and `.rpm`
> assets on the [releases page](https://github.com/abysslink/abysslink/releases).
> The Homebrew tap (`brew tap abysslink/tap`, macOS) is live and receives the cask
> automatically with new releases once publishing credentials finish rolling out —
> until then use the installer above. Check for newer releases any time with
> `abysslink upgrade --check` (exits `3` when a newer release is available).

## 1b. The `abysslinkd` daemon

`abysslinkd` is the long-running background process on your rig. It powers:

- **Watchers** (`abysslink watch`) — push when a tmux pane goes idle, a log matches a regex, or an HTTP endpoint changes status.
- **The notify socket** — `abysslink notify` and the Claude Code hooks deliver through it (falling back to a direct push when it's down).
- **The tailnet content store** — serves opaque notification bodies and the one-scan **credential pull** for `enroll phone` over the tailnet (HTTPS, bound to the tailnet IP only).
- **Ack receipts** — records true phone-side delivery receipts.
- **The phone approve loop** — hosts the `/approve` endpoints that `abysslink approve` and gate enforcement use.
- **The tmux session registry** — detects sessions waiting for input (`needs_input` notifications; on by default, `session_registry` in the config).
- **The dead-man switch timer** — opt-in no-contact lockdown timer (`abysslink deadman`).
- **Metrics + daily digest** — optional Prometheus metrics listener and daily status digest (`observability` in the config).
- **The web dashboard** — opt-in, only in binaries compiled with the `webui` build tag.

The release installer ships it; `go install` and `make install` install it alongside the CLI (see above). Run it as a login service so it starts on boot and stays up:

```sh
abysslink daemon enable --apply   # install + start the launchd (macOS) / systemd --user (Linux) service
abysslink daemon status           # expect: service: running · socket: reachable
abysslink daemon disable --apply  # stop and remove the service
```

Without a running daemon, watchers don't fire, `notify` falls back to a direct push, and `enroll phone` degrades to showing the credentials inline instead of the one-scan pull QR (`daemon not reachable — showing credentials inline`).

> The content store + credential pull serve HTTPS with a Tailscale-issued `*.ts.net` cert, so they need **MagicDNS + HTTPS Certificates enabled** on your tailnet (see Prerequisites). With certs off the daemon still runs, but the phone fetch fails the TLS handshake (*"server stopped responding"*).

## 2. Initialize

Run the interactive setup wizard on your rig:

```sh
abysslink init
```

`init` is a guided setup, not just a config writer. It:

1. Probes the prerequisite tools (`tailscale`, `tmux`, `mosh`, `ntfy`, and optionally `cosign`) and offers to install any that are missing via your platform package manager, then makes sure `tailscaled` is running.
2. On macOS, offers two `sudo` security fixes: enabling the Application Firewall and disabling sleep on AC power.
3. Asks for your backend (Tailscale by default; self-hosted Headscale or NetBird also supported), email, and hostname, then shows a preview of the generated `~/.config/abysslink/abysslink.yaml` for confirmation before writing it.
4. Walks the guided 8-stage setup journey: Account → Prereqs → Converge → Lock → Enroll → Verify → ACL → Done.

Interrupted? Run `abysslink init --resume` to continue from the last completed stage (progress is saved in `journey-state.json`). Non-interactive runs (CI, scripts) must consent explicitly: `abysslink init --yes --email you@example.com` (or set `ABYSSLINK_EMAIL`).

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
2. Harden `sshd_config` (a timestamped backup is written alongside the file as `sshd_config.bak.<timestamp>` and the mutation is recorded in the audit log at `~/.local/state/abysslink/audit.log`)
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

Like every mutating command, `enroll phone` is dry-run by default — run it bare
to preview, then add `--apply` to actually pair:

```sh
abysslink enroll phone --apply
```

This installs Tailscale on the phone (QR to the download page), mints a
single-use tagged auth key and shows it as a QR to scan, waits for the phone to
join the tailnet, shows a QR to subscribe in the ntfy app, and writes a
printable runbook (`~/Documents/abysslink-runbook-*.md`) covering the manual SSO
hardening steps (passkey, disabling SMS 2FA, lock-screen previews).

When the `abysslinkd` daemon is running it also stages the device credentials
and prints **one** single-use QR — scan it to pull every credential (SSH key +
cert, bearer, push token) over the tailnet instead of hand-copying them; it
expires in a few minutes (`content_store.enroll_ttl_seconds`). The one-time
secret box still prints as the source of truth, and `--qr` adds per-credential
QRs as an offline fallback.

Then connect from an SSH client:

1. iOS: [Blink Shell](https://blink.sh) (best mosh support) or [Termius](https://termius.com). Android: ConnectBot, or Termux from F-Droid for mosh.
2. Connect to your rig's Tailscale hostname (e.g. `mosh user@my-rig.tail12345.ts.net -- tmux new -A -s main`)
3. Your persistent tmux session is waiting

## 7. Optional: enable the duress decoy

If you cross borders or otherwise face **casual coercion** ("show me your unlocked laptop"), enrol a duress decoy. It ships OFF; turn it on with a real and a decoy passphrase read from stdin (never argv):

```sh
printf 'your-real-pass\nyour-decoy-pass\n' | abysslink duress enable --apply
```

Then, under coercion, run `abysslink duress unlock` and type the **decoy** passphrase: you get a benign rig view (a quiet machine, no fleet) while your real session is degraded for real in the background (armed agents killed, lockdown latch set). Verify it is live with `abysslink doctor` (`sec-duress` OK).

This mitigates casual coercion for seconds-to-minutes. It is **not** plausible deniability against a forensic adversary, and there is deliberately **no** destructive wipe — full-disk encryption is your real at-rest control. See the [threat model](security/threat-model.md#duress-decoy-what-it-defends-and-what-it-deliberately-does-not).

## Next steps

- Read the [module docs](modules/tailscale.md) to understand what each component configures
- Review the [threat model](security/threat-model.md)
- Set up [Claude Code hooks](modules/claudecode.md) to get notifications when Claude finishes a task
- Learn the ongoing-operations commands in the [CLI reference](cli-reference.md): `abysslink audit verify`, `abysslink audit evidence` (signed evidence bundle) / `audit verify-evidence`, and secret rotation (`abysslink rotate ntfy-creds | anthropic-key | audit-hmac`, all `--apply` to execute). Audit-key rotation is covered in [Hardening → Audit HMAC key rotation](security/hardening.md#audit-hmac-key-rotation).
