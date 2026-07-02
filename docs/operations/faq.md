# FAQ

## General

### What is Abysslink?

Abysslink is a CLI tool that automates a secure phone-to-laptop remote-control setup over Tailscale. It handles the full stack: Tailscale configuration, SSH hardening, tmux/mosh sessions, push notifications, and optional Claude Code integration.

### Why does everything default to `--dry-run`?

Because every change Abysslink makes to your system is potentially disruptive — modifying `sshd_config`, changing firewall rules, restarting services. Defaulting to dry-run means you can review every change before it happens. Pass `--apply` when you're ready.

### Does Abysslink phone home?

No. There is no telemetry in v1, and there never will be unless you explicitly opt in. The binary makes no network requests except to services you configure (Tailscale, ntfy, GitHub for updates).

### Can I use Abysslink without Tailscale?

Tailscale is the default backend, but since v3.0.0 two self-hosted control planes are supported as first-class alternatives: Headscale (`backend.type: headscale`) and NetBird (`backend.type: netbird`), provisioned with `abysslink server headscale init` / `abysslink server netbird init`. The security model still requires an overlay network as the trust boundary — there is no plain-internet mode.

### Does Abysslink support Windows?

No. v1 supports macOS 13+ and Linux (Ubuntu 22.04+, Debian 12+, Fedora 40+). Windows support is not planned.

## Security

### Why is FileVault/LUKS required?

If your laptop is stolen and the disk is unencrypted, the attacker has everything: your SSH keys, Tailscale credentials, source code, secrets. Disk encryption is the last line of defence. Abysslink refuses to operate on an unencrypted disk because the security guarantees would be meaningless.

### Where are secrets stored?

In the OS keychain — the macOS Keychain on macOS; on Linux, `libsecret` (`secret-tool`) or `pass`, probed in that order. Never in plain text on disk. Never in the config file. Never in the audit log.

### Can I disable Tailnet Lock?

You can, but Abysslink will warn loudly and `doctor` will fail. Tailnet Lock prevents unauthorized devices from joining your tailnet even if your auth key is compromised — disabling it is a meaningful security regression.

### Why is Tailscale Funnel blocked?

Funnel exposes services to the public internet. That is fundamentally incompatible with the threat model. There is no configuration option to enable it — it is rejected at the YAML schema level.

## Claude Code integration

### Does Abysslink depend on Claude Code?

No. The `claudecode` module is one opt-in consumer of the generic notification system. The core Abysslink modules (Tailscale, SSH, tmux, mosh, ntfy, watch) have no dependency on Claude.

### How do I get notified when Claude finishes?

1. Enable the claudecode module: `abysslink enable claudecode --apply` (sets `claudecode.enabled: true` in `abysslink.yaml`)
2. Run `abysslink up --apply` to install the hooks
3. Enroll your phone: `abysslink enroll phone --apply` — one QR scan pulls the device credentials (bearer + push token) over the tailnet. Manually subscribing to a topic in the ntfy app does not work: the rig's ntfy server runs deny-all authentication, so anonymous subscriptions are rejected
4. Start a Claude session — you'll get a push notification when it completes

## Releases and updates

### How do I update Abysslink?

```sh
curl -fsSL https://abysslink.dev/install.sh | sh
```

The installer always fetches the latest release by default. Pin a version with `ABYSSLINK_VERSION=v3.0.2`.

### How are releases signed?

Releases are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) using keyless signing via GitHub OIDC. The install script verifies the signature automatically if `cosign` is installed.

### Is there a Homebrew tap?

Not yet. The release pipeline is wired for `abysslink/tap`, but the tap is not published. Use the install script or `go install` for now (see the [Quickstart](../quickstart.md)).
