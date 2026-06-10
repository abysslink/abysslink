# FAQ

## General

### What is Abysslink?

Abysslink is a CLI tool that automates a secure phone-to-laptop remote-control setup over Tailscale. It handles the full stack: Tailscale configuration, SSH hardening, tmux/mosh sessions, push notifications, and optional Claude Code integration.

### Why does everything default to `--dry-run`?

Because every change Abysslink makes to your system is potentially disruptive — modifying `sshd_config`, changing firewall rules, restarting services. Defaulting to dry-run means you can review every change before it happens. Pass `--apply` when you're ready.

### Does Abysslink phone home?

No. There is no telemetry in v1, and there never will be unless you explicitly opt in. The binary makes no network requests except to services you configure (Tailscale, ntfy, GitHub for updates).

### Can I use Abysslink without Tailscale?

No. Tailscale is the only supported VPN in v1. The entire security model is built around the tailnet being the trust boundary. Support for Headscale (self-hosted Tailscale control plane) and NetBird is planned for v2+.

### Does Abysslink support Windows?

No. v1 supports macOS 13+ and Linux (Ubuntu 22.04+, Debian 12+, Fedora 40+). Windows support is not planned.

## Security

### Why is FileVault/LUKS required?

If your laptop is stolen and the disk is unencrypted, the attacker has everything: your SSH keys, Tailscale credentials, source code, secrets. Disk encryption is the last line of defence. Abysslink refuses to operate on an unencrypted disk because the security guarantees would be meaningless.

### Where are secrets stored?

In the OS keychain (macOS Keychain, Linux `libsecret`). Never in plain text on disk. Never in the config file. Never in the audit log.

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
3. Install ntfy on your phone and subscribe to your rig's topic
4. Start a Claude session — you'll get a push notification when it completes

## Releases and updates

### How do I update Abysslink?

```sh
curl -fsSL https://abysslink.dev/install.sh | sh
```

The installer always fetches the latest release by default. Pin a version with `ABYSSLINK_VERSION=v0.2.0`.

### How are releases signed?

Releases are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) using keyless signing via GitHub OIDC. The install script verifies the signature automatically if `cosign` is installed.

### Is there a Homebrew tap?

Yes: `brew install abysslink/tap/abysslink`. The tap is updated automatically on each release.
