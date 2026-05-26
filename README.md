# Abysslink

> **Across the abyss. Linked.**
>
> Vibe-code Claude from your phone — securely. (And anything else with a terminal.)

Abysslink turns your laptop into a paranoid-by-default dev rig you can drive from your phone over Tailscale. SSH into your tmux session, run Claude Code, get a push notification the moment something needs you, tap back in, type, done.

One Go binary. macOS + Linux. Free + open source. No telemetry, no SaaS, no paid tier.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/abysslink/abysslink/main/scripts/install.sh | sh
```

Or download a release binary from [Releases](https://github.com/abysslink/abysslink/releases) and drop it in your PATH.

Verify the cosign signature:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/abysslink/abysslink' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle abysslink_linux_amd64.bundle \
  abysslink_linux_amd64
```

---

## Quickstart

```bash
# 1. Interactive setup wizard
abysslink init

# 2. Preview what will change (dry-run is the default)
abysslink up

# 3. Apply when ready
abysslink up --apply

# 4. Pair your phone (shows ANSI QR code)
abysslink enroll phone --ios      # or --android

# 5. Health check
abysslink doctor
```

Under 10 minutes from first command to working `mosh mac-dev -- tmux new -A -s main` on your phone.

---

## What it does

### 1. Secure terminals from anywhere

SSH into your laptop, attach tmux, run anything. Survives wifi↔cell roaming, app backgrounding, and the phone locking.

```bash
# On your phone (via Blink, Termius, or Termux)
mosh mac-dev -- tmux new -A -s main
```

### 2. Push notifications from any process

```bash
abysslink notify "deploy done" "v1.2.3 is live"    # manual ping
abysslink notify -- npm run build                    # wrap a command
abysslink watch add --pane main --idle-secs 30      # watch for idle prompts
```

The `claudecode` opt-in module auto-wires Claude Code's Stop hook into this — get a push every time Claude finishes a task. Your phone buzzes; you tap back in; you type the next instruction.

### 3. Everything is auditable and reversible

Every change Abysslink makes is:
- Shown in dry-run before applied
- Backed up (`abysslink backup restore <timestamp>`)
- Written to a tamper-evident audit log (JSON-lines, no secrets in body)

```bash
abysslink logs                          # tail the audit log
abysslink backup restore 2026-01-15     # undo any change
abysslink doctor                        # check every footgun from the threat model
```

### 4. Emergency revocation in one command

```bash
abysslink panic
```

No confirmation prompt. Tears down the Tailscale session, revokes auth keys, notifies you via ntfy. Completes in under 10 seconds.

---

## Commands

| Command | What it does |
|---------|-------------|
| `abysslink init` | Interactive TUI wizard — writes `abysslink.yaml` |
| `abysslink up [--apply]` | Converge all enabled modules (dry-run by default) |
| `abysslink status [--json]` | One-screen health summary |
| `abysslink doctor` | Deep health check; exits 0/1/2 by severity |
| `abysslink repair` | Auto-fix doctor findings where possible |
| `abysslink enroll phone` | Mint auth key, show QR, poll for device join |
| `abysslink notify <title> <body>` | Fire a push notification |
| `abysslink watch add/list/remove` | Manage idle/file/HTTP watchers |
| `abysslink panic` | Emergency revocation — no prompt, immediate |
| `abysslink logs` | Tail the audit log |
| `abysslink backup restore <ts>` | Restore a previous file state |
| `abysslink acl edit/show/push` | Manage Tailnet ACLs (HuJSON round-trip) |
| `abysslink lock init/status` | Manage Tailnet Lock |
| `abysslink enable/disable <module>` | Toggle optional modules |
| `abysslink upgrade` | Self-update with cosign signature verification |
| `abysslink threat-model` | Print the project threat model |
| `abysslink uninstall` | Remove everything Abysslink installed |

---

## Modules

### Core (always available)

| Module | What it configures |
|--------|-------------------|
| `tailscale` | Installs + starts tailscaled; verifies connectivity |
| `ssh` | Tailscale SSH with 12h check period; MagicDNS hostname |
| `tmux` | tmux + tmux-resurrect; session persistence config |
| `mosh` | mosh server; UDP 60000–61000 ACL grant |
| `ntfy` | Self-hosted ntfy server bound to tailnet IP only |
| `notify` | Notification dispatcher (wraps ntfy backend) |
| `watch` | Idle-pane / file-tail / HTTP-change watchers |
| `acl` | Tailnet ACL: tag:mobile → tag:laptop grants |
| `lock` | Tailnet Lock: init, rotate, verify |
| `power` | caffeinate / systemd-inhibit to prevent sleep |
| `hardening` | FileVault (macOS) / LUKS (Linux) enforcement |

### Optional

| Module | What it adds |
|--------|-------------|
| `claudecode` | Claude Code Stop hook → `abysslink notify`; API key in keychain |
| `code-server` | VS Code in the browser, tailnet-IP-only, HTTPS |
| `ttyd` | Browser terminal via ttyd, tailnet-IP-only |
| `eternal-terminal` | ET server for connection-resuming sessions |

Enable any optional module:

```bash
abysslink enable claudecode --apply
```

---

## Security model

- **No Tailscale Funnel.** Permanently rejected at the YAML schema level. Services bind to your tailnet IP only.
- **Tailnet Lock on by default.** Disablement secrets are printed once to stdout and never stored on disk.
- **No secrets on argv.** API keys and passwords go through stdin or the OS keychain (macOS `security`, Linux `secret-tool`/`pass`).
- **No secrets in the audit log.** Entries record titles and diff hashes — never body content.
- **SSH checkPeriod is 12h** and can only be lowered, not raised, without an explicit flag.
- **FileVault / LUKS required.** `abysslink doctor` fails closed (exit 2) if disk is unencrypted.
- **Cosign-verified upgrades.** `abysslink upgrade` refuses to replace the binary without a valid sigstore signature. Refuses to run as root.
- **No telemetry.** The binary makes no outbound calls except to Tailscale's local API and your own ntfy server.

See [docs/threat-model.md](docs/threat-model.md) for the full threat model and mitigations.

---

## Stack

| Layer | Tool |
|-------|------|
| Mesh / private network | [Tailscale](https://tailscale.com) |
| Secure shell | Tailscale SSH (OpenSSH fallback) |
| Session persistence | tmux + tmux-resurrect |
| Roaming transport | mosh (Eternal Terminal opt-in) |
| Push notifications | Self-hosted [ntfy](https://ntfy.sh), tailnet-only |
| Browser IDE (opt-in) | code-server |
| Browser terminal (opt-in) | ttyd |
| Language | Go 1.23+ |
| License | Apache-2.0 |

---

## Platform support

| Platform | Support |
|----------|---------|
| macOS 13 (Ventura) | Tier 1 |
| macOS 14 (Sonoma) | Tier 1 |
| macOS 15 (Sequoia) | Tier 1 |
| Ubuntu 22.04 / 24.04 | Tier 1 |
| Debian 12 | Tier 1 |
| Fedora 40 | Tier 1 |
| RHEL / CentOS 9 | Tier 2 |
| Arch Linux | Tier 2 |
| NixOS (flake) | Tier 2 |

---

## Nix

```bash
nix build github:abysslink/abysslink#abysslink
```

Or add to your flake:

```nix
inputs.abysslink.url = "github:abysslink/abysslink";
```

---

## Configuration

Abysslink reads `~/.config/abysslink/abysslink.yaml` (or `--config` override). The `init` wizard writes it interactively. See [abysslink.yaml.example](abysslink.yaml.example) for annotated reference.

Key defaults:

```yaml
version: 1
tailnet:
  ssh: true
  lock:
    enabled: true
  check_period: 12h
modules:
  ntfy:
    enabled: false          # set true after abysslink up --apply
    bind_addr: ""           # filled in by `up` — never 0.0.0.0
```

---

## Contributing

DCO sign-off required (`git commit -s`), not a CLA. Read [CONTRIBUTING.md](CONTRIBUTING.md).

Lint and test:

```bash
make lint test
```

Run conformance suite against a built binary:

```bash
make conformance
```

---

## Security disclosure

Report vulnerabilities via GitHub's private security advisory. 90-day coordinated disclosure window. Details in [SECURITY.md](SECURITY.md).

---

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## Docs

Full documentation at [docs/](docs/) or the hosted site (coming soon).

| Doc | Read it for |
|-----|-------------|
| [docs/DESIGN.md](docs/DESIGN.md) | Vision, architecture, security model, module catalog |
| [docs/IMPLEMENTATION-TASKS.md](docs/IMPLEMENTATION-TASKS.md) | Phased implementation backlog |
| [docs/BUSINESS.md](docs/BUSINESS.md) | Monetization roadmap |
| [CLAUDE.md](CLAUDE.md) | Instructions for Claude Code working in this repo |
