# Abysslink

> **Across the abyss. Linked.**
>
> Vibe-code Claude from your phone — securely. (And anything else with a terminal.)

Abysslink turns your laptop into a paranoid-by-default dev rig you can drive from your phone over Tailscale. SSH into your tmux session, run Claude Code (or any prompt-shaped tool), get a push the moment something needs you, tap back, type, done.

One Go binary. macOS + Linux. Free + open source. No telemetry, no SaaS, no paid tier.

---

## Status

🚧 **Pre-alpha — design phase.** The product is fully specified in `docs/` but no code is written yet. The first commit is being driven from the docs by Claude Code.

If you're an early adopter or contributor, watch the repo and read [docs/DESIGN.md](docs/DESIGN.md). v1 ETA: 8–12 weeks from first commit.

---

## What it does

1. **Secure terminals from the phone.** SSH into your laptop, attach tmux, run anything — `npm`, `pytest`, `terraform`, `vim`, `htop`, `claude`. Survives wifi↔cell roaming, app backgrounding, the phone locking.
2. **Generic push notifications.** Anything on the laptop can ping the phone:
   ```bash
   abysslink notify -- npm run build               # wrap a command
   abysslink notify "deploy done" "v1.2.3 live"    # fire manually
   abysslink watch add --pane main --idle-secs 30  # watch for idle prompts
   ```
   Claude Code auto-wires into this via the opt-in `claudecode` module. So does `pytest --pdb`, Rails console, your own `read -p` scripts — anything that prompts.
3. **Apps over tailnet (optional).** `abysslink enable code-server` for VS Code in mobile Safari. `abysslink enable ttyd` for a browser terminal. `abysslink enable syncthing` for file sync.
4. **Verifiable & reversible.** Every change Abysslink makes is shown before applied, backed up, audit-logged. `abysslink doctor` catches every footgun in the project's threat model. `abysslink backup restore` undoes any change.

## Why it exists

Setting up a *secure* phone-to-laptop rig today means reading 5–10 blog posts of variable quality, making 30 small decisions (SSO mix, ACL schema, Tailnet Lock policy, mobile-client choice, push-notification stack, keychain handling, power management), and getting every one right because one mistake silently leaves you exposed. The author wrote 7 markdown files documenting his own setup. Abysslink is those files turned into an idempotent binary.

## Quickstart (target — not yet implemented)

```bash
# Install
curl -fsSL https://get.abysslink.dev/install.sh | sh

# Configure (interactive TUI)
abysslink init

# Apply
abysslink up --apply

# Pair your phone
abysslink enroll phone --ios       # or --android
```

Under 10 minutes from first command to working `mosh mac-dev -- tmux new -A -s main` on your phone.

## Documents

| Doc | Read it for |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | Vision, architecture, security model, module catalog, roadmap |
| [docs/IMPLEMENTATION-TASKS.md](docs/IMPLEMENTATION-TASKS.md) | Phased, numbered, acceptance-tested implementation backlog (Claude Code reads this to start) |
| [docs/BUSINESS.md](docs/BUSINESS.md) | Honest monetization roadmap — what's viable, in what order, what to avoid |
| [CLAUDE.md](CLAUDE.md) | Project-level instructions for Claude Code when working in this repo |

## Stack

| Layer | Tool |
|---|---|
| Mesh / private network | [Tailscale](https://tailscale.com) (or Headscale, post-v1) |
| Secure shell | Tailscale SSH (with OpenSSH fallback) |
| Session persistence | tmux + tmux-resurrect |
| Roaming transport | mosh (or Eternal Terminal, opt-in) |
| Push notifications | self-hosted [ntfy](https://ntfy.sh), bound to your tailnet IP only |
| Language | Go 1.22+ |
| License | Apache-2.0 |

## Non-goals

- No custom mobile app in v1. Abysslink *configures* existing apps (Tailscale + Blink/Termius/ConnectBot/Termux + ntfy) via QR codes and printable runbooks.
- No proprietary cloud component. The CLI is local; there is no `api.abysslink.dev` calling home.
- No Tailscale Funnel / public exposure. Ever.
- No telemetry, no usage stats, no version pings.
- No paid tier in v1.

## Contributing

We use DCO sign-off (`git commit -s`), not a CLA. Read [CONTRIBUTING.md](CONTRIBUTING.md) (to be written) once the repo skeleton lands.

## Security

Responsible disclosure to `security@abysslink.dev` (or until that domain is live, open a private security advisory on GitHub). PGP key in `SECURITY.md`. Coordinated 90-day disclosure window.

## License

Apache-2.0. See [LICENSE](LICENSE).
