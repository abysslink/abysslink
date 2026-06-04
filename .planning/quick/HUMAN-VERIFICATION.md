# Abysslink — Human Verification Checklist (security hardening, slices 1–8)

Run these on a real macOS/Linux rig once you're ready. Automated tests already
pass (`make lint test`); this covers behavior that needs a human + real Tailscale
account + a phone.

## Prerequisites
- [ ] Tailscale account created; `tailscale` reachable.
- [ ] (For full automation) OAuth client created at login.tailscale.com/admin/settings/oauth
      (scopes: devices, auth_keys); `tailnet.admin.tailnet` + `tailnet.admin.oauth_client_id`
      in abysslink.yaml; `export ABYSSLINK_TS_OAUTH_SECRET=tskey-client-...`
- [ ] FileVault (macOS) / LUKS (Linux) ENABLED.

## Golden path
- [ ] `abysslink init` writes ~/.config/abysslink/abysslink.yaml.
- [ ] `abysslink up` (dry-run) prints a plan, mutates nothing.
- [ ] `abysslink up --apply` installs tailscale/tmux/mosh/ntfy, opens the browser
      for SSO login, enables Tailscale SSH, sets hostname + auto-update.
- [ ] Re-run `abysslink up --apply` → near no-op (idempotent), no second backups.
- [ ] `abysslink doctor` → all green.

## Fail-closed gates (security-critical)
- [ ] Disable FileVault/LUKS → `abysslink up --apply` REFUSES (mentions disk encryption).
      `--force-unsafe` overrides with a loud warning.
- [ ] Set `ssh_check_period: 24h` → `up --apply` REFUSES unless `--accept-checkperiod-extension`.
- [ ] Manually enable Funnel (`tailscale funnel 443 on`) → `abysslink doctor` and
      `abysslink threat-model` flag it FATAL/✗.

## Tailnet Lock
- [ ] `abysslink lock init --apply` prints disablement secrets ONCE, demands the
      attestation confirmation, never writes them to disk (grep audit.log — only hashes).
- [ ] `abysslink lock status` reports enabled.

## ACL
- [ ] `abysslink acl diff` shows the mobile→laptop grant (tcp/22 + udp/60000-61000) + SSH rule.
- [ ] `abysslink acl push` converges; `abysslink acl validate` → valid + converged.
- [ ] Without OAuth creds: `acl push` falls back to clipboard + opens the admin editor.

## Daemon + notifications
- [ ] `abysslink daemon enable` then `abysslink daemon status` → service running, socket reachable.
- [ ] `abysslink notify "test" "hi"` → phone buzzes (delivered via socket).
- [ ] Leave a tmux pane idle at a prompt → idle "waiting for input" notification fires.
- [ ] `abysslink watch add --file ./build.log --grep FAILED` → append a matching line → notification.
- [ ] `abysslink watch add --http https://staging/health --expect 200` → status change → notification.
- [ ] `abysslink watch list` shows pane/file/http; `watch remove --file ...` removes it.
- [ ] Stop daemon → `abysslink notify` still works (direct fallback).

## Enroll phone
- [ ] `abysslink enroll phone` → download QR, auth-key QR (admin mode), polls for join,
      ntfy subscription QR, runbook written to ~/Documents/abysslink-runbook-*.md.

## claudecode (if enabled)
- [ ] `abysslink enable claudecode` + `up --apply` writes ~/.claude/settings.json with
      Notification + Stop hooks calling `abysslink notify`.
- [ ] With `ANTHROPIC_API_KEY` exported, the key is stored in keychain (not left in env/argv).
- [ ] After reboot (macOS), `abysslink doctor` flags the locked-keychain state until console login.

## Reversibility (Success Criteria #4)
- [ ] `abysslink backup ls` lists modified files.
- [ ] `abysslink uninstall` (dry-run) shows the reverse plan.
- [ ] `abysslink uninstall --apply` restores every touched file to its pre-abysslink
      content (or deletes files abysslink created), prints a SHA-256 manifest, removes
      ~/.config/abysslink. Confirm originals are byte-identical.
- [ ] `--purge` also removes the state dir.

## Rotation + panic
- [ ] `export ABYSSLINK_NEW_ANTHROPIC_KEY=...; abysslink rotate anthropic-key --apply`
      → verifies the key against the API, stores it, opens console to revoke old.
- [ ] `abysslink rotate ntfy-creds --apply` → new password, ntfy updated, keychain updated.
- [ ] `abysslink panic` → disconnects tailnet, revokes phone via admin API, deletes the
      local Anthropic key from keychain, audit-logs each action (no confirmation prompt).

## Optional terminals (if enabled)
- [ ] `abysslink enable code-server` + `up --apply` → installed, config bound to tailnet IP,
      password in keychain, service running. Reachable from phone browser over tailnet only.
- [ ] ttyd / eternal-terminal similar (bind tailnet IP only).

## Cross-platform
- [ ] Repeat golden path on a Linux distro (Ubuntu/Fedora/Arch) — installs via apt/dnf/pacman
      (sudo), systemd --user services, LUKS check, secret-tool/pass keychain.

## Conformance suite (automated)

Run before any release. Requires a freshly built binary (uses `ABYSSLINK_BIN`):

```sh
make conformance          # 15 scenarios, all must pass
make security-audit       # conformance + telemetry grep
```

Or manually:
```sh
go build -o /tmp/abysslink-current ./cmd/abysslink
ABYSSLINK_BIN=/tmp/abysslink-current go run ./cmd/abysslink-conformance/
```

Scenarios covered: version, init, up dry-run, doctor, status JSON, panic no-hang,
notify stdin, disable/enable, checkperiod gate, dry-run purity, backup ls,
uninstall dry-run, ntfy bind-addr, sshd directives, binary size.

## Per-watch thresholds (configurable in YAML)

```yaml
watch:
  pane_poll_secs: 10        # default 5
  pane_idle_secs: 60        # default 30
  pane_cool_off_secs: 600   # default 300
  files:
    - path: /tmp/build.log
      grep: FAILED
      poll_secs: 5           # default 2
```

Or via CLI: `abysslink watch add --file ./build.log --grep FAILED --poll 5`

## ACL port-grant reminder

`abysslink up` always prints "ACL port grants required" for enabled modules whose
ports are not in the default ACL (ntfy tcp/8080 is on by default). Test:

- [ ] `abysslink up` output includes "ACL port grants required" box listing ntfy tcp/8080.
- [ ] `abysslink enable code-server && abysslink up` adds code-server tcp/8080 to the list.
- [ ] `abysslink acl push` converges and removes the warning on next `up`.

## Known NOT done (don't test as working)
- upgrade self-replace: intentionally refuses (use install.sh / go install). `--check` works.
  Real signed self-update is BLOCKED on a key decision only the owner can make:
  generate a cosign/ed25519 signing keypair, store the private key in CI secrets,
  have goreleaser sign releases, and embed the public key in the binary. Until then
  it correctly fails closed.
- ttyd: no basic auth (tailnet ACL is the boundary, by design).
- Windows: not supported (v1 non-goal).
- Deferred modules (syncthing, atuin, sandbox, asciinema, upsnap): v2 stubs, no logic.
