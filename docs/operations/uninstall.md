# Uninstall

Abysslink is built to leave cleanly. Every file it changed was backed up and recorded in the audit log, and `abysslink uninstall` replays that log in reverse. Full removal is four steps: stop the daemon, reverse the system changes, remove the binaries, and (optionally) remove the data it kept.

## 1. Stop the daemon

If you enabled the `abysslinkd` background service, remove it first:

```sh
abysslink daemon disable --apply
```

This stops the daemon and removes its launchd (macOS) / systemd user (Linux) service.

## 2. Reverse the system changes

Like every mutating command, `uninstall` is dry-run by default. Preview first:

```sh
abysslink uninstall
```

The preview lists every action, driven by the audit log: files restored from their timestamped backups (SSH config, ntfy config, tmux config, …), files abysslink created that will be deleted, and module teardowns (for example the managed ntfy Docker container on macOS). Shared files you also edited — such as `~/.claude/settings.json` — are reverted surgically: only abysslink's additions are removed, your own edits stay.

Then execute:

```sh
abysslink uninstall --apply
```

You will see a blast-radius summary and must type `UNINSTALL` to confirm. Each restored file's SHA-256 is printed as it is reversed.

By default, `~/.config/abysslink/` and the state dir (audit log + backups) are **kept** for forensics — you retain a tamper-evident record of everything that was changed and changed back. Third-party packages (`tailscale`, `ntfy`, `mosh`, `tmux`) are left installed; remove them with your package manager if you no longer want them.

## 3. Remove the binaries

How you remove the binaries depends on how you installed them.

**Installer script** (`curl … install.sh | sh`):

```sh
rm ~/.local/bin/abysslink ~/.local/bin/abysslinkd
```

If you ran the installer as root, the binaries are in `/usr/local/bin/` instead:

```sh
sudo rm /usr/local/bin/abysslink /usr/local/bin/abysslinkd
```

**Homebrew:**

```sh
brew uninstall --cask abysslink
brew untap abysslink/tap
```

**Nix:** if you ran `nix build`, delete the `result` symlink (the store path is garbage-collected later). If you installed into a profile, remove it from the profile:

```sh
nix profile remove abysslink
```

**`go install`:** the binaries live in `GOBIN` (defaults to `$GOPATH/bin`):

```sh
rm "$(go env GOPATH)/bin/abysslink" "$(go env GOPATH)/bin/abysslinkd"
```

## 4. Optional: remove the data

### Config, audit log, and backups

`abysslink uninstall` has two flags for this — run them **before** removing the binary:

- `--remove-config` deletes `~/.config/abysslink/` but keeps the state dir (audit log + backups).
- `--purge` deletes both `~/.config/abysslink/` and `~/.local/state/abysslink/`.

**Warning:** the state dir holds the audit log and every backup. Deleting it destroys the audit trail and the ability to restore anything — it is irreversible, and `--purge` makes you confirm that separately.

If the binary is already gone, remove the directories by hand (same warning applies):

```sh
rm -rf ~/.config/abysslink ~/.local/state/abysslink
```

### Keychain entries

`uninstall` does **not** delete keychain entries. Abysslink stores its secrets in the OS keychain under the service name `abysslink` (rigs enrolled by name with `enroll rig` additionally use `abysslink-rig-<name>`). Which accounts exist depends on which features you used; the possible account names are:

| Account | Created by |
|---|---|
| `ntfy-password` | ntfy module (`up --apply`) |
| `anthropic-api-key` | claudecode module |
| `code-server-password` | code-server module |
| `audit-hmac` | audit log signing (first apply) |
| `audit-counter` | audit log anchoring |
| `audit-evidence-key` | `audit evidence` |
| `device-ssh-ca` | phone enrolment (device SSH CA) |
| `duress-real`, `duress-decoy` | `duress enable` (argon2id digests, not passphrases) |

`abysslink rotate --help` lists the secrets that can be rotated in place if you would rather re-key than delete. To delete manually:

```sh
# macOS — repeat per account
security delete-generic-password -s abysslink -a ntfy-password

# Linux (libsecret) — repeat per account
secret-tool clear service abysslink account ntfy-password
```

### Agent session recordings

If you used the `arm` kill-switch, session recordings ("casts") live under the data dir:

```sh
rm -rf ~/.local/share/abysslink/casts
```
