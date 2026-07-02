# code-server Module

The code-server module runs [code-server](https://github.com/coder/code-server) (VS Code in the browser) on your rig, bound to the tailnet IP only. Optional; disabled by default.

## What it configures

`abysslink up --apply` (with the module enabled):

- Installs code-server via the platform package manager when missing
- Writes `~/.config/code-server/config.yaml`:
  - `bind-addr: <tailnet-ip>:8080` — never `0.0.0.0`, never loopback
  - `auth: password` with **`hashed-password`** (argon2id PHC string) — the
    plaintext password is generated once and lives only in the OS keychain
    (service `abysslink`, account `code-server-password`); no secret sits at
    rest in config.yaml
  - `cert: false` — transport encryption is the tailnet (WireGuard)
- Installs a background service (`dev.abysslink.codeserver`)

The config is only rewritten when it has drifted (the salted hash is verified
against the keychain password, so a converged system produces no backup/audit
churn). A legacy plaintext `password:` key is detected and converted to
`hashed-password` on the next apply.

## Configuration

```yaml
modules:
  code_server:
    enabled: true
```

`enabled` is the only key the schema accepts. The port (8080) is fixed.

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `code_server_installed` | **fatal** (`doctor` exits 2) |
| `config_exists` / `config_readable` / `config_valid` | warning (`doctor` exits 1) |
| `plaintext_password` — config stores a plaintext password | warning; remediated on next apply |
| `bind_addr_tailnet` — bind-addr is a wildcard or loopback | warning |

## Access

From a tailnet device, browse to `http://<tailnet-ip>:8080` and enter the
keychain-held password. Remember to grant `tcp/8080` in the tailnet ACL — the
plan output reminds you.

## Commands

```sh
abysslink enable code-server     # flip modules.code_server.enabled
abysslink up [--apply]           # install + configure + service
abysslink doctor                 # verify bind + password posture
```
