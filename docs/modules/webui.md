# webui Module

The webui module is an opt-in, **read-only** browser dashboard served by `abysslinkd` over the tailnet. Disabled by default, and gated at *build* level, not just config level.

## Build-tag gating

The entire package is compiled only into `-tags webui` builds. The base
`abysslinkd` binary contains zero Web UI bytes and never links the Tailscale
SDK. Releases ship a separate `abysslinkd-webui` binary for users who want the
dashboard — run that binary (or build with `-tags webui`) *and* set
`webui.enabled: true`.

## Security spine

- **TLS is required** — the listener uses the Tailscale MagicDNS certificate
  (`GetCertificate`); it never binds plaintext. On a non-Tailscale backend
  (Headscale/NetBird) certificates cannot be provisioned, so the module **fails
  closed**: a fatal `webui-tls` doctor finding and no port is ever opened.
- **Every request crosses the WhoIs identity gate.** Loopback addresses
  (`127.0.0.1`, `::1`) and unidentifiable peers receive 403 — there is no
  trusted-local bypass.
- **Read-only is enforced by validation** — `read_only: false` is rejected at
  config load.

## Configuration

```yaml
webui:
  enabled: true        # default: false — the listener never starts unless opted in
  bind_addr: ""        # optional; resolved to the tailnet IP at runtime when empty
  port: 8443           # optional; default 8443
  read_only: true      # MUST be true; false fails config validation
  allow_notify: false  # scaffolded; default false
```

`webui:` is a top-level key (not under `modules:`).

## `abysslink doctor` checks

| Check | Failure behaviour |
|-------|------------------|
| `webui-tls` — backend is not Tailscale, so no TLS cert can be provisioned | **fatal** (`doctor` exits 2); the listener will not bind |

## Usage

```sh
abysslinkd-webui                 # run the webui-enabled daemon build
# then from a tailnet device:
open https://<magicdns-name>:8443
```
