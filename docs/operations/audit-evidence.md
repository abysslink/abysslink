# Audit evidence bundles

Abysslink keeps a tamper-evident, HMAC-signed, hash-chained audit log of every
system mutation and agent action. `abysslink audit evidence` packages that log
into a **signed, externally-verifiable evidence bundle** you can hand to a SOC 2
auditor or ingest into a compliance platform — proof of what ran, when, on which
machine, and whether the chain is intact.

## Producing a bundle

```sh
# Full history
abysslink audit evidence --out evidence.alevidence

# A time window (RFC 3339 UTC)
abysslink audit evidence --since 2026-07-01T00:00:00Z --out july.alevidence
```

It is **read-only** — the audit log is never modified. The command prints the
**signing-key fingerprint**; record it and give it to whoever will verify the
bundle (see trust model below).

A `.alevidence` bundle is a `tar.gz` containing:

- `manifest.json` — format version, rig identity, time range, the
  chain-verification result (VALID / entry count / signatures verified / key
  epoch), the SHA-256 of every other file, and the ed25519 public key + its
  fingerprint.
- `manifest.sig` — the ed25519 signature over `manifest.json`.
- `audit.jsonl` — the raw hash-chained audit entries (secret-free by design).
- `report.md` — a human-readable summary and action table.

## Verifying a bundle

```sh
abysslink audit verify-evidence evidence.alevidence
# exit 0 = valid, exit 2 = invalid

# Fail closed unless it was signed by the key you expect:
abysslink audit verify-evidence --expect-key <sha256-fingerprint> evidence.alevidence
```

Verification checks the ed25519 signature over the manifest and every pinned
content hash. Any edit to any file — a reordered entry, a deleted action, a
doctored report — breaks verification.

## Trust model (read this)

The audit log itself is **HMAC-signed with a secret key**, so it is
tamper-evident only to whoever holds that key. An external auditor does not, so
the evidence bundle adds an **asymmetric (ed25519) signature** over a manifest
that *attests* the chain-verification result — computed by the operator's
`abysslink`, which does hold the HMAC key.

This means an evidence bundle proves: **"abysslink, holding evidence-signing key
`<fingerprint>`, attests this audit history is intact."** It is an honest
attestation *by the operator*, not a zero-trust proof. The trust anchor is the
signing-key fingerprint:

1. The operator states the fingerprint out-of-band (once) — e.g. in a signed
   email or a control document.
2. The auditor verifies each bundle with `--expect-key <that fingerprint>`.

A bundle signed by any other key still verifies as *internally* consistent but
presents a **different fingerprint** — which is exactly why the out-of-band pin
matters. This is the same trust model as an SSH host key.

Verification fetches the audit log's own chain result from the signed manifest;
it does **not** need the secret HMAC key, so anyone can run it.
