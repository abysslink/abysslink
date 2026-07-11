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

## Machine-readable output (`--json`)

Both commands accept the global `--json` flag and emit one JSON object on stdout.
This is the ingest surface a compliance platform (or the future Teams plane)
consumes.

**`abysslink audit evidence --json`** emits the bundle **manifest** — the same
object stored as `manifest.json` inside the bundle (compact, single line):

```json
{"alevidence_v":1,"generated_at":"2026-07-09T12:00:00Z","rig":{"hostname":"rig","abysslink_version":"v4.0.1"},"range":{},"chain":{"verified":true,"entry_count":5,"sigs_verified":5,"sigs_skipped":0,"key_epoch":1,"counter_status":"verified","truncation_detected":false},"contents":{"audit_jsonl_sha256":"…","report_md_sha256":"…"},"signing":{"algo":"ed25519","public_key":"…","key_fingerprint":"…"}}
```

**`abysslink audit verify-evidence --json`** emits the verification verdict with
the manifest nested under `Manifest` (these four keys are the Go field names —
`Valid`, `Fingerprint`, `Manifest`, `Reason`):

```json
{"Valid":true,"Fingerprint":"<sha256-hex>","Manifest":{ …the manifest above… },"Reason":""}
```

`Valid` is `true` only when the signature and every content hash check out;
`Reason` carries the failure text otherwise. `Fingerprint` is the signing key's
fingerprint — **you still have to compare it to your pinned value** (or pass
`--expect-key`); a valid signature over an unexpected key is still `Valid:true`.

### The manifest schema (ingest contract)

The manifest conforms to a versioned JSON Schema (draft 2020-12), published as
the stable ingest contract:

- [`docs/schemas/alevidence-v1.schema.json`](../schemas/alevidence-v1.schema.json)
  (`$id`: `https://abysslink.github.io/abysslink/schemas/alevidence-v1.schema.json`)

`alevidence_v` is the format version (`1`); a breaking change ships as a new
`alevidence-vN.schema.json`. A test (`internal/evidence/schema_test.go`) validates
a real manifest against this schema and fails if the struct and schema drift.

| Field | Type | Req? | Meaning |
|---|---|---|---|
| `alevidence_v` | int (const `1`) | yes | Manifest format version. |
| `generated_at` | string (RFC3339 UTC) | yes | When the bundle was produced. |
| `rig.hostname` | string | yes | Short hostname of the rig. |
| `rig.abysslink_version` | string | yes | abysslink version that produced it. |
| `range.since` | string (RFC3339 UTC) | no | Window start; omitted when open-ended. |
| `range.until` | string (RFC3339 UTC) | no | Window end; omitted when open-ended. |
| `chain.verified` | bool | yes | OK **and** not truncated **and** not indeterminate. |
| `chain.entry_count` | int ≥ 0 | yes | Audit entries in the bundle. |
| `chain.sigs_verified` | int ≥ 0 | yes | Entries whose HMAC signature verified. |
| `chain.sigs_skipped` | int ≥ 0 | yes | Entries whose signature could not be checked. |
| `chain.key_epoch` | int (uint32) | yes | Audit key epoch at generation. |
| `chain.counter_status` | enum `verified`\|`unknown`\|`mismatch`\|`""` | yes | AUD-02 counter check (honest tri-state; never coerced to PASS). |
| `chain.truncation_detected` | bool | yes | Tail truncation was detected. |
| `chain.reason` | string | no | Explanation when not fully verified; omitted on a clean result. |
| `contents.audit_jsonl_sha256` | string (`^[0-9a-f]{64}$`) | yes | SHA-256 of `audit.jsonl`. |
| `contents.report_md_sha256` | string (`^[0-9a-f]{64}$`) | yes | SHA-256 of `report.md`. |
| `signing.algo` | string (const `ed25519`) | yes | Signature algorithm. |
| `signing.public_key` | string (base64) | yes | ed25519 public key. |
| `signing.key_fingerprint` | string (`^[0-9a-f]{64}$`) | yes | SHA-256 of the public key — the value pinned out-of-band. |

The manifest is an **operator attestation**, not a zero-trust proof (see the
trust model below). `chain.*` reflects what the operator's abysslink computed
with the secret HMAC key; a consumer trusts it exactly as far as it trusts the
`signing.key_fingerprint` it pinned.

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
