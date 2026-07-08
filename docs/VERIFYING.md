# Verifying an Abysslink release

Every tagged Abysslink release is independently verifiable. There is **one**
verification story with **three legs**, and `abysslink verify` / `abysslink
upgrade` implement all three **fail-closed** — they refuse the operation when any
leg fails, never silently warn-and-proceed.

| Leg | What it proves | Tool |
|-----|----------------|------|
| 1. cosign signature | The checksum manifest was signed by this repo's release workflow (keyless OIDC) | `cosign verify-blob --bundle` |
| 2. SLSA Build L3 provenance | The artifacts were built by the exact isolated reusable workflow `release-build.yml` | `gh attestation verify --signer-workflow` |
| 3. SHA-256 checksum | The bytes you downloaded match the signed manifest | `sha256sum --check` |

> **Why `gh attestation verify` and not `slsa-verifier`?**
> Abysslink generates provenance with [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance).
> `slsa-verifier verify-artifact` only understands `slsa-github-generator` output,
> and its `verify-github-attestation` subcommand is hardcoded to a bazel-only
> builder-id allowlist — it will reject Abysslink's builder. The **only** verifier
> compatible with `actions/attest-build-provenance` bundles is the GitHub CLI's
> `gh attestation verify`. The CI publish gate and the client `verify`/`upgrade`
> commands all use it.

---

## The easy path: let abysslink do it

If you already have an installed binary, the built-in commands run all three
legs for you, fail-closed:

```sh
# Verify the running binary against its signed release (cosign + SLSA + checksum)
abysslink verify

# Verify, then self-update only if every leg passes
abysslink upgrade --apply
```

`abysslink verify` additionally hashes the **running executable** against the
released binary extracted from the checksum-verified tarball, so a locally
tampered binary fails even when the manifest signature is valid.

Both commands **fail closed**:

- a missing or invalid SLSA provenance ⇒ non-zero exit, no install;
- the `gh` CLI being absent on the network verify path ⇒ non-zero exit
  (refuse), never a silent skip.

---

## The manual path

You need [`cosign`](https://docs.sigstore.dev/cosign/) (v3+) and the
[GitHub CLI](https://cli.github.com) (`gh`).

```sh
VERSION=v1.2.3          # the release tag you are verifying
BARE=${VERSION#v}       # goreleaser artifact names drop the leading "v"
OWNER=abysslink
BASE=https://github.com/abysslink/abysslink/releases/download/${VERSION}
```

### Leg 1 — cosign signature on the checksum manifest

The cosign v3 `.bundle` embeds the certificate chain and the Rekor proof.
cosign v3 verifies it against the Sigstore trust root, which it fetches from the
Sigstore TUF repository over the network (so this leg needs internet access; the
old `--offline` flag is deprecated and does not change this for the new bundle
format).

```sh
curl -fsSL ${BASE}/abysslink_${BARE}_checksums.txt        -o checksums.txt
curl -fsSL ${BASE}/abysslink_${BARE}_checksums.txt.bundle -o checksums.txt.bundle

cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp "^https://github\.com/abysslink/abysslink/\.github/workflows/release\.yml@refs/tags/.*$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

### Leg 2 — SLSA Build L3 provenance on the artifact

`--signer-workflow` is what enforces L3 trust: the provenance must come from the
specific isolated reusable workflow that builds releases. `--owner` scopes the
attestation lookup.

```sh
curl -fsSL -o abysslink_${BARE}_linux_amd64.tar.gz \
  ${BASE}/abysslink_${BARE}_linux_amd64.tar.gz

gh attestation verify abysslink_${BARE}_linux_amd64.tar.gz \
  --owner ${OWNER} \
  --signer-workflow abysslink/abysslink/.github/workflows/release-build.yml
# exit 0 = provenance valid AND signed by the pinned reusable workflow
```

### Leg 3 — SHA-256 checksum of the artifact

The manifest you verified in Leg 1 is the trust anchor for this check.

```sh
# The leading space + trailing anchor keep the match to the tarball line
# itself. An unanchored grep also matches the manifest's .cdx.json/.spdx.json
# SBOM lines, and sha256sum then exits non-zero with phantom "FAILED open or
# read" errors for files you never downloaded — on a perfectly healthy
# release. (macOS ships no sha256sum: use `shasum -a 256 --check`.)
grep " abysslink_${BARE}_linux_amd64.tar.gz$" checksums.txt | sha256sum --check
# abysslink_${BARE}_linux_amd64.tar.gz: OK
```

All three must succeed. If any leg fails, **do not install the artifact** — treat
it as compromised.

---

## What the CI pipeline guarantees

- The build + provenance attestation run inside an **isolated reusable workflow**
  (`.github/workflows/release-build.yml`) — neither the source under test nor the
  developer who pushed the tag can influence the signing step (SLSA v1 Build L3).
- A post-build `verify` job re-runs `gh attestation verify --signer-workflow`
  against the release artifacts. The `publish` job is **gated** on it: if
  provenance is missing or invalid, the draft release is never published.
- The checksum manifest is cosign-signed by a separate `sign` job; `publish`
  is also gated on that, so a published release always carries both its `.bundle`
  and verifiable provenance.

This is the single source of truth for release verification. If the README or
release notes mention verifying a download, they point here.
