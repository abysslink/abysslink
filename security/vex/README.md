<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Abysslink Contributors -->

# Hand-written VEX statements (`security/vex/`)

This directory holds **hand-written** [OpenVEX](https://openvex.dev) statements that suppress vulnerability findings the project has assessed as **not exploitable** (e.g. non-Go transitive deps, or Go findings govulncheck cannot reason about). They are consumed by the Grype SBOM scan in `.github/workflows/grype.yml`:

```text
grype "sbom:<sbom>" \
  --vex dist/govulncheck.openvex.json \   # auto, reachability-derived, regenerated every run
  --vex security/vex \                     # hand-written statements in THIS directory
  --fail-on high                           # High+Critical fail unless VEX-suppressed; Medium warn-only
```

Two VEX sources feed the gate:

| Source | Where | Freshness |
| ------ | ----- | --------- |
| `govulncheck -format openvex` (automated, reachability) | `dist/govulncheck.openvex.json` (built each run) | Always fresh — regenerated every CI run; **not** freshness-checked |
| Hand-written `not_affected` statements | `security/vex/*.openvex.json` | **90-day expiry**, enforced by `check-vex-freshness.sh` |

## The PURL gotcha (read this before authoring a statement)

> **Grype VEX suppression requires the product PURL in the VEX document to match the PURL Grype derives from the SBOM *exactly*. A mismatched PURL silently fails to suppress** — Grype keeps failing on a finding you "suppressed", or (worse, conceptually) you believe a finding is handled when it is not. (`github.com/anchore/grype#3168`, `#1589`.)

For this module the product PURL form Grype derives is:

```text
pkg:golang/github.com/abysslink/abysslink@vX.Y.Z
```

For a transitive dependency it is the dependency's own PURL, e.g.:

```text
pkg:golang/github.com/some/dep@v1.2.3
```

**Always copy the PURL from Grype's own output** (`grype ... -o json | jq '.matches[].artifact.purl'`) rather than hand-typing it. A trailing version, a missing `v` prefix, or a different casing all count as a mismatch.

Because a wrong PURL fails *silently*, every new hand-written statement MUST be proven to actually fire — see **[Proving a suppression fires](#proving-a-suppression-fires)** below.

## Authoring a statement

Use [`vexctl`](https://github.com/openvex/vexctl) (SHA-pinned in CI; install the matching release locally):

```sh
vexctl create \
  --product "pkg:golang/github.com/some/dep@v1.2.3" \
  --vuln    "CVE-2026-12345" \
  --status  "not_affected" \
  --justification "vulnerable_code_not_in_execute_path" \
  --file    security/vex/dep-CVE-2026-12345.openvex.json
```

Then:

1. Confirm the document carries an ISO-8601 `.timestamp` (vexctl sets it).
2. Run `security/vex/check-vex-freshness.sh` — it must report the new doc as `fresh`.
3. Prove the suppression fires (next section).
4. Commit the statement with a one-line rationale in the PR.

### The 90-day validity window

OpenVEX has no native expiry field. The project convention is: a hand-written statement is valid for **90 days** from its `.timestamp`. After that, `check-vex-freshness.sh` fails CI, forcing a maintainer to re-assess whether the suppressed finding is still not exploitable and to re-stamp the `.timestamp`. The automated govulncheck VEX in `dist/` is exempt — it is regenerated every run and is always current.

## Proving a suppression fires

A wrong PURL fails silently, so a hand-written suppression is not trusted until a **WITH-vs-WITHOUT `--vex` comparison** proves it changes Grype's exit status. This is the **Pitfall-3 guard** and it MUST be re-run whenever a new hand-written VEX statement is added.

### Suppression-proof fixture (`testdata/`)

`security/vex/testdata/` holds a deterministic, offline fixture pair:

| File | Role |
| ---- | ---- |
| `known-advisory.spdx.json` | A minimal SPDX SBOM containing exactly one package — `github.com/dgrijalva/jwt-go@v3.2.0+incompatible` — that carries a **known advisory** (`CVE-2020-26160` / `GHSA-w73w-5m7g-f7qc`) Grype matches off the package PURL. |
| `known-advisory.openvex.json` | A `not_affected` VEX statement whose product `@id` PURL matches the SBOM package PURL **byte-for-byte** (`pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0+incompatible`). |

This is a fixture only — `jwt-go` is **not** a real abysslink dependency. It exists solely to prove that a PURL-matching statement flips Grype's exit status.

### Running the proof

```sh
make vex-suppression-proof
```

The target (and the underlying one-liner) runs Grype over the fixture SBOM **twice**:

```sh
# 1. without --vex: the advisory MUST appear and grype MUST fail (exit non-zero).
grype "sbom:security/vex/testdata/known-advisory.spdx.json" --fail-on high

# 2. WITH --vex: the not_affected statement MUST suppress it and grype MUST pass.
grype "sbom:security/vex/testdata/known-advisory.spdx.json" \
  --vex security/vex/testdata/known-advisory.openvex.json --fail-on high
```

Assertions:

- **without `--vex`** the run **fails** (advisory detected). If it passes, the fixture no longer trips the advisory and the proof is meaningless — re-pick a package/CVE Grype's DB still matches.
- **with `--vex`** the run **passes** (advisory suppressed). If it fails, the suppression did **not** fire: the PURL match is wrong (Pitfall 3) — compare the SBOM `externalRef` PURL against the VEX product `@id`.

### Why this is partly manual

The proof depends on Grype's live vulnerability DB matching the fixture's advisory, so it cannot run hermetically inside `go test`. It is therefore the **executable form of the Manual-Only / CI-integration verification** recorded in [`32-VALIDATION.md`](../../.planning/phases/32-supply-chain-depth-trimmed-fortify/32-VALIDATION.md) (SUPL-03, row `02-T3`: *"VEX suppression actually fires (WITH vs WITHOUT `--vex`)"*). Run `make vex-suppression-proof` in CI or locally whenever a hand-written VEX statement is added or changed; never ship a new suppression without it.
