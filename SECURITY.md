# Security Policy

## Supported Versions

Only the latest minor release line receives security fixes. Upgrade with `abysslink upgrade`.

| Version | Supported          |
| ------- | ------------------ |
| Latest minor release line (`v4.x` at time of writing) | :white_check_mark: |
| Older release lines | :x:                |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

**Primary channel:** [GitHub Private Vulnerability Reporting](https://github.com/abysslink/abysslink/security/advisories/new) — this opens a private advisory visible only to you and the maintainers.

**Secondary channel:** email **security@abysslink.dev** (email forwarding for this address is being provisioned — prefer the GitHub channel).

When reporting, please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept code
- Affected versions
- Any suggested mitigations you may have identified

We will acknowledge receipt of your report within **72 hours** and will provide a more detailed response within 7 days indicating next steps.

We offer **CVE coordination** — if a CVE ID is warranted, we will work with you and MITRE to assign and publish one.

## Disclosure Policy

We follow a **90-day coordinated disclosure window**. This means:

1. You report the vulnerability privately.
2. We confirm the issue and develop a fix within 90 days.
3. We release the fix and publish an advisory simultaneously.
4. If we cannot fix within 90 days, we will discuss an extension with you in good faith.
5. After the fix is released, you are free to publish your findings.

We request that you do not publicly disclose vulnerability details before the coordinated release date. We will publicly credit researchers who report valid vulnerabilities (unless you prefer to remain anonymous).

## OpenSSF Scorecard

We run [OpenSSF Scorecard](https://github.com/ossf/scorecard) continuously in CI (`.github/workflows/scorecard.yml`): on every push to `main`, weekly, and on branch-protection-rule changes. Results are published to the public Scorecard API and uploaded as SARIF to the GitHub code-scanning dashboard.

### Badge policy

The README Scorecard badge is added **only when the published aggregate score is at or above ~8**. Below that threshold the badge is intentionally left out of the README until the score recovers — a low badge is worse than no badge. This is a **badge gate, not a CI gate**: there is deliberately no "fail CI if score < N" step. Several Scorecard checks are structurally low for a small, auditable, self-hosted-friendly project (see below), and external probes (deps.dev, OSV) dip transiently; hard-failing the build on the aggregate score would break CI for reasons outside a contributor's control.

The Scorecard score is an **internal quality signal**. It is **never cited in launch, marketing, or Show-HN copy.** (This policy feeds the Phase 33 launch-claims audit.)

### Structurally-low checks (and why)

These Scorecard checks score low for reasons inherent to this project's shape, not because the underlying control is missing. Every row maps to a real file or workflow in this repository.

| Check | Why it is structurally low | Reality |
| ----- | -------------------------- | ------- |
| **Branch-Protection** | A solo/low-contributor repo cannot satisfy Scorecard's required-reviewers heuristic. | Changes land via per-phase PRs (the diff is the documentation); `main` is the integration branch. Scorecard cannot see the review discipline. |
| **Signed-Releases** | Scorecard looks for specific signature artifact patterns it does not always detect. | **Satisfied in substance:** releases are keyless-signed with `cosign sign-blob --bundle` and carry SLSA provenance (`.github/workflows/release.yml`, `release-build.yml`). |
| **CI-Tests** | Scorecard's heuristic keys on PR check runs, which under-count on a solo repo. | Tests, lint, and security scans run on every push and PR (`test.yml`, `lint.yml`, `security.yml`). |
| **Fuzzing** | Scorecard primarily recognizes OSS-Fuzz integration. | Native Go fuzzing runs in CI (`.github/workflows/fuzz.yml`); we are not (yet) enrolled in OSS-Fuzz. |
| **Dependency-Update-Tool** | Scorecard wants a recognized config. | Dependabot is configured (`.github/dependabot.yml`). |
| **Vulnerabilities** | Reflects open advisories in the dependency tree at scan time, including transitive ones we cannot directly patch. | Gated by `govulncheck` (reachability), `grype --vex` (SBOM scan with VEX suppression), and dependency-review on PRs (`security.yml`, `grype.yml`). |

If a future maintainer adds a Scorecard badge to the README while the published score is below ~8, remove it until the score recovers, per the badge policy above.
