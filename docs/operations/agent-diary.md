# Agent diary

`abysslink diary` answers one question: **"What happened on my rig today?"**

It groups a single local calendar day of the tamper-evident
[audit chain](audit-evidence.md) into operator-meaningful buckets — actions run,
approvals/denies, kill-switch and deadman events, key rotations, config
mutations, backups/restores — and highlights the moments an agent action was
gated on a human.

It is a **read-only lens over the audit chain**. It writes no audit data, reads
one file (`audit.log`), and never opens the files that log points at. (On a
fresh install the shared state-path helper may create the empty
`~/.local/state/abysslink` directory, exactly as `abysslink logs` does — no
audit entry, backup, or config is ever written.)

```sh
# Today's digest (local time)
abysslink diary

# A specific day
abysslink diary --date 2026-07-09

# Machine-readable, byte-stable JSON
abysslink --json diary --date 2026-07-09
```

## What it covers (and what it does not)

The diary reflects **only what the audit chain recorded.** Every file mutation
and agent action funnels through `internal/audit`, so the digest is a faithful
summary of that chain — but anything that bypasses the audit chain is invisible
to it. **The diary is not a complete activity log of the host.** For per-file
detail, use [`abysslink logs`](../cli-reference.md).

## The category model

Each audit op maps to **exactly one** category, so per-category counts never
double-count and always reconcile: `applied + dry_run == total_entries` and the
category counts sum to `total_entries`.

| Category (`json` slug)  | Ops that map to it                                                   | Meaning |
|-------------------------|---------------------------------------------------------------------|---------|
| `action-run`            | `arm-run:*` (e.g. `arm-run:end`), `wol`                             | Agent/action runs and wake-on-LAN. |
| `approval`              | `approve-decision`                                                   | A human **resolved** a request — approve **or** deny (see the honesty note below). |
| `agent-waited-on-human` | `ack-receipt`                                                       | A device acknowledged a pushed message — an agent action gated on a human. |
| `kill-switch`           | `panic:*`                                                          | Emergency kill-switch actions. |
| `deadman`               | `deadman-lockdown`                                                   | The dead-man's switch fired. |
| `rotation`              | `rotate-audit-hmac`                                                  | Audit HMAC signing-key rotation. |
| `config-mutation`       | `write`, `delete`, `sec-fix`                                        | File mutations (high-volume — counts only). |
| `backup`                | `backup`, `restore`, `restore-unverified`                          | Backup / restore (high-volume — counts only). |
| `other`                 | any op this build does not recognize                                | Forward-compat: an op a newer release added that this binary predates. Emitted **only** when its count is non-zero. |

`human_gate_events` is a derived total = `approval` + `agent-waited-on-human`.

**Notable events** are the *signal* categories only. The high-volume routine
categories (`config-mutation`, `backup`) are represented by **counts**, not a
per-event list — `write`/`backup`/`sec-fix`/`delete`/`restore` do not appear in
the notable block. That is a deliberate call, not a bug; per-file detail lives in
`abysslink logs`.

## `--date`

`--date YYYY-MM-DD` selects a local calendar day (default: today, local time).
The window is `[start, end)` where `end` is exactly one calendar day after
`start` (DST-safe). Entries are stored in UTC but compared as absolute instants,
so a UTC-stored time is placed on the correct **local** day.

- A malformed date is a clear error (exit 1):
  `diary: invalid --date "…" (want YYYY-MM-DD): …`.
- **An empty day is not an error.** Zero matching entries yield a zero digest and
  exit 0. A **missing** audit log (fresh install) reads as zero entries and
  produces the same clean empty digest — never a crash, never a fabricated entry.

## Honesty caveats

- **Casts come only from `arm-run:end`.** There is no asciinema recording index
  anywhere in abysslink — the asciinema module only writes
  `~/.config/asciinema/config`. Cast paths are surfaced **exclusively** from the
  `Target` of `arm-run:end` audit entries (the cast bytes are hashed into the
  audit chain at run end). The section header labels this provenance
  ("from arm-run:end"). If a day has no armed runs, the diary says **"no agent
  runs recorded today"** — it never invents a recorded-session count.
- **`approval` = resolved, not approve-vs-deny.** `approve-decision` covers both
  approve and deny; the verdict lives in the receipt body, not the audit op. The
  diary counts *resolutions* and does not claim an approve/deny breakdown.
- **`dry_run` entries are counted** (split out as `dry_run`) because the chain
  logged them as *planned*. They are reported honestly-labelled, never silently
  dropped.
- **No fabricated freshness.** There is no `generated_at`/wall-clock field. The
  only temporal claim is `date` (the requested day).

## Byte-stable `--json`

`abysslink --json diary --date X` emits a single JSON object. Run it twice over
the same log and you get **identical bytes**, guaranteed by:

- no wall-clock field (`date` is flag-derived, never `time.Now`);
- the fixed 8 known categories always present (zeros included), slug-sorted, with
  `other` appended only when non-zero;
- notable events ordered by time (equal times keep causal/append order), capped
  at 200 with a `notable_omitted` count;
- `casts` sorted and deduped;
- `notable` and `casts` always non-null (`[]` on an empty day).

### Secret-safety

The diary can never leak a secret. `notable` is a **projection** that carries
only `{time, op, target, category, dry_run}` — it structurally omits the chain
digests (`hash`, `sig`, `prev_hash`, `key_epoch`). `target` is treated as an
opaque path/id and is never opened or expanded; as defense-in-depth it is bounded
in length and any secret-shaped value is rendered as
`<redacted:secret-shaped-target>` (this never fires on real path/id data).

### Example object

```json
{
  "date": "2026-07-09",
  "total_entries": 12,
  "applied": 9,
  "dry_run": 3,
  "human_gate_events": 2,
  "categories": [
    {"category": "action-run", "count": 2, "applied": 2, "dry_run": 0},
    {"category": "agent-waited-on-human", "count": 1, "applied": 1, "dry_run": 0},
    {"category": "approval", "count": 1, "applied": 1, "dry_run": 0},
    {"category": "backup", "count": 3, "applied": 3, "dry_run": 0},
    {"category": "config-mutation", "count": 4, "applied": 1, "dry_run": 3},
    {"category": "deadman", "count": 0, "applied": 0, "dry_run": 0},
    {"category": "kill-switch", "count": 1, "applied": 1, "dry_run": 0},
    {"category": "rotation", "count": 0, "applied": 0, "dry_run": 0}
  ],
  "notable": [
    {"time": "2026-07-09T09:15:02Z", "op": "wol", "target": "rig-1/aa:bb:cc:dd:ee:ff", "category": "action-run", "dry_run": false},
    {"time": "2026-07-09T14:03:11Z", "op": "deadman-lockdown", "target": "no operator contact for 24h0m0s", "category": "deadman", "dry_run": false},
    {"time": "2026-07-09T14:05:40Z", "op": "panic:tailscale_down", "target": "panic", "category": "kill-switch", "dry_run": false}
  ],
  "notable_omitted": 0,
  "casts": ["/home/u/.local/state/abysslink/casts/run-2026-07-09T09-16.cast"]
}
```
