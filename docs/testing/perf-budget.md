# Performance budget — measured baseline (P-C2)

This records **real, measured** baseline numbers for Abysslink's security-critical
hot paths, plus a **soft** budget per path. It closes the loop on the performance
budget named in `docs/DESIGN.md` §8.3 / `CLAUDE.md` Task 8.3, which previously had
no enforcement and no numbers.

## What this is — and is NOT

- **This is measurement, not a gate.** There is no CI regression assertion, no
  `b.Errorf` on a timing threshold, no per-op ceiling baked into a test. The
  benchmarks print numbers; a human reads them.
- **The numbers below are indicative on one dev machine.** They are a sanity
  reference ("is append milliseconds or seconds?"), not a contract. fsync
  latency, disk, CPU, and Go version all move them. Do **not** treat a slower
  number on another machine as a regression.
- **No false precision.** Numbers are rounded to what the measurement supports.

## How to reproduce

```sh
make bench                 # fixed 100x iterations (bounded, repeatable)
make bench BENCHTIME=1s    # or auto-scaled wall-clock
# equivalently:
GOTOOLCHAIN=go1.26.5 go test -bench=. -benchmem -run=^$ -benchtime=100x \
  ./internal/audit/... ./internal/evidence/... ./internal/config/...
```

The benchmarks live beside the code they measure
(`internal/audit/bench_test.go`, `internal/evidence/bench_test.go`,
`internal/config/bench_test.go`). Each is hermetic: an in-memory
`secrets.MockStore` seeded with a synthetic all-ones HMAC key (never a live
keychain) and a `b.TempDir()` log. They do **not** run under a normal
`go test ./...` — only under `-bench`.

## Measured baseline

Captured with `-benchtime=100x -count=1`.

| Machine | OS / arch | CPU | Go |
| --- | --- | --- | --- |
| dev laptop | darwin / arm64 | Apple M4 Pro | 1.26.5 (`GOTOOLCHAIN=go1.26.5`) |

| Benchmark | ns/op | ≈ time | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: |
| `BenchmarkAuditAppend` | 13,731,505 | ~13.7 ms | 233,008 | 589 |
| `BenchmarkChainVerify/N=100` | 647,741 | ~0.65 ms | 286,968 | 2,366 |
| `BenchmarkChainVerify/N=1000` | 2,439,595 | ~2.44 ms | 2,300,428 | 23,079 |
| `BenchmarkEvidenceCreate` | 1,375,074 | ~1.38 ms | 1,415,929 | 4,096 |
| `BenchmarkEvidenceVerify` | 493,562 | ~0.49 ms | 150,327 | 151 |
| `BenchmarkConfigLoad` | 258,979 | ~0.26 ms | 103,021 | 1,192 |

Raw output:

```
goos: darwin
goarch: arm64
pkg: github.com/abysslink/abysslink/internal/audit
cpu: Apple M4 Pro
BenchmarkAuditAppend-14          100    13731505 ns/op    233008 B/op      589 allocs/op
BenchmarkChainVerify/N=100-14    100      647741 ns/op    286968 B/op     2366 allocs/op
BenchmarkChainVerify/N=1000-14   100     2439595 ns/op   2300428 B/op    23079 allocs/op
pkg: github.com/abysslink/abysslink/internal/evidence
BenchmarkEvidenceCreate-14       100     1375074 ns/op   1415929 B/op     4096 allocs/op
BenchmarkEvidenceVerify-14       100      493562 ns/op    150327 B/op      151 allocs/op
pkg: github.com/abysslink/abysslink/internal/config
BenchmarkConfigLoad-14           100      258979 ns/op    103021 B/op     1192 allocs/op
```

## Soft budget (per path)

Phrased as expectations, not assertions. A number outside these ranges is a
prompt to look, not a build failure.

### Audit append — `BenchmarkAuditAppend`

A single signed `Append` is **durability-bound, not CPU-bound**. The HMAC + JSON
marshal + prev-hash scan are microseconds; the cost is the **two durable writes**
per append — an fsync'd JSONL line plus an fsync'd atomic anchor rewrite (the
anchor-every-append invariant). On macOS those are `F_FULLFSYNC` calls, which is
why the measured ~13.7 ms is milliseconds, **not** sub-millisecond.

- **Soft budget:** single-append should stay in the **low tens of milliseconds**
  on a machine doing real durable fsyncs (macOS `F_FULLFSYNC`), and typically
  **≤ a few milliseconds** on Linux/SSD. If a single append ever reaches
  hundreds of ms or seconds, something is wrong (disk contention, an accidental
  O(N²) rescan, a fsync storm).
- **Caveat — grows with log size:** append re-scans the log tail to compute
  `prev_hash` and to recount for the anchor, so per-op cost rises with the number
  of entries already in the log. The baseline above is for a small log (the 100x
  run keeps it ≤ 100 entries). Production logs are rotation-bounded, which keeps
  this in range; an unrotated multi-GB log would make append visibly slower.

### Chain verify — `BenchmarkChainVerify`

Verify is **O(N)** in the number of log entries: it walks every entry, checks the
hash link and HMAC signature, then validates the anchor. The sub-benchmarks make
the linear growth explicit — ~0.65 ms at 100 entries vs ~2.44 ms at 1000
(~10× entries → ~3.8× time, the rest being fixed setup), and allocations scale
almost exactly 10× (2,366 → 23,079). Marginal cost is on the order of a couple of
microseconds per entry.

- **Soft budget:** expect **linear** growth, roughly **single-digit microseconds
  per entry** plus fixed overhead. A verify of a rotation-sized log should stay in
  the **low milliseconds**. Super-linear growth (e.g. N=1000 costing far more than
  ~10× N=100) would indicate an accidental quadratic and is worth investigating.

### Evidence create / verify — `BenchmarkEvidenceCreate`, `BenchmarkEvidenceVerify`

`Create` bundles a full `audit.Verify` (so it inherits verify's O(N)) plus report
rendering, content hashing, ed25519 signing, and a gzip'd tar stream — ~1.38 ms
over a 100-entry log. `Verify` is the cheaper asymmetric half (un-gzip, one
ed25519 verify, two SHA-256 checks) at ~0.49 ms and only 151 allocs.

- **Soft budget:** both should stay **sub-10 ms** for a normal bundle. `Create`
  tracks `ChainVerify` growth (it embeds a verify), so a large audit log moves it;
  `Verify` is essentially flat in the audit-log size (it re-hashes the pinned
  files but does **not** re-walk the HMAC chain).

### Config load — `BenchmarkConfigLoad`

A full `config.Load` of the representative `abysslink.yaml.example`: open, YAML
decode with `KnownFields(true)`, apply defaults, and run `Validate` (the
fail-closed startup path every mutating command hits). ~0.26 ms.

- **Soft budget:** **sub-millisecond**. Config parsing is off the critical path
  and small; if it ever crossed into milliseconds it would mean the schema or
  validation grew pathologically.

## Notes / honesty caveats

- Numbers vary run-to-run by a few percent (fsync jitter especially); treat the
  table as one sample, not a distribution. Re-run `make bench` for a fresh read.
- `-benchtime=100x` is deliberate: it bounds `BenchmarkAuditAppend`'s log growth
  (see the append caveat) so the reported per-op is the near-empty-log cost, and
  it keeps the whole run to well under a couple of minutes (the 1000-entry verify
  chain is built once, un-timed, and dominates wall-clock setup).
- These benchmarks required **no product-code change** — every hot path was
  reachable through existing exported constructors (`audit.NewSigned`,
  `audit.Verify`, `evidence.Create`, `evidence.Verify`, `config.Load`).
