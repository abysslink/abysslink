# Demo assets

The README hero demo (`abysslink.gif` + `abysslink.mp4`) is generated from
[`abysslink.tape`](abysslink.tape) with [VHS](https://github.com/charmbracelet/vhs).

## What the demo shows

Three real value moments, in ~16 seconds: `abysslink up` printing its dry-run
convergence plan ("6 changes planned … run `abysslink up --apply`"),
`abysslink quorum eval` returning a DENY verdict for `tailscale funnel 443`
without ever executing it (the compiled deny-floor), and `abysslink threat-model`
printing the live ✓/✗ status of every defense in the threat model. Everything
shown is read-only or dry-run — the demo never mutates the recording machine.

## Regenerate

```bash
# 1. Build a current binary onto your PATH (the tape's `Require abysslink`).
make build && export PATH="$PWD:$PATH"

# 2. Render from the repo root (~16s of playback).
vhs demo/abysslink.tape          # writes demo/abysslink.gif + demo/abysslink.mp4
```

Commit the regenerated `demo/abysslink.gif` and `demo/abysslink.mp4` alongside
any change that alters the output of the three commands shown in the tape.

## Determinism and privacy

- The tape's hidden setup exports `HOME=/tmp/abysslink-demo-home` and installs
  [`abysslink.demo.yaml`](abysslink.demo.yaml) — a sanitized config whose
  identity values are generic (`dev@example.com`, hostname `rig`) — so no real
  hostname, username, tailnet IP, or home path can appear in a frame. The
  prompt is forced to a neutral `dev@rig ~ $`.
- All three commands are infra-free reads: `up` is dry-run by default,
  `quorum eval` never executes the command it judges, and `threat-model` only
  reports. The tape never passes `--apply`.
- Output is near-deterministic; a handful of live probes (the quorum closure
  hash, a ✓/✗/— that depends on the recording machine's posture) may vary
  between renders, which is cosmetic and acceptable.

## Palette

The tape sets a custom inline VHS theme ("abyss") whose colors are lifted from
the product palette in `internal/ui/theme.go` (background `#0f1117`, accent
cyan `#2CE0F5`, success `#04B575`, fatal `#FF5F87`, info `#6E80F7`, selection
violet `#B57BFF`, warn `#FFD060`). If `theme.go` changes, update the
`Set Theme` line to match.

To record a real end-to-end pairing walkthrough (QR + `mosh`), use the product's
own recorder on a configured machine: `abysslink asciinema rec`.
