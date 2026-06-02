# Demo assets

The README hero GIF (`abysslink.gif`) is generated from [`abysslink.tape`](abysslink.tape) with [VHS](https://github.com/charmbracelet/vhs).

## Regenerate

```bash
# 1. Build a current binary onto your PATH (the tape's `Require abysslink`).
make build && export PATH="$PWD:$PATH"

# 2. Render. Deterministic + fast (~13s of playback).
vhs demo/abysslink.tape          # writes demo/abysslink.gif
```

Commit the regenerated `demo/abysslink.gif` alongside any change that alters the
command surface shown in the tape.

## Why help/version only

The tape runs only infra-free commands (`--help`, `version`) so it:

- **never hangs** waiting on a tailnet, control plane, or paired phone;
- **always renders identically** — no timestamps, IPs, or machine paths leak into the frame (the prompt is forced to a neutral `abysslink ~/dev $`);
- sells the *security posture* — grouped/discoverable commands, dry-run-by-default, an explicit-acknowledgement model for weakening a default, and a verifiable binary — instead of staging a fake live flow.

To record a real end-to-end pairing walkthrough (QR + `mosh`), use the product's
own recorder on a configured machine: `abysslink asciinema rec`.
