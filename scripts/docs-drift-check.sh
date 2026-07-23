#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Abysslink Contributors
#
# docs-drift-check.sh — fail when user docs drift from the shipped surface.
#
# Checks, read-only:
#   1. every top-level CLI command in `abysslink help` appears in docs/cli-reference.md
#   2. every global flag in `abysslink help` appears in docs/cli-reference.md
#   3. every top-level key in abysslink.yaml.example appears in docs/configuration.md
#
# Usage: scripts/docs-drift-check.sh   (or: make docs-drift)
# Env:   ABYSSLINK_BIN=/path/to/abysslink to skip the build.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

BIN="${ABYSSLINK_BIN:-}"
if [ -z "$BIN" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    go build -o "$tmp/abysslink" ./cmd/abysslink
    BIN="$tmp/abysslink"
fi

help_out="$("$BIN" help)"
fail=0

# 1. Top-level commands: indented "name  description" rows in the grouped sections.
cmds="$(printf '%s\n' "$help_out" \
    | sed -n '/^Usage:/,$p' \
    | grep -E '^  [a-z][a-z-]+ ' \
    | awk '{print $1}' \
    | grep -vE '^(help|completion)$' \
    | sort -u)"
for c in $cmds; do
    if ! grep -qE "\b$c\b" docs/cli-reference.md; then
        echo "FAIL: command '$c' missing from docs/cli-reference.md"
        fail=1
    fi
done

# 2. Global flags.
flags="$(printf '%s\n' "$help_out" | grep -oE '^\s+(-[a-z], )?--[a-z-]+' | grep -oE '\-\-[a-z-]+' | sort -u)"
for f in $flags; do
    if ! grep -q -- "$f" docs/cli-reference.md; then
        echo "FAIL: global flag '$f' missing from docs/cli-reference.md"
        fail=1
    fi
done

# 3. Config top-level keys.
keys="$(grep -oE '^[a-z_]+:' abysslink.yaml.example | tr -d ':' | sort -u)"
for k in $keys; do
    if ! grep -qE "\b$k\b" docs/configuration.md; then
        echo "FAIL: config key '$k' missing from docs/configuration.md"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "PASS: docs cover $(echo "$cmds" | wc -l | tr -d ' ') commands, $(echo "$flags" | wc -l | tr -d ' ') global flags, $(echo "$keys" | wc -l | tr -d ' ') config keys"
fi
exit "$fail"
