#!/usr/bin/env bash
# Verify the Verus model of the pure core.
# Set VERUS to the path of the verus binary. Or, put `verus` on PATH.
set -euo pipefail
cd "$(dirname "$0")"
# A proof must not skip work.
if grep -nE 'assume\(|admit\(|external_body|external_fn_specification' core.rs; then
    echo "verify.sh: core.rs uses an unchecked proof step" >&2
    exit 1
fi
out="$("${VERUS:-verus}" core.rs 2>&1)" || { printf '%s\n' "$out"; exit 1; }
printf '%s\n' "$out" | tail -n 3
printf '%s\n' "$out" | grep -qE 'verification results:: [0-9]+ verified, 0 errors'
