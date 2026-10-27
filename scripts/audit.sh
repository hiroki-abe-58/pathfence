#!/usr/bin/env bash
# Proof audit: no escape hatches in the library, and only Lean's standard axioms behind its theorems.
set -euo pipefail
cd "$(dirname "$0")/.."

# 1. No `sorry`, `admit`, `native_decide`, new axioms, `implemented_by`/`extern` or `partial`/`unsafe`
#    definitions in the proven library. (`Main.lean`, the CLI, may use `partial` to read stdin.)
if grep -nE '\b(sorry|admit|native_decide|axiom|implemented_by|extern|partial|unsafe)\b' \
    PathFence.lean PathFence/*.lean; then
  echo "audit: forbidden keyword in the library" >&2
  exit 1
fi

# 2. Every theorem listed in scripts/Axioms.lean depends only on the standard axioms.
out=$(lake env lean scripts/Axioms.lean)
echo "$out"
expected=$(grep -c '^#print axioms' scripts/Axioms.lean)
seen=$(grep -c "depends on axioms\|does not depend on any axioms" <<<"$out" || true)
if [ "$seen" -ne "$expected" ]; then
  echo "audit: expected $expected axiom reports, got $seen" >&2
  exit 1
fi
bad=$(grep "depends on axioms" <<<"$out" | sed -E 's/.*\[(.*)\]/\1/' | tr ',' '\n' | tr -d ' ' \
  | grep -vxE 'propext|Classical\.choice|Quot\.sound' || true)
if [ -n "$bad" ]; then
  echo "audit: non-standard axioms: $bad" >&2
  exit 1
fi
echo "audit: OK ($seen theorems, standard axioms only)"
