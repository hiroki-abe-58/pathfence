#!/usr/bin/env bash
# Proof audit: no escape hatches in the library, only Lean's standard axioms behind any of its
# declarations, and every module accepted by the kernel's own checker.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "audit: $*" >&2; exit 1; }

# 1. No `sorry`/`admit`, `native_decide`, new axioms or opaque constants, `implemented_by`/`extern`,
#    `partial`/`unsafe` definitions, options that skip kernel checking, or metaprograms that could
#    assign proofs behind the kernel's back. (`Main.lean`, the CLI, may use `partial` to read stdin.)
files=$(find PathFence.lean PathFence -name '*.lean' | sort)
if grep -nE '\b(sorry|admit|native_decide|axiom|opaque|implemented_by|extern|partial|unsafe|run_tac|run_cmd|run_elab|run_meta|elab|elab_rules|macro|macro_rules|syntax|skipKernelTC)\b|set_option +debug|^import +Lean\b' \
    $files; then
  fail "forbidden keyword in the library"
fi

# 2. Every declaration in the PathFence modules depends only on the standard axioms.
out=$(lake env lean scripts/Axioms.lean)
lines=$(grep '^AXIOMS ' <<<"$out" || true)
[ -n "$lines" ] || fail "no declarations listed"
if grep -E '^AXIOMS (axiom|opaque) ' <<<"$lines"; then
  fail "the library declares an axiom or opaque constant"
fi
bad=$(sed -E 's/^AXIOMS [a-z]+ [^ ]+: \[(.*)\]$/\1/' <<<"$lines" | tr ',' '\n' | tr -d ' ' | grep -v '^$' \
  | grep -vxE 'propext|Classical\.choice|Quot\.sound' | sort -u || true)
[ -z "$bad" ] || fail "non-standard axioms: $bad"

# The published theorems must all be there (a rename would otherwise drop one silently).
for t in join_split split_join walkB_spec walkB_keeps_base walkL_of_valid resolve_empty resolve_nul \
    resolve_abs resolve_rel_spec resolve_rel_within resolve_valid resolve_render within_iff_render \
    check_allow_iff check_deny_iff check_reject_iff check_allow_rel_within_base check_allow_of_add_deny \
    check_allow_add_allow confine_allow_iff allowedUnder_spec allowedUnder_of_allow parseRoot_valid \
    parseRoot_render Policy.make_valid; do
  grep -q "^AXIOMS theorem PathFence\.$t: " <<<"$lines" || fail "missing theorem PathFence.$t"
done
thms=$(grep -c '^AXIOMS theorem ' <<<"$lines")
decls=$(wc -l <<<"$lines")

# 3. The kernel's own checker replays every module.
lake env leanchecker PathFence >/dev/null || fail "leanchecker rejected a module"

echo "audit: OK ($decls declarations, $thms theorems, standard axioms only, leanchecker passed)"
