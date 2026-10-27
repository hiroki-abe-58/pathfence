#!/usr/bin/env bash
# Rebuild and re-check PathFence from a fresh clone of this checkout's HEAD, in a temporary
# directory, so that nothing local (an old build, uncommitted files) affects the result.
#
#   ./scripts/reproduce.sh          # what CI runs, but a skipped test fails the run
#
# Needs git, elan (for the pinned toolchain), python3 and Linux 5.6 or later with openat2 not
# blocked by a seccomp filter (some containers): the kernel tests use it, and a skipped test
# fails the run rather than count as passing.
set -euo pipefail

for t in git lake python3 sha256sum; do
  command -v "$t" >/dev/null || { echo "reproduce: $t not found" >&2; exit 1; }
done
# Test the binary built here (tests/common.py honours PATHFENCE_BIN), with the pinned toolchain.
unset PATHFENCE_BIN ELAN_TOOLCHAIN

src=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
head=$(git -C "$src" rev-parse HEAD)
if [ -n "$(git --no-optional-locks -C "$src" status --porcelain)" ]; then
  echo "reproduce: uncommitted changes and untracked files in $src are not included" >&2
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export TMPDIR="$work"  # the steps' temporary files (the mutation check's copy) go with it

git clone --quiet --no-local --no-checkout "$src" "$work/pathfence"
cd "$work/pathfence"
git -c advice.detachedHead=false checkout --quiet "$head"
echo "== PathFence $(git rev-parse --short HEAD), $(cat lean-toolchain)"

step() { echo; echo "== $*"; }
step "pinned build configuration (before anything runs Lake)"
./scripts/audit.sh --pins
step "build"
lake build
step "proof audit"
./scripts/audit.sh
step "tests"
python3 -m unittest discover -s tests -v 2>&1 | tee "$work/tests.log"
if grep -q "skipped=" "$work/tests.log"; then
  echo "reproduce: tests were skipped (see above); the kernel tests need openat2 (Linux 5.6+, not blocked by seccomp)" >&2
  exit 1
fi
step "mutation check"
python3 tests/mutants.py

step "done: every step passed"
sha256sum .lake/build/bin/pathfence
