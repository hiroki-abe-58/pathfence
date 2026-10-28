"""Mutation check for the test suite: does it notice plausible bugs?

Copies the repository to a temporary directory, then, for each mutant, rebuilds the CLI with a
mutated copy of the decision functions (the proven library is untouched) and runs the test suite.
The E mutants instead plant a bug in examples/safe_extract.py and use the unmutated CLI. M0 is the
unmutated control and must pass; every other mutant must make the suite fail. Exits 1 otherwise.

    python3 tests/mutants.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PRELUDE = r'''
namespace Mut
open PathFence

def walkB (k : Nat) (st : List Seg) : List Seg → Option (List Seg)
  | [] => some st
  | c :: cs =>
    if c = dotdot then (if @WALKCOND@ then walkB k st.tail cs else none)
    else walkB k (stepL st c) cs

def resolve (base : Path) (s : List Char) : Except Reason Path :=
  if @EMPTY@ then .error .empty
  else if '\x00' ∈ s then .error .nul
  else if isAbs s then .ok (@ABSWALK@).reverse
  else match walkB (@BASEK@) base.reverse (split s) with
    | some o => .ok o.reverse
    | none => .error .escapes

def inside (a p : Path) : Bool := @INSIDE@

def allowedUnder (pol : Policy) (p : Path) : Option (Path × Path) := @UNDER@

def check (pol : Policy) (s : List Char) : Decision :=
  match resolve pol.base s with
  | .error r => .reject r
  | .ok p =>
    if pol.allow.any (fun a => inside a p) && !pol.deny.any (fun d => @DENYW@) then .allow p
    else .deny p
end Mut
'''

BASE = {
    "@WALKCOND@": "longerThan k st",  # k < st.length
    "@ABSWALK@": "walkL [] (split s.tail)",
    "@BASEK@": "base.length",
    "@INSIDE@": "a.isPrefixOf p",
    "@DENYW@": "inside d p",
    "@EMPTY@": "s = []",
    "@UNDER@": "(pol.allow.find? fun a => a.isPrefixOf p).map fun a => (a, p.drop a.length)",
}

MUTANTS = {
    "M0 control (unmutated)": {},
    "M1 `..` allowed at the base": {"@WALKCOND@": "k == 0 || longerThan (k - 1) st"},  # k ≤ st.length
    "M2 no beneath rule": {"@BASEK@": "0"},
    "M3 string-prefix containment (CVE style)": {"@INSIDE@": "(render a).isPrefixOf (render p)"},
    "M4 deny roots ignored": {"@DENYW@": "false"},
    "M5 `..` refused one level too early": {"@WALKCOND@": "longerThan (k + 1) st"},  # k + 1 < st.length
    "M6 deny only on an exact match": {"@DENYW@": "d == p"},
    "M7 absolute `..` ignored": {"@ABSWALK@": "walkL [] ((split s.tail).filter (· ≠ dotdot))"},
    "M8 empty input accepted": {"@EMPTY@": "False"},
    "M9 rel is the whole path": {"@UNDER@": "(pol.allow.find? fun a => a.isPrefixOf p).map fun a => (a, p)"},
    "M10 last matching root named": {
        "@UNDER@": "(pol.allow.reverse.find? fun a => a.isPrefixOf p).map fun a => (a, p.drop a.length)"},
    "M11 rel off by one segment": {
        "@UNDER@": "(pol.allow.find? fun a => a.isPrefixOf p).map fun a => (a, p.drop (a.length + 1))"},
}

# Bugs planted in examples/safe_extract.py, as (text, replacement); the CLI is the control's.
EXAMPLE_MUTANTS = {
    "E1 hard links extracted as files": ("m.isreg() or m.isdir()", "m.isreg() or m.isdir() or m.islnk()"),
    "E2 files created without O_EXCL": ("os.O_CREAT | os.O_EXCL", "os.O_CREAT | os.O_TRUNC"),
    "E3 the raw name created instead of rel": ('r["rel"].split("/")', 'name.split("/")'),
}


def main():
    tmp = tempfile.mkdtemp()
    repo = os.path.join(tmp, "pathfence")
    shutil.copytree(ROOT, repo, symlinks=True)
    main_lean = os.path.join(repo, "Main.lean")
    orig = open(main_lean, encoding="utf-8").read()
    hooks = ["let d := pol.checkString s;", "match pol.allowedUnder p with", "/-- A relative path: its segments"]
    for h in hooks:
        assert orig.count(h) == 1, f"Main.lean changed; update the mutation hooks ({h!r})"
    example = os.path.join(repo, "examples", "safe_extract.py")
    example_orig = open(example, encoding="utf-8").read()
    for old, _ in EXAMPLE_MUTANTS.values():
        assert example_orig.count(old) == 1, f"safe_extract.py changed; update the example mutants ({old!r})"
    ok = True
    try:
        for name, over in list(MUTANTS.items()) + [(n, {}) for n in EXAMPLE_MUTANTS]:
            pre = PRELUDE
            for k, v in dict(BASE, **over).items():
                pre = pre.replace(k, v)
            m = orig.replace(hooks[0], "let d := Mut.check pol s.toList;")
            m = m.replace(hooks[1], "match Mut.allowedUnder pol p with")
            m = m.replace(hooks[2], pre + "\n" + hooks[2])
            open(main_lean, "w", encoding="utf-8").write(m)
            old, new = EXAMPLE_MUTANTS.get(name, ("", ""))
            open(example, "w", encoding="utf-8").write(example_orig.replace(old, new) if old else example_orig)
            b = subprocess.run(["lake", "build", "pathfence"], cwd=repo, capture_output=True, text=True)
            if b.returncode != 0:
                print(f"{name}: BUILD FAILED\n{b.stdout[-1500:]}{b.stderr[-1500:]}")
                ok = False
                continue
            t = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=repo,
                               capture_output=True, text=True)
            passed = t.returncode == 0
            expected = name.startswith("M0")
            verdict = "ok" if passed == expected else "UNEXPECTED"
            ok &= passed == expected
            summary = [l for l in t.stderr.splitlines() if l.startswith(("OK", "FAILED"))]
            print(f"{name}: suite {'passed' if passed else 'failed'} ({' '.join(summary)}) -> {verdict}")
    finally:
        shutil.rmtree(tmp)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
