"""Shared helpers: run the `pathfence` binary, and an independent Python model of its documented rules.

The model is written from the README's description, not from the Lean code, so the tests compare two
separate implementations of the same specification.
"""
import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("PATHFENCE_BIN", os.path.join(ROOT, ".lake", "build", "bin", "pathfence"))


def run_check(paths, allow, deny=(), base=None, stdin=False):
    """Run `pathfence check` and return (exit status, list of decoded JSON results)."""
    args = [BIN, "check"]
    for a in allow:
        args += ["--allow", a]
    for d in deny:
        args += ["--deny", d]
    if base is not None:
        args += ["--base", base]
    if stdin:
        proc = subprocess.run(args + ["--stdin"], input="".join(p + "\n" for p in paths).encode(),
                              capture_output=True, check=False)
    else:
        proc = subprocess.run(args + ["--"] + list(paths), capture_output=True, check=False)
    lines = [json.loads(l) for l in proc.stdout.decode().splitlines() if l]
    return proc.returncode, lines


# ---- the reference model -------------------------------------------------------------------------

def lexical(stack, parts):
    """Lexical normalisation: '' and '.' do nothing, '..' leaves a directory (staying at '/')."""
    st = list(stack)
    for c in parts:
        if c in ("", "."):
            continue
        if c == "..":
            st = st[:-1]
        else:
            st.append(c)
    return st


def beneath(base, parts):
    """Like `lexical`, but a '..' taken while at the base (or above) fails: returns None."""
    st = list(base)
    for c in parts:
        if c in ("", "."):
            continue
        if c == "..":
            if len(st) <= len(base):
                return None
            st.pop()
        else:
            st.append(c)
    return st


def parse_root(s):
    assert s.startswith("/") and "\x00" not in s
    return lexical([], s[1:].split("/"))


def render(p):
    return "/" + "/".join(p)


def within(r, p):
    return p[: len(r)] == r


def model_check(s, allow, deny=(), base=None):
    """The decision the README promises, as (decision, path or reason)."""
    allow_p = [parse_root(a) for a in allow]
    deny_p = [parse_root(d) for d in deny]
    base_p = parse_root(base) if base is not None else allow_p[0]
    if "\x00" in s:
        return ("reject", "nul")
    if s.startswith("/"):
        p = lexical([], s[1:].split("/"))
    else:
        p = beneath(base_p, s.split("/"))
        if p is None:
            return ("reject", "escapes")
    ok = any(within(a, p) for a in allow_p) and not any(within(d, p) for d in deny_p)
    return ("allow" if ok else "deny", render(p))


def as_pair(result):
    return (result["decision"], result.get("path", result.get("reason")))
