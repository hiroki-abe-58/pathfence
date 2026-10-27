"""Shared helpers: run the `pathfence` binary, and a Python model of its documented rules.

The model is a separate implementation of the rules in the README, written without the Lean code. It
follows the same rules, so it catches implementation mistakes, not mistakes in the rules themselves
(the kernel test in test_kernel.py checks the relative-path rule against Linux).
"""
import json
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("PATHFENCE_BIN", os.path.join(ROOT, ".lake", "build", "bin", "pathfence"))


def run_check(paths, allow, deny=(), base=None, stdin=False):
    """Run `pathfence check` and return (exit status, list of decoded JSON results).

    An allowed root of "/" is passed as `--allow-all`."""
    args = ["check"]
    for a in allow:
        args += ["--allow-all"] if a == "/" else ["--allow", a]
    for d in deny:
        args += ["--deny", d]
    if base is not None:
        args += ["--base", base]
    if stdin:
        return run_raw(args + ["--stdin"], "".join(p + "\n" for p in paths).encode())
    return run_raw(args + ["--"] + list(paths))


def run_raw(args, data=None):
    """Run `pathfence` with `args` (str, or bytes via surrogateescape) and stdin bytes `data`."""
    proc = subprocess.run([BIN] + list(args), input=data, capture_output=True, check=False)
    out = proc.stdout.decode("ascii")  # the output is ASCII by design
    return proc.returncode, [json.loads(l) for l in out.split("\n") if l]


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
    """A root must be canonical: '/' or '/seg/seg' with valid segments. Returns None otherwise."""
    if s == "/":
        return []
    if not s.startswith("/") or "\x00" in s:
        return None
    parts = s[1:].split("/")
    if any(c in ("", ".", "..") for c in parts):
        return None
    return parts


def render(p):
    return "/" + "/".join(p)


def within(r, p):
    return p[: len(r)] == r


def model_check(s, allow, deny=(), base=None):
    """The decision the README promises, as (decision, path or reason)."""
    allow_p = [parse_root(a) for a in allow]
    deny_p = [parse_root(d) for d in deny]
    base_p = parse_root(base) if base is not None else allow_p[0]
    if s == "":
        return ("reject", "empty")
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


def model_under(path, allow):
    """The first allowed root that `path` (an allowed result) is within, and the rest below it."""
    p = [c for c in path.split("/") if c]
    for a in allow:
        r = parse_root(a)
        if within(r, p):
            rest = p[len(r):]
            return render(r), "/".join(rest) if rest else "."
    raise AssertionError(f"{path} is under no allowed root")


def as_pair(result):
    return (result["decision"], result.get("path", result.get("reason")))
