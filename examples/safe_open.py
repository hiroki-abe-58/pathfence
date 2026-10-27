"""Open a file for an agent: PathFence decides, the kernel opens. Linux 5.6+ (openat2).

    fd = safe_open("src/main.rs", allow=["/home/u/project"], deny=["/home/u/project/.git"])

1. `pathfence check` decides whether the requested path is allowed. If it is, it reports the
   allowed root the path is under and the rest of the path below that root (`root`, `rel`). Its
   answer is used only if it is one JSON object for exactly this path, the exit status agrees with
   the decision, and `root` is one of the allowed roots as given; a timeout, a missing binary,
   malformed output or a usage error (a root that is not canonical, say) refuses.
2. The file is opened as `rel` beneath a directory handle for `root`, with
   `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`. The kernel then refuses any symlink and any
   escape at open time, which the lexical check cannot see, so a symlink into a denied root or
   out of the workspace fails too.

Python's standard library has no openat2, so it is called through ctypes. The path is passed as one
command-line argument after `--`, never on stdin, so a newline in it cannot split it into two
requests.
"""
import ctypes
import json
import os
import struct
import subprocess

PATHFENCE = os.environ.get("PATHFENCE_BIN", "pathfence")
TIMEOUT = 10  # seconds for `pathfence check`

SYS_openat2 = 437  # x86_64 and aarch64
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08


class Refused(Exception):
    """PathFence denied or rejected the path, or gave no usable answer; `result` is the answer."""

    def __init__(self, result):
        super().__init__(f"{result.get('decision')}: {result.get('path') or result.get('reason')}")
        self.result = result


def check(path, allow, deny=(), base=None):
    """PathFence's answer for one path, as a dict; a `reject` whenever the answer is unusable."""
    for name, value in (("allow", allow), ("deny", deny)):
        if isinstance(value, (str, bytes)):
            raise TypeError(f"{name} must be a list of strings, not a single string")
    allow, deny = [os.fspath(a) for a in allow], [os.fspath(d) for d in deny]
    if not all(isinstance(x, str) for x in allow + deny):
        raise TypeError("allow and deny must hold str or os.PathLike paths")
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    args = [PATHFENCE, "check"]
    for a in allow:
        args += ["--allow", a]
    for d in deny:
        args += ["--deny", d]
    if base is not None:
        args += ["--base", base]
    try:
        p = subprocess.run(args + ["--", path], stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT,
                           check=False)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as e:
        return {"decision": "reject", "reason": f"pathfence did not run: {e}"}
    if p.returncode == 2:  # a usage error, e.g. a root that is not canonical
        return {"decision": "reject", "reason": "pathfence: " + p.stderr.decode("utf-8", "replace").strip()}
    lines = p.stdout.decode("ascii", "replace").split("\n")
    if not p.stdout.isascii() or len(lines) != 2 or lines[1] != "":  # the output is ASCII by design
        return {"decision": "reject", "reason": f"unexpected pathfence output (exit {p.returncode})"}
    try:
        r = json.loads(lines[0])
    except ValueError:
        r = None
    if not isinstance(r, dict) or r.get("input") != path:
        return {"decision": "reject", "reason": "pathfence answered for something else"}
    if r.get("decision") not in ("allow", "deny", "reject"):
        return {"decision": "reject", "reason": "pathfence gave no decision"}
    # The exit status is 0 exactly when every path is allowed; a mismatch means a confused answer.
    if (r["decision"] == "allow") != (p.returncode == 0):
        return {"decision": "reject", "reason": f"pathfence exit {p.returncode} disagrees with its decision"}
    # The file is opened beneath `root`, so a wrong `root` (say `/`) would open a file outside the roots.
    if r["decision"] == "allow" and (r.get("root") not in allow or not isinstance(r.get("rel"), str)):
        return {"decision": "reject", "reason": "pathfence named a root that is not an allowed root"}
    # `rel` is what gets opened, so it must name the reported `path` (`.` is the root itself).
    if r["decision"] == "allow" and r.get("path") != (r["root"] if r["rel"] == "." else r["root"] + "/" + r["rel"]):
        return {"decision": "reject", "reason": "pathfence's root and rel do not name its path"}
    return r


def openat2(dirfd, path, flags, mode=0, resolve=RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS):
    libc = ctypes.CDLL(None, use_errno=True)
    how = struct.pack("QQQ", flags | os.O_CLOEXEC, mode, resolve)
    buf = ctypes.create_string_buffer(how, len(how))
    fd = libc.syscall(SYS_openat2, dirfd, os.fsencode(path), buf, len(how))
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), path)
    return fd


def safe_open(path, allow, deny=(), base=None, flags=os.O_RDONLY, mode=0o644):
    """A file descriptor for `path`, or `Refused` (PathFence said no, or gave no usable answer) or
    `OSError` (the kernel did)."""
    r = check(path, allow, deny, base)
    if r["decision"] != "allow":
        raise Refused(r)
    rootfd = os.open(r["root"], os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        # openat2 refuses a mode unless the call can create the file.
        return openat2(rootfd, r["rel"], flags, mode if flags & (os.O_CREAT | os.O_TMPFILE) else 0)
    finally:
        os.close(rootfd)
