"""Open a file for an agent: PathFence decides, the kernel opens. Linux 5.6+ (openat2).

    fd = safe_open("src/main.rs", allow=["/home/u/project"], deny=["/home/u/project/.git"])

1. `pathfence check` decides whether the requested path is allowed. If it is, it reports the
   allowed root the path is under and the rest of the path below that root (`root`, `rel`).
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

SYS_openat2 = 437  # x86_64 and aarch64
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08


class Refused(Exception):
    """PathFence denied or rejected the path; `result` is its JSON answer."""

    def __init__(self, result):
        super().__init__(f"{result.get('decision')}: {result.get('path') or result.get('reason')}")
        self.result = result


def check(path, allow, deny=(), base=None):
    """PathFence's answer for one path, as a dict."""
    args = [PATHFENCE, "check"]
    for a in allow:
        args += ["--allow", a]
    for d in deny:
        args += ["--deny", d]
    if base is not None:
        args += ["--base", base]
    p = subprocess.run(args + ["--", path], capture_output=True, check=False)
    if p.returncode == 2:
        raise ValueError(p.stderr.decode(errors="replace").strip())
    lines = p.stdout.decode("ascii").split("\n")
    if len(lines) != 2 or lines[1] != "":
        raise RuntimeError(f"expected one result line, got {p.stdout!r}")
    return json.loads(lines[0])


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
    """A file descriptor for `path`, or `Refused` (PathFence said no) or `OSError` (the kernel did)."""
    r = check(path, allow, deny, base)
    if r["decision"] != "allow":
        raise Refused(r)
    rootfd = os.open(r["root"], os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        # openat2 refuses a mode unless the call can create the file.
        return openat2(rootfd, r["rel"], flags, mode if flags & (os.O_CREAT | os.O_TMPFILE) else 0)
    finally:
        os.close(rootfd)
