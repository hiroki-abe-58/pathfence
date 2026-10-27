"""Compare the beneath rule with the Linux kernel: `openat2(…, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`
on a real directory tree without symlinks.

For each random relative path, the directories it enters are created first, so that the only reason
for the kernel to refuse is leaving the base. PathFence must allow exactly the paths the kernel
opens, with the same resulting directory (read back through /proc/self/fd), and must reject with
`escapes` exactly the paths the kernel refuses with EXDEV. Skipped where `openat2` is unavailable
(not Linux, kernel older than 5.6, or blocked by a seccomp filter).
"""
import ctypes
import errno
import os
import random
import shutil
import struct
import sys
import tempfile
import unittest

from common import run_check

SYS_openat2 = 437  # the same number on x86_64 and aarch64
O_PATH = 0o10000000
O_CLOEXEC = 0o2000000
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
# "base" is the base directory's own name, so that inputs like "../base/x" occur.
PIECES = ["a", "b", "é", ".", "..", "..", "", "...", " ", "%2e", "\\", "base"]


def openat2(dirfd, path):
    """Return (fd, 0) on success, or (-1, errno)."""
    libc = ctypes.CDLL(None, use_errno=True)
    how = struct.pack("QQQ", O_PATH | O_CLOEXEC, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)
    buf = ctypes.create_string_buffer(how, len(how))
    fd = libc.syscall(SYS_openat2, dirfd, path.encode(), buf, len(how))
    return (fd, 0) if fd >= 0 else (-1, ctypes.get_errno())


def make_dirs(base, path):
    """Create every directory the lexical walk of `path` enters while it stays inside `base`."""
    cur = []
    for c in path.split("/"):
        if c in ("", "."):
            continue
        if c == "..":
            if not cur:
                return
            cur.pop()
        else:
            cur.append(c)
            os.makedirs(os.path.join(base, *cur), exist_ok=True)


def openat2_available():
    if not sys.platform.startswith("linux"):
        return False
    d = tempfile.mkdtemp()
    try:
        dirfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fd, _ = openat2(dirfd, ".")
            if fd < 0:
                return False  # ENOSYS, or EPERM from a seccomp filter
            os.close(fd)
            return True
        finally:
            os.close(dirfd)
    finally:
        shutil.rmtree(d)


@unittest.skipUnless(openat2_available(), "openat2 is not available")
class KernelBeneath(unittest.TestCase):
    def test_matches_resolve_beneath(self):
        rng = random.Random(42)
        inputs = []
        while len(inputs) < 1500:
            s = "/".join(rng.choice(PIECES) for _ in range(rng.randint(1, 7)))
            if s and not s.startswith("/"):  # relative, non-empty (the kernel refuses "")
                inputs.append(s)
        tmp = tempfile.mkdtemp()
        try:
            base = os.path.realpath(os.path.join(tmp, "base"))
            os.mkdir(base)
            for s in inputs:
                make_dirs(base, s)
            _, out = run_check(inputs, [base], stdin=True)
            dirfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            allowed = refused = 0
            try:
                for s, r in zip(inputs, out):
                    with self.subTest(input=s):
                        fd, err = openat2(dirfd, s)
                        if fd >= 0:
                            try:
                                opened = os.readlink(f"/proc/self/fd/{fd}")
                            finally:
                                os.close(fd)
                            self.assertEqual(r["decision"], "allow")
                            self.assertEqual(r["path"], opened)
                            self.assertEqual(r["root"], base)
                            # Opening `rel` beneath `root`, as callers are told to, reaches the same
                            # directory.
                            fd2, err2 = openat2(dirfd, r["rel"])
                            self.assertGreaterEqual(fd2, 0, f"errno {err2}")
                            try:
                                self.assertEqual(os.readlink(f"/proc/self/fd/{fd2}"), opened)
                            finally:
                                os.close(fd2)
                            allowed += 1
                        else:
                            self.assertEqual(err, errno.EXDEV)  # the kernel refused to leave the base
                            self.assertEqual((r["decision"], r.get("reason")), ("reject", "escapes"))
                            refused += 1
            finally:
                os.close(dirfd)
            # Both outcomes must occur often, or the comparison says little.
            self.assertGreater(allowed, 100)
            self.assertGreater(refused, 100)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
