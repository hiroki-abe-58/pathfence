"""Compare the beneath rule with the Linux kernel: `openat2(…, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`
on a real directory tree without symlinks.

For each random relative path, the directories it enters are created first, so that the only reason
for the kernel to refuse is leaving the base. PathFence must allow exactly the paths the kernel
resolves. Skipped where `openat2` is unavailable (not Linux, or kernel older than 5.6).
"""
import ctypes
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
PIECES = ["a", "b", "é", ".", "..", "..", "", "...", " ", "%2e", "\\"]


def openat2_ok(dirfd, path):
    libc = ctypes.CDLL(None, use_errno=True)
    how = struct.pack("QQQ", O_PATH | O_CLOEXEC, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)
    buf = ctypes.create_string_buffer(how, len(how))
    fd = libc.syscall(SYS_openat2, dirfd, path.encode(), buf, len(how))
    if fd >= 0:
        os.close(fd)
        return True, 0
    return False, ctypes.get_errno()


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
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            ok, err = openat2_ok(fd, ".")
            return ok or err not in (38,)  # ENOSYS
        finally:
            os.close(fd)
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
            base = os.path.join(tmp, "base")
            os.mkdir(base)
            for s in inputs:
                make_dirs(base, s)
            _, out = run_check(inputs, [base], stdin=True)
            fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
            allowed = refused = 0
            try:
                for s, r in zip(inputs, out):
                    with self.subTest(input=s):
                        kernel_ok, err = openat2_ok(fd, s)
                        self.assertEqual(r["decision"] == "allow", kernel_ok, f"errno {err}")
                        if not kernel_ok:
                            self.assertEqual(err, 18)  # EXDEV: the kernel refused to leave the base
                    allowed += kernel_ok
                    refused += not kernel_ok
            finally:
                os.close(fd)
            # Both outcomes must occur often, or the comparison says little.
            self.assertGreater(allowed, 100)
            self.assertGreater(refused, 100)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
