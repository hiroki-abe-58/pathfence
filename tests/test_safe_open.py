"""The two layers together (examples/safe_open.py): PathFence decides, openat2 opens.

A workspace with a denied `.git`, a symlink into it and a symlink out of the workspace: the lexical
check alone allows both symlinked paths, and the confined open refuses them.
"""
import errno
import os
import shutil
import sys
import tempfile
import unittest

from common import BIN, ROOT
from test_kernel import openat2_available

sys.path.insert(0, os.path.join(ROOT, "examples"))
import safe_open  # noqa: E402

safe_open.PATHFENCE = BIN


@unittest.skipUnless(openat2_available(), "openat2 is not available")
class SafeOpen(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.w = os.path.realpath(os.path.join(self.tmp, "w"))
        os.makedirs(os.path.join(self.w, ".git"))
        os.makedirs(os.path.join(self.w, "src"))
        with open(os.path.join(self.w, ".git", "config"), "w") as f:
            f.write("[secret]\n")
        with open(os.path.join(self.w, "src", "main.rs"), "w") as f:
            f.write("fn main() {}\n")
        os.symlink(".git", os.path.join(self.w, "cfg"))      # into the denied root
        os.symlink("/etc", os.path.join(self.w, "out"))      # out of the workspace
        self.policy = dict(allow=[self.w], deny=[os.path.join(self.w, ".git")])

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_allowed_file_opens(self):
        fd = safe_open.safe_open("src/../src/main.rs", **self.policy)
        with os.fdopen(fd) as f:
            self.assertEqual(f.read(), "fn main() {}\n")

    def test_creates_inside_root(self):
        fd = safe_open.safe_open("src/new.txt", **self.policy, flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        os.close(fd)
        self.assertTrue(os.path.isfile(os.path.join(self.w, "src", "new.txt")))

    def test_pathfence_refuses(self):
        for p in [".git/config", "../w/src/main.rs", "/etc/passwd", ""]:
            with self.subTest(path=p), self.assertRaises(safe_open.Refused):
                safe_open.safe_open(p, **self.policy)

    def test_symlinks_are_refused_at_open(self):
        for p in ["cfg/config", "out/passwd"]:
            with self.subTest(path=p):
                # The lexical check allows these: it cannot see the symlink ...
                self.assertEqual(safe_open.check(p, **self.policy)["decision"], "allow")
                # ... and the confined open refuses it.
                with self.assertRaises(OSError) as e:
                    safe_open.safe_open(p, **self.policy)
                self.assertEqual(e.exception.errno, errno.ELOOP)

    def test_newline_is_one_request(self):
        # One argument is one request: `src\n..` is a single name, so this resolves to /w/etc/passwd
        # (and does not become the two requests `src` and `../../etc/passwd`).
        r = safe_open.check("src\n../../etc/passwd", **self.policy)
        self.assertEqual((r["decision"], r["path"], r["rel"]), ("allow", self.w + "/etc/passwd", "etc/passwd"))


if __name__ == "__main__":
    unittest.main()
