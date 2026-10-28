"""The two layers together (examples/safe_open.py): PathFence decides, openat2 opens.

A workspace with a denied `.git`, a symlink into it and a symlink out of the workspace: the lexical
check alone allows both symlinked paths, and the confined open refuses them. Unusable answers from
the binary, simulated by replacing `subprocess.run`, refuse before anything is opened.
"""
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


def pathfence_says(code, stdout, stderr=b""):
    return mock.patch.object(safe_open.subprocess, "run",
                             return_value=subprocess.CompletedProcess([], code, stdout, stderr))


def answer(**fields):
    r = {"input": "src/a", "decision": "allow", "path": "/w/src/a", "root": "/w", "rel": "src/a"}
    return json.dumps({**r, **fields}).encode() + b"\n"


class UnusableAnswers(unittest.TestCase):
    POLICY = dict(allow=["/w"], deny=["/w/.git"])

    def test_each_refuses_before_anything_is_opened(self):
        good = answer()
        for code, out in ((0, answer(input="src/other")), (1, good), (3, good), (-11, good),
                          # A root that is not one of the allowed roots, or no usable rel.
                          (0, answer(root="/", rel="etc/passwd", path="/etc/passwd")),
                          (0, answer(root="/w/src", rel="a")), (0, answer(rel=None)),
                          # A rel that does not name the reported path (it is what gets opened).
                          (0, answer(rel=".git/config")),
                          (0, b"not json\n"), (0, b"[]\n"), (0, b"{}\n"), (0, answer(decision="maybe")),
                          (0, b""), (0, good + good), (0, good[:-1]), (0, good[:-3] + b'\xc3\xa9"}\n')):
            with self.subTest(code=code, out=out), pathfence_says(code, out):
                self.assertEqual(safe_open.check("src/a", **self.POLICY)["decision"], "reject")
                with mock.patch.object(safe_open.os, "open") as opened, self.assertRaises(safe_open.Refused):
                    safe_open.safe_open("src/a", **self.POLICY)
                opened.assert_not_called()

    def test_a_good_answer_is_used(self):
        with pathfence_says(0, answer()):
            self.assertEqual(safe_open.check("src/a", **self.POLICY)["rel"], "src/a")
        # os.PathLike paths and roots work as their strings.
        with pathfence_says(0, answer()):
            self.assertEqual(safe_open.check(Path("src/a"), allow=[Path("/w")])["decision"], "allow")
        # The root itself is `rel` ".".
        with pathfence_says(0, answer(input=".", path="/w", rel=".")):
            self.assertEqual(safe_open.check(".", **self.POLICY)["decision"], "allow")

    def test_several_paths_need_one_usable_answer_each(self):
        a, b = answer(), answer(input="src/b", path="/w/src/b", rel="src/b")
        deny_b = answer(input="src/b", decision="deny", path="/w/.git/b")
        with pathfence_says(0, a + b):
            self.assertEqual([r["rel"] for r in safe_open.check_all(["src/a", "src/b"], **self.POLICY)],
                             ["src/a", "src/b"])
        with pathfence_says(1, a + deny_b):
            self.assertEqual([r["decision"] for r in safe_open.check_all(["src/a", "src/b"], **self.POLICY)],
                             ["allow", "deny"])
        # One bad part makes every answer a reject: a missing or swapped answer, a wrong exit status
        # (only 1 goes with a deny; 3 or a signal is a crash, not an answer).
        for code, out in ((0, a), (0, b + a), (0, a + deny_b), (1, a + b), (0, a + b + b),
                          (3, a + deny_b), (-11, a + deny_b), (137, a + deny_b)):
            with self.subTest(code=code, out=out), pathfence_says(code, out):
                self.assertEqual([r["decision"] for r in safe_open.check_all(["src/a", "src/b"], **self.POLICY)],
                                 ["reject", "reject"])

    def test_a_usage_error_refuses_and_says_why(self):
        with pathfence_says(2, b"", b"not a canonical absolute directory: /w/\n"):
            r = safe_open.check("src/a", allow=["/w/"])
        self.assertEqual((r["decision"], r["reason"]), ("reject", "pathfence: not a canonical absolute directory: /w/"))
        # And with the real binary.
        self.assertEqual(safe_open.check("src/a", allow=["/w/"])["decision"], "reject")

    def test_a_timeout_is_set_and_refuses(self):
        with mock.patch.object(safe_open.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("pathfence", 1)) as run:
            self.assertEqual(safe_open.check("src/a", **self.POLICY)["decision"], "reject")
        self.assertEqual(run.call_args.kwargs["timeout"], safe_open.TIMEOUT)

    def test_a_missing_binary_or_input_it_cannot_take_refuses(self):
        with mock.patch.object(safe_open, "PATHFENCE", os.path.join(ROOT, "no-such-binary")):
            self.assertEqual(safe_open.check("src/a", **self.POLICY)["decision"], "reject")
        for bad in ("src/a\x00b", None):
            with self.subTest(path=repr(bad)):
                self.assertEqual(safe_open.check(bad, **self.POLICY)["decision"], "reject")

    def test_a_single_string_policy_is_an_error(self):
        with self.assertRaises(TypeError):
            safe_open.check("src/a", allow="/w")
        with self.assertRaises(TypeError):
            safe_open.check("src/a", allow=[b"/w"])


if __name__ == "__main__":
    unittest.main()
