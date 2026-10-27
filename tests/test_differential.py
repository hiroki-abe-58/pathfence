"""Random inputs: the binary must agree with the independent Python model, and absolute inputs must
normalise like `posixpath.normpath` (up to the leading-`//` case, which POSIX leaves to the
implementation and PathFence treats as `/`)."""
import posixpath
import random
import unittest

from common import as_pair, model_check, run_check

PIECES = ["a", "b", "c", "é", ".", "..", "", "...", ".a", "a.", " ", "%2e", "\\", "a\\..", "-x", "~"]


def random_path(rng):
    n = rng.randint(0, 8)
    s = "/".join(rng.choice(PIECES) for _ in range(n))
    if rng.random() < 0.4:
        s = "/" * rng.randint(1, 3) + s
    if rng.random() < 0.2:
        s += "/"
    return s


class Differential(unittest.TestCase):
    def test_against_model(self):
        rng = random.Random(20261027)
        policies = [
            (["/w"], [], None),
            (["/w/a"], ["/w/a/b"], None),
            (["/w", "/tmp/s"], ["/w/b"], "/w/c"),
            (["/"], ["/w"], "/w"),
        ]
        for allow, deny, base in policies:
            inputs = [random_path(rng) for _ in range(1500)]
            _, out = run_check(inputs, allow, deny, base=base, stdin=True)
            self.assertEqual(len(out), len(inputs))
            seen = set()
            for s, r in zip(inputs, out):
                with self.subTest(input=s, allow=allow, deny=deny, base=base):
                    self.assertEqual(r["input"], s)
                    self.assertEqual(as_pair(r), model_check(s, allow, deny, base))
                seen.add(r["decision"])
            # Each policy must see allows and rejects (and denies, where it can deny at all).
            self.assertIn("allow", seen)
            self.assertIn("reject", seen)
            self.assertIn("deny", seen)

    def test_absolute_matches_normpath(self):
        rng = random.Random(7)
        inputs = []
        while len(inputs) < 2000:
            s = random_path(rng)
            if s.startswith("/"):
                inputs.append(s)
        _, out = run_check(inputs, ["/"], stdin=True)
        for s, r in zip(inputs, out):
            with self.subTest(input=s):
                expected = posixpath.normpath(s)
                if expected.startswith("//") and not expected.startswith("///"):
                    expected = expected[1:]  # POSIX keeps a leading '//'; PathFence treats it as '/'
                self.assertEqual(r["decision"], "allow")
                self.assertEqual(r["path"], expected)


if __name__ == "__main__":
    unittest.main()
