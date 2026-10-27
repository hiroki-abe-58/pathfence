"""Random inputs: the binary must agree with the Python model, and absolute inputs must normalise like
`posixpath.normpath` (up to the leading-`//` case, which POSIX leaves to the implementation and
PathFence treats as `/`)."""
import posixpath
import random
import unittest

from common import as_pair, model_check, model_under, run_check

# Root names and their near misses ("w" against "wx" and "w.") make random absolute inputs land inside,
# next to and around the allowed roots, which is where string-prefix bugs show.
PIECES = ["a", "b", "c", "é", ".", "..", "", "...", ".a", "a.", " ", "%2e", "\\", "a\\..", "-x", "~",
          "w", "wx", "w.", "tmp", "s", "sx", ".git"]


def random_path(rng):
    n = rng.randint(0, 8)
    s = "/".join(rng.choice(PIECES) for _ in range(n))
    if rng.random() < 0.5:
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
            (["/w", "/tmp/s"], ["/w/b", "/w/.git"], "/w/c"),
            (["/"], ["/w"], "/w"),
        ]
        for allow, deny, base in policies:
            inputs = [random_path(rng) for _ in range(1500)]
            _, out = run_check(inputs, allow, deny, base=base, stdin=True)
            self.assertEqual(len(out), len(inputs))
            seen = {}
            for s, r in zip(inputs, out):
                with self.subTest(input=s, allow=allow, deny=deny, base=base):
                    self.assertEqual(r["input"], s)
                    self.assertEqual(as_pair(r), model_check(s, allow, deny, base))
                    if r["decision"] == "allow":
                        self.assertEqual((r["root"], r["rel"]), model_under(r["path"], allow))
                seen[r["decision"]] = seen.get(r["decision"], 0) + 1
            # Each policy must see each decision often, or the comparison says little.
            for d in ("allow", "deny", "reject"):
                self.assertGreater(seen.get(d, 0), 50, (allow, deny, base, seen))

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
