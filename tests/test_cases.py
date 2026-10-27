"""Fixed cases, including inputs in the style of published path-confinement bugs (CWE-22)."""
import json
import subprocess
import unittest

from common import BIN, as_pair, model_check, model_under, run_check, run_raw

CASES = [
    # (allow roots, deny roots, input, expected decision, expected path or reason)
    # CVE-2025-54794 / CVE-2025-53110 style: a sibling whose name starts with the root's name.
    (["/tmp/allowed_dir"], [], "/tmp/allowed_dir_malicious/secret", "deny", "/tmp/allowed_dir_malicious/secret"),
    (["/tmp/allowed_dir"], [], "../allowed_dir_malicious/secret", "reject", "escapes"),
    (["/tmp/allowed_dir"], [], "/tmp/allowed_dir/x", "allow", "/tmp/allowed_dir/x"),
    # CVE-2025-22873 style (Go os.Root): a trailing "../".
    (["/w"], [], "../", "reject", "escapes"),
    (["/w"], [], "a/../", "allow", "/w"),
    (["/w"], [], "a/../..", "reject", "escapes"),
    # Traversal, absolute and relative.
    (["/w"], [], "../../etc/passwd", "reject", "escapes"),
    (["/w"], [], "a/../../w/b", "reject", "escapes"),
    (["/w"], [], "/w/../etc/passwd", "deny", "/etc/passwd"),
    (["/w"], [], "/w/x/../y", "allow", "/w/y"),
    (["/w"], [], "//w///x/./y", "allow", "/w/x/y"),
    (["/w"], [], "/../../w/x", "allow", "/w/x"),
    (["/w"], [], "", "reject", "empty"),
    (["/w"], [], ".", "allow", "/w"),
    (["/w"], [], "./a//b/", "allow", "/w/a/b"),
    # POSIX names are bytes other than '/' and NUL: these are ordinary names.
    (["/w"], [], "..\\..\\etc", "allow", "/w/..\\..\\etc"),
    (["/w"], [], "%2e%2e/%2e%2e/etc", "allow", "/w/%2e%2e/%2e%2e/etc"),
    (["/w"], [], "...", "allow", "/w/..."),
    (["/w"], [], "é/ü", "allow", "/w/é/ü"),
    # Deny roots inside an allowed root.
    (["/w"], ["/w/.git"], ".git/config", "deny", "/w/.git/config"),
    (["/w"], ["/w/.git"], "src/../.git/hooks/pre-commit", "deny", "/w/.git/hooks/pre-commit"),
    (["/w"], ["/w/.git"], ".gitignore", "allow", "/w/.gitignore"),
    (["/w"], ["/w/.git"], "/w/.git", "deny", "/w/.git"),
    # Allowing everything ("/", passed as --allow-all).
    (["/"], [], "/etc/passwd", "allow", "/etc/passwd"),
    (["/"], [], "..", "reject", "escapes"),
]


class FixedCases(unittest.TestCase):
    def test_cases(self):
        for allow, deny, s, decision, detail in CASES:
            with self.subTest(input=s, allow=allow, deny=deny):
                status, out = run_check([s], allow, deny)
                self.assertEqual(len(out), 1)
                self.assertEqual(as_pair(out[0]), (decision, detail))
                self.assertEqual(model_check(s, allow, deny), (decision, detail))
                self.assertEqual(status, 0 if decision == "allow" else 1)
                if decision == "allow":
                    self.assertEqual((out[0]["root"], out[0]["rel"]), model_under(detail, allow))

    def test_root_and_rel(self):
        _, out = run_check(["/tmp/scratch/out/x", "src/main.rs", "."], ["/home/u/p", "/tmp/scratch"])
        self.assertEqual([(r["root"], r["rel"]) for r in out],
                         [("/tmp/scratch", "out/x"), ("/home/u/p", "src/main.rs"), ("/home/u/p", ".")])
        # The first allowed root that contains the path is named.
        _, out = run_check(["/w/a/b"], ["/w", "/w/a"])
        self.assertEqual((out[0]["root"], out[0]["rel"]), ("/w", "a/b"))

    def test_nul_is_rejected(self):
        # NUL cannot be passed in argv; it can be passed on stdin.
        status, out = run_check(["a\x00b", "ok"], ["/w"], stdin=True)
        self.assertEqual([as_pair(r) for r in out], [("reject", "nul"), ("allow", "/w/ok")])
        self.assertEqual(status, 1)

    def test_encoding(self):
        # Bytes that are not UTF-8 are rejected, not checked with replacement characters.
        status, out = run_raw(["check", "--allow", "/w", "--stdin"], b"ok\nx\xffy\n\xe2\x82\xac\nx\xc3/../../etc")
        self.assertEqual([as_pair(r) for r in out],
                         [("allow", "/w/ok"), ("reject", "encoding"), ("allow", "/w/€"),
                          ("reject", "encoding")])
        self.assertEqual([r.get("input_hex") for r in out], [None, "78ff79", None, "78c32f2e2e2f2e2e2f657463"])
        self.assertEqual(status, 1)
        # On the command line the program only sees U+FFFD, so any U+FFFD is rejected there;
        # the same name passes on stdin, where it is known to be genuine.
        status, out = run_raw(["check", "--allow", "/w", "--", "x\udcffy", "x�y", "ok"])
        self.assertEqual([as_pair(r) for r in out],
                         [("reject", "encoding"), ("reject", "encoding"), ("allow", "/w/ok")])
        self.assertEqual(run_check(["x�y"], ["/w"], stdin=True)[1][0]["decision"], "allow")
        self.assertEqual(run_raw(["check", "--allow", "/w\udcff", "--", "a"])[0], 2)

    def test_ascii_output(self):
        # Line separators and other non-ASCII characters are escaped, so splitting the output on any
        # line boundary gives one result per input.
        names = ["a b", "c d", "e\x85f", "g\x7fh", "\U0001f600", "é"]
        status, out = run_check(names, ["/w"], stdin=True)
        self.assertEqual([r["input"] for r in out], names)
        self.assertEqual([r["path"] for r in out], ["/w/" + n for n in names])
        raw = subprocess.run([BIN, "check", "--allow", "/w", "--stdin"], input="\n".join(names).encode(),
                             capture_output=True, check=False).stdout
        self.assertTrue(raw.isascii())
        self.assertEqual(len(raw.decode().splitlines()), len(names))

    def test_separate_base(self):
        status, out = run_check(["out.txt", "/tmp/scratch/x", "/tmp/scratchpad/x"],
                                ["/home/u/p", "/tmp/scratch"], base="/home/u/p")
        self.assertEqual([as_pair(r) for r in out],
                         [("allow", "/home/u/p/out.txt"), ("allow", "/tmp/scratch/x"),
                          ("deny", "/tmp/scratchpad/x")])

    def test_roots_are_literal(self):
        # Non-canonical roots are refused, not normalised (`/w/..` would otherwise become `/`).
        for root in ["/w/..", "/w/", "//w", "/w/./x", "w", "", "/tmp/x/../.."]:
            with self.subTest(root=root):
                self.assertEqual(run_raw(["check", "--allow", root, "--", "a"])[0], 2)
                self.assertEqual(run_raw(["check", "--allow", "/w", "--deny", root, "--", "a"])[0], 2)
        # Allowing everything must be explicit.
        self.assertEqual(run_raw(["check", "--allow", "/", "--", "/etc/passwd"])[0], 2)
        self.assertEqual(run_raw(["check", "--allow-all", "--", "/etc/passwd"])[0], 0)

    def test_usage_errors(self):
        self.assertEqual(run_check(["x"], [])[0], 2)
        self.assertEqual(run_check(["x"], ["relative"])[0], 2)
        # Paths go after `--`; before it, anything that is not an option is an error.
        self.assertEqual(run_raw(["check", "--allow", "/w", "x"])[0], 2)
        self.assertEqual(run_raw(["check", "--allow", "/w", "--bogus", "--", "x"])[0], 2)
        # After `--`, option names are paths.
        status, out = run_raw(["check", "--allow", "/w", "--", "--stdin", "--allow"], b"")
        self.assertEqual([as_pair(r) for r in out], [("allow", "/w/--stdin"), ("allow", "/w/--allow")])
        # Nothing to check is an error, not a pass.
        self.assertEqual(run_raw(["check", "--allow", "/w"])[0], 2)
        self.assertEqual(run_raw(["check", "--allow", "/w", "--stdin"], b"")[0], 2)
        self.assertEqual(run_raw(["check", "--allow", "/w", "--"])[0], 2)

    def test_going_down_and_back_up_takes_linear_time(self):
        # 1 MB: 200,000 levels down, then 200,000 `..`. When each `..` measured the whole stack, this
        # took 42 s on the machine in the README's Performance section; it takes 0.1 s. The limit
        # leaves a wide margin for slower machines.
        n = 200_000
        p = subprocess.run([BIN, "check", "--allow", "/w", "--stdin"], input=("a/" * n + "../" * n + "x\n").encode(),
                           capture_output=True, timeout=10, check=False)
        self.assertEqual((p.returncode, json.loads(p.stdout)["path"]), (0, "/w/x"))


if __name__ == "__main__":
    unittest.main()
