"""Fixed cases, including inputs in the style of published path-confinement bugs (CWE-22)."""
import unittest

from common import as_pair, model_check, run_check

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
    (["/w"], [], "", "allow", "/w"),
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
    # Root "/" allows every absolute path.
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

    def test_nul_is_rejected(self):
        # NUL cannot be passed in argv; it can be passed on stdin.
        status, out = run_check(["a\x00b", "ok"], ["/w"], stdin=True)
        self.assertEqual([as_pair(r) for r in out], [("reject", "nul"), ("allow", "/w/ok")])
        self.assertEqual(status, 1)

    def test_separate_base(self):
        status, out = run_check(["out.txt", "/tmp/scratch/x", "/tmp/scratchpad/x"],
                                ["/home/u/p", "/tmp/scratch"], base="/home/u/p")
        self.assertEqual([as_pair(r) for r in out],
                         [("allow", "/home/u/p/out.txt"), ("allow", "/tmp/scratch/x"),
                          ("deny", "/tmp/scratchpad/x")])

    def test_usage_errors(self):
        self.assertEqual(run_check(["x"], [])[0], 2)
        self.assertEqual(run_check(["x"], ["relative"])[0], 2)


if __name__ == "__main__":
    unittest.main()
