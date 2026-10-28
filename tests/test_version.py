"""The version is written in three places, and they must agree.

lakefile.lean is the source: the Python package takes its version from it (pyproject.toml,
[tool.hatch.version]). `pathfence --version` (Main.lean) and the README's status line, which is also
the PyPI description, are written by hand. Without this test, a release that bumped only the
lakefile would ship a wheel whose `--version` names the previous release. See docs/release-checks.md.

Nothing here skips. Wherever the suite runs (a checkout, the sdist, or publish.yml's installed-wheel
test, which moves only .lake and the Lean toolchain away), lakefile.lean and README.md are there, so
a missing file or a line not found is a failure, not a pass.
"""
import os
import re
import subprocess
import unittest

from common import BIN, ROOT

# Every `version := v!"..."` in the lakefile, with any spacing. It matches wherever hatch's pattern in
# pyproject.toml does (hatch takes the first match), so exactly one match here is the version hatch
# reads. Lean is not needed: the installed-wheel test runs without it.
LAKEFILE_VERSION = re.compile(r'version\s*:=\s*v!"([^"]*)"')
# A version on the README's status line is `v` and a digit, up to the last letter or digit before a
# space or punctuation: `v0.1.0,` is 0.1.0, `v0.2.0-rc.1.` is 0.2.0-rc.1. Release tags are written
# the same way. The rest of the line is free, and numbers without a `v` (Linux 5.6) are not versions.
README_VERSION = re.compile(r"\bv(\d(?:[\w.+-]*\w)?)")


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def package_version():
    found = LAKEFILE_VERSION.findall(read("lakefile.lean"))
    if len(found) != 1:
        raise AssertionError(f'lakefile.lean: expected one `version := v!"..."`, found {len(found)}: {found}')
    return found[0]


class Version(unittest.TestCase):
    def test_cli_prints_the_package_version(self):
        version = package_version()
        p = subprocess.run([BIN, "--version"], capture_output=True, timeout=10, check=False)
        self.assertEqual((p.returncode, p.stdout), (0, f"pathfence {version}\n".encode()),
                         f"`{BIN} --version` must print lakefile.lean's version, {version} "
                         "(the string is in Main.lean)")

    def test_readme_status_names_the_package_version(self):
        version = package_version()
        status = [line for line in read("README.md").splitlines() if line.startswith("Status:")]
        self.assertEqual(len(status), 1, "README.md: expected one line starting with `Status:`")
        self.assertEqual(README_VERSION.findall(status[0]), [version],
                         f"README.md's status line must name lakefile.lean's version, v{version}, and no other: "
                         f"{status[0]!r}")


if __name__ == "__main__":
    unittest.main()
