# Release checks

The version is written in three places:

| Where | What uses it |
| --- | --- |
| `lakefile.lean`: `version := v!"…"` | the Python package (hatch reads it, see `pyproject.toml`), so the wheel and sdist versions and the tag check in `publish.yml` |
| `Main.lean` | `pathfence --version` |
| `README.md`: the line starting with `Status:` | the GitHub page and the PyPI description |

[`tests/test_version.py`](../tests/test_version.py) fails unless they agree:

* `lakefile.lean` contains `version := v!"…"` exactly once, with any spacing. Hatch's pattern is
  narrower and takes the first match, so this is the version hatch reads.
* `pathfence --version`, run on the binary the tests use, prints exactly `pathfence <version>` and
  exits 0.
* `README.md` has exactly one line starting with `Status:`, and the only version on it is
  `v<version>`. A version there is `v` and a digit, up to the last letter or digit before a space or
  punctuation (`v0.1.0,` is 0.1.0). The rest of the wording is free.

The strings are compared as written in `lakefile.lean`. For a plain `major.minor.patch` such as
0.1.0, that is also the version in the wheel's metadata.

## Where it runs

It never skips: a missing file, or a pattern found zero or several times, fails the suite.

* CI (`ci.yml`) and `scripts/reproduce.sh`: against `.lake/build/bin/pathfence`, built from the
  commit.
* `publish.yml`, step "Test installed wheel without the Lean toolchain", on all four platforms:
  against the installed wheel's `pathfence` (`PATHFENCE_BIN`). The step runs in the checkout, so
  `lakefile.lean` and `README.md` are there; only `.lake` and the Lean toolchain are moved away. On
  a release, the publish job runs only after this job passes, so a wheel whose `--version`
  disagrees with its package version is not uploaded.
* `tests/mutants.py` (in CI, the release workflow and `scripts/reproduce.sh`): V1 rebuilds the CLI
  with `--version` printing another version and requires the suite to fail. If the `--version`
  comparison stopped running (skipped, or no longer found by test discovery), the mutation check
  would fail.

With publish.yml's check that the release tag is `v` and the wheel's version, the tag, the package,
`pathfence --version` and the README status line name one version.

## What it does not check

* That the version is new. PyPI refuses a version already uploaded.
* Other mentions of a version, such as the examples in `docs/publishing.md`.
