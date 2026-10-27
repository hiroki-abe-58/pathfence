# Publishing PathFence

The PyPI package contains the compiled Lean executable and a Python launcher. It has no
Python runtime dependencies. Installing a wheel does not download or require Lean.
Linux (x86-64 and ARM64) and macOS (Intel and Apple Silicon) wheels are built and tested
by `.github/workflows/publish.yml`. Windows users can use the Linux package in WSL;
native Windows paths remain unsupported.

## One-time setup

1. Log in to PyPI, then open <https://pypi.org/manage/account/publishing/>.
2. Add a **pending publisher** with these exact values:

   | Field | Value |
   | --- | --- |
   | PyPI Project Name | `pathfence` |
   | Owner | `hiroki-abe-58` |
   | Repository name | `pathfence` |
   | Workflow name | `publish.yml` |
   | Environment name | `pypi` |

3. In GitHub repository Settings → Environments, create `pypi`. Restrict deployments
   to release tags and optionally add a required reviewer.

No PyPI password or API token belongs in GitHub secrets. If the PyPI project already
exists, configure its Trusted Publisher in the project's Publishing settings instead.

## Release

1. Change the version in `lakefile.lean` and update its pinned hash in `scripts/audit.sh`.
   Python package metadata reads the version from that same file. The first release is `0.1.0`.
2. Merge a reviewed PR after both CI and Python distribution checks pass.
3. Publish a GitHub release with the matching tag (for example `v0.1.0`) on the merged commit.
4. The workflow builds all four wheels, audits the Lean proofs, runs mutation checks,
   repairs platform dependencies, checks metadata, and tests installed wheels with the
   build tree and Lean toolchain moved out of the way. Only then does it publish.
5. Verify in a fresh virtual environment:

   ```sh
   python -m pip install --only-binary=:all: pathfence
   pathfence check --allow /w -- a/../b
   ```

PRs, pushes and manual workflow runs build and test artifacts without publishing.
Do not reuse a version already uploaded to PyPI. A partial upload must be investigated
before retrying; the workflow intentionally does not silently skip existing files.

## Local source builds

Install elan and the toolchain pinned in `lean-toolchain`, plus a C toolchain, then run:

```sh
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
```

The build first produces an sdist and then compiles the wheel from that sdist, checking
that the Lean sources and build configuration are included. A source install requires
Lean; use a published wheel when installing without a compiler. Linux wheels must be
processed by `auditwheel repair` before uploading to PyPI. macOS wheels are processed by
`delocate-wheel`. Compatibility tags reflect the build platform and audited native dependencies.
