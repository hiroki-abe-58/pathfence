# PathFence

A path-confinement check for tools that let an AI agent (or any untrusted caller) read and write
files, written and proven in Lean 4.

You give it the directories the caller may use, optionally directories inside them it may not use,
and a requested path. It answers *allow* (with the resolved path), *deny* (with the resolved path)
or *reject* (with a reason). Lean theorems state exactly when it allows, and a command-line tool
makes the proven function usable from any language.

```console
$ pathfence check --allow /tmp/allowed_dir -- /tmp/allowed_dir_malicious/secret ../x a/../b
{"input":"/tmp/allowed_dir_malicious/secret","decision":"deny","path":"/tmp/allowed_dir_malicious/secret"}
{"input":"../x","decision":"reject","reason":"escapes"}
{"input":"a/../b","decision":"allow","path":"/tmp/allowed_dir/b"}
```

Status: v0.1.0, experimental. Not reviewed by a third party. The decision is *lexical*: it looks at
the path string, never at the file system. Read [What it does not cover](#what-it-does-not-cover)
before relying on it.

## Why

Confinement checks are easy to get almost right. Published examples:

* [CVE-2025-53110](https://www.cve.org/CVERecord?id=CVE-2025-53110) (MCP Filesystem server before
  0.6.4 / 2025.7.01) and [CVE-2025-54794](https://www.cve.org/CVERecord?id=CVE-2025-54794) (Claude
  Code before 0.2.111): the check was a string-prefix test, so `/tmp/allowed_dir_malicious` passed
  as "inside" `/tmp/allowed_dir`.
* [CVE-2025-22873](https://www.cve.org/CVERecord?id=CVE-2025-22873) (Go `os.Root` before 1.23.9 /
  1.24.3): `Root.Open("../")` opened the parent of the root.

PathFence compares paths segment by segment, and its theorems rule out both kinds of mistake for
the decision it makes. [`PathFence/Examples.lean`](PathFence/Examples.lean) runs it on inputs in the
style of these bugs at build time. (It does not reproduce the original programs.)

## The rules

A *policy* has a base directory (where relative paths start), allowed roots and denied roots, all
absolute.

1. An input containing NUL is rejected (`nul`).
2. An absolute input is normalised lexically from `/`: empty pieces and `.` are dropped, and `..`
   removes the previous segment (at `/` it does nothing, as in POSIX).
3. A relative input is walked from the base with the *beneath* rule of Linux's
   `openat2(RESOLVE_BENEATH)`: a `..` that would leave the base is an error (`escapes`), even if
   later segments come back in. `a/../../w/b` with base `/w` is rejected.
4. The resolved path is allowed when it is within some allowed root and within no denied root.
   "Within" compares whole segments: `/tmp/a` is within `/tmp/a` and `/tmp/a/b`, never `/tmp/ab`.

Names are POSIX names: any characters except `/` and NUL. `\`, `%2e`, `...` and non-ASCII names are
ordinary names.

The command-line tool also rejects input that is not UTF-8 (`encoding`) instead of checking a
different string; see [`Main.lean`](Main.lean).

## What is proven

All theorems are in [`PathFence/`](PathFence), checked by Lean v4.35.0, with no `sorry` and only
Lean's standard axioms (`propext`, `Classical.choice`, `Quot.sound`;
see [`scripts/audit.sh`](scripts/audit.sh)).

| Theorem | Statement |
| --- | --- |
| `check_allow_iff` | `check` allows `p` **iff** the input resolves to `p`, `p` is within some allowed root, and `p` is within no denied root. |
| `resolve_rel_spec` | A relative input resolves to `p` **iff** `p` is its lexical walk from the base and every `..` is taken strictly inside the base. |
| `resolve_rel_within`, `check_allow_rel_within_base` | A resolved (or allowed) relative input is within the base. |
| `resolve_abs`, `resolve_nul` | Absolute inputs are normalised lexically from `/`; inputs with NUL are rejected. |
| `resolve_valid` | Every resolved segment is a real name: not empty, `.` or `..`, no `/` or NUL. |
| `resolve_render` | Printing a resolved path and resolving the printed string gives the same path, so the string you pass on is the path that was checked. |
| `within_iff_render` | For a root other than `/`, segment-wise "within" is the same as a string test on the printed paths: equal, or a prefix **followed by `/`**. This is the correct form of the string check that failed in the CVEs above. |
| `check_allow_of_add_deny`, `check_allow_add_allow` | Adding a denied root never allows more; adding an allowed root never allows less. |
| `walkB_spec` | The beneath walk equals its declarative specification. |
| `join_split`, `split_join`, `parseRoot_valid` | Splitting on `/` and joining are inverse; parsed roots are valid paths. |

The statements are about the Lean functions `Policy.check` and `resolve`, which the CLI calls
directly. The CLI itself (argument parsing, JSON output, stdin decoding) is ordinary code, covered
by tests rather than proofs.

## How it is checked

* `lake build` checks the proofs and runs the `#guard` examples.
* `scripts/audit.sh` rejects `sorry`, `admit`, `native_decide`, `axiom`, `implemented_by`,
  `extern`, `partial` and `unsafe` in the library, and prints the axioms behind each theorem.
* CI replays every module through the kernel with `leanchecker`.
* `tests/` (Python, standard library only) runs the built CLI against:
  * fixed cases, including the CVE-style inputs and invalid UTF-8;
  * an independent Python model of the rules above, on 6000 random inputs over four policies;
  * `posixpath.normpath` for absolute inputs;
  * on Linux 5.6+, the kernel itself: for 1500 random relative paths it creates the directories,
    then calls `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`. PathFence allows a path exactly
    when the kernel opens it, and every kernel refusal is `EXDEV`.

## Usage

Build with [elan](https://github.com/leanprover/elan) installed:

```sh
lake build
.lake/build/bin/pathfence check --allow /home/u/project --deny /home/u/project/.git -- src/main.rs
```

```
pathfence check --allow DIR [--allow DIR ...] [--deny DIR ...] [--base DIR] [--stdin] [--] PATH ...
```

* `--base` defaults to the first `--allow` root.
* `--stdin` reads one path per line (after any paths on the command line).
* One JSON object per path, in order. Exit status 0 if every path is allowed, 1 otherwise, 2 for a
  usage error.

**Open the returned `path`, not the original input.** The returned path is the one that was checked
(`resolve_render`).

From Lean, depend on this package and call `PathFence.Policy.check` (on `List Char`) or
`Policy.checkString`.

## What it does not cover

PathFence decides on the string. Between that decision and the file access, the file system can
disagree:

* **Symbolic links.** `/w/link/secret` is "within" `/w` even if `link` points to `/etc`. Absolute
  inputs are normalised lexically, so `/w/link/../x` becomes `/w/x`, whereas the kernel would follow
  `link` first. Open the result with symlink-safe calls: `openat2` with `RESOLVE_BENEATH` and
  `RESOLVE_NO_SYMLINKS` on Linux, or `O_NOFOLLOW` on every component.
* **Races.** A directory can be replaced by a symlink after the check (TOCTOU). Only resolving at
  open time, relative to a directory handle, closes this.
* **Hard links, bind mounts, `/proc/self/fd`** and similar aliases.
* **Case-insensitive or normalising file systems** (macOS, Windows): `/W` and `/w`, or NFC and NFD
  forms of a name, are different strings to PathFence but may be the same file.
* **Windows paths.** No drive letters, UNC paths or `\` separators. POSIX only.
* **Bytes that are not UTF-8.** The library works on Unicode text; the CLI rejects such input.
  POSIX names that are not UTF-8 cannot be allowed.
* **Leading `//`.** POSIX lets an implementation give it a special meaning; PathFence treats it as
  `/`.

Use PathFence as the policy layer (which paths an agent may ask for, with a precise answer), and an
`openat2`-style or capability API (Go `os.Root`, Rust `cap-std`) for the actual access.

## Related work

* Linux [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html) `RESOLVE_BENEATH`:
  the kernel rule PathFence's relative walk follows, and the oracle for its tests.
* Go [`os.Root`](https://pkg.go.dev/os#Root) and
  [`filepath.IsLocal`](https://pkg.go.dev/path/filepath#IsLocal); Rust
  [`cap-std`](https://github.com/bytecodealliance/cap-std): file-system-level confinement.
* [`is-path-inside`](https://github.com/sindresorhus/is-path-inside) (npm): the same lexical
  question, unverified.
* [Proven-Commons/path](https://github.com/Proven-Commons/path): a planned verified model of Go's
  `path.Clean`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

Written with AI assistance (Claude Code, Claude Opus 5.5) and reviewed by the author.
