# PathFence

A path-confinement check for tools that let an AI agent (or any untrusted caller) read and write
files, written and proven in Lean 4.

You give it the directories the caller may use, optionally directories inside them it may not use,
and a requested path. It answers *allow* (with the resolved path, and the allowed root it is under),
*deny* (with the resolved path) or *reject* (with a reason). Lean theorems state exactly when it
allows, and a command-line tool makes the proven function usable from any language.

```console
$ pathfence check --allow /tmp/allowed_dir -- /tmp/allowed_dir_malicious/secret ../x a/../b
{"input":"/tmp/allowed_dir_malicious/secret","decision":"deny","path":"/tmp/allowed_dir_malicious/secret"}
{"input":"../x","decision":"reject","reason":"escapes"}
{"input":"a/../b","decision":"allow","path":"/tmp/allowed_dir/b","root":"/tmp/allowed_dir","rel":"b"}
```

Status: v0.1.0, experimental. No human security review yet.

> **PathFence is not a sandbox. The decision is lexical.** It looks only at the path string, never
> at the file system. A symlink, a race between the check and the open, a hard link, a mount or a
> case-insensitive file system can make an allowed path reach a file outside the roots, and an agent
> can create symlinks itself (by cloning a repository, extracting an archive, or running a shell
> command). Do not pass the returned `path` to a plain `open()`. Open `rel` beneath `root` with a
> confined call, as in [Opening an allowed path](#opening-an-allowed-path), and read
> [What it does not cover](#what-it-does-not-cover).

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

A *policy* has a base directory (where relative paths start), allowed roots and denied roots.

0. Roots are taken literally and must be canonical: `/`, or `/` followed by names separated by
   single slashes, with no `.`, `..`, empty segment or trailing `/`. Anything else is refused, not
   normalised. Pass real directories (for example from `realpath`), not paths through symlinks.
1. An empty input is rejected (`empty`), and so is an input containing NUL (`nul`).
2. An absolute input is normalised lexically from `/`: empty pieces and `.` are dropped, and `..`
   removes the previous segment (at `/` it does nothing, as in POSIX).
3. A relative input is walked from the base with the *beneath* rule of Linux's
   `openat2(RESOLVE_BENEATH)`: a `..` that would leave the base is an error (`escapes`), even if
   later segments come back in. `a/../../w/b` with base `/w` is rejected.
4. The resolved path is allowed when it is within some allowed root and within no denied root.
   "Within" compares whole segments: `/tmp/a` and `/tmp/a/b` are within `/tmp/a`; `/tmp/ab` is
   not.

Names are POSIX names: any characters except `/` and NUL. `\`, `%2e`, `...` and non-ASCII names are
ordinary names.

## What is proven

All theorems are in [`PathFence/`](PathFence), checked by Lean v4.35.0, with no `sorry` and only
Lean's standard axioms (`propext`, `Classical.choice`, `Quot.sound`; see
[`scripts/audit.sh`](scripts/audit.sh)).

| Theorem | Statement |
| --- | --- |
| `check_allow_iff` | `check` allows `p` **iff** the input resolves to `p`, `p` is within some allowed root, and `p` is within no denied root. |
| `check_deny_iff`, `check_reject_iff` | It denies `p` iff the input resolves to `p` and `p` is not allowed; it rejects iff resolving fails, with the same reason. |
| `resolve_rel_spec` | A non-empty relative input resolves to `p` **iff** `p` is its lexical walk from the base and every `..` is taken strictly inside the base. |
| `resolve_rel_within`, `check_allow_rel_within_base` | A resolved (or allowed) relative input is within the base. |
| `resolve_empty`, `resolve_nul`, `resolve_abs` | Empty inputs and inputs with NUL are rejected; absolute inputs are normalised lexically from `/` (this restates the definition). |
| `resolve_valid` | Every resolved segment is a real name: not empty, `.` or `..`, no `/` or NUL. |
| `resolve_render` | Resolving a printed result gives the same path, so re-checking it gives the same decision. (This is about PathFence's lexical resolver, not about what the file system does with the string.) |
| `within_iff_render` | For a root other than `/`, segment-wise "within" is the same as a string test on the printed paths: equal, or a prefix **followed by `/`**. This is the correct form of the string check that failed in the CVEs above. |
| `allowedUnder_spec`, `allowedUnder_of_allow` | Every allowed path is reported with an allowed root `root` and a remainder `rel` such that `root ++ rel` is the path. |
| `check_allow_of_add_deny`, `check_allow_add_allow` | Adding a denied root never allows more; adding an allowed root never allows less. |
| `parseRoot_render`, `parseRoot_valid`, `Policy.make_valid` | A parsed root prints back to exactly its string, and consists of valid segments, as do all roots of a policy built with `Policy.make`. |
| `walkB_spec`, `join_split`, `split_join` | The beneath walk equals its declarative specification; splitting on `/` and joining are inverse. |

That the lexical normalisation of absolute inputs matches POSIX `normpath` is tested, not proven.

### Where the proofs end

The statements are about the Lean functions `Policy.check`, `resolve`, `Policy.allowedUnder` and
`parseRoot` on lists of characters. The CLI ([`Main.lean`](Main.lean)) calls them directly, and the
rest of it is ordinary code covered by tests, not proofs: argument parsing, reading and decoding
stdin, the conversion between `String` and `List Char`, JSON output and exit codes.

## How it is checked

* `lake build` checks the proofs and runs the `#guard` examples.
* `scripts/audit.sh`:
  * rejects `sorry`, `admit`, `native_decide`, axioms, `implemented_by`/`extern`, `partial`/`unsafe`,
    `#eval`/`initialize`, kernel-skipping options and metaprogramming commands in the library
    source;
  * checks that `lakefile.lean` builds just the library and the CLI, with no dependencies and no extra
    compiler options;
  * checks the compiled environment:
    * the library imports only `Init` and its own modules;
    * no library declaration has its compiled code replaced (`implemented_by`, `extern`);
    * every declaration (the list is generated, not maintained by hand) depends on no axiom outside
      the standard three;
  * replays every module through the kernel's own checker (`leanchecker`).

  It does not check that `Main.lean` calls the library as documented; that is left to review and
  the tests.
* `tests/` (Python, standard library only) runs the built CLI against:
  * fixed cases, including the CVE-style inputs, invalid UTF-8, option-like paths and
    non-canonical roots;
  * a separate Python implementation of the rules above, on 6000 random inputs over four policies,
    with root names and near misses (`w`, `wx`, `w.`) among the pieces. It follows the same rules,
    so it catches implementation mistakes, not mistakes in the rules;
  * `posixpath.normpath` for absolute inputs;
  * on Linux 5.6+, the kernel itself. For 1500 random relative paths the test creates the
    directories, then calls `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`. PathFence allows a
    path exactly when the kernel opens it, and reports the directory the kernel opened (read back
    from `/proc/self/fd`). It rejects with `escapes` exactly when the kernel refuses with `EXDEV`.
* `tests/mutants.py` checks the tests themselves. It rebuilds the CLI with eleven plausible bugs and
  requires each one to make the suite fail. The bugs include the CVE-style string prefix, an
  off-by-one in the beneath rule, an ignored deny root, accepting the empty input, and a wrong
  `root` or `rel`.

## Usage

Build with [elan](https://github.com/leanprover/elan) installed:

```sh
lake build
.lake/build/bin/pathfence check --allow /home/u/project --deny /home/u/project/.git -- src/main.rs
```

```
pathfence check (--allow DIR | --allow-all) ... [--deny DIR ...] [--base DIR] [--stdin] [-- PATH ...]
```

* Paths go after `--`. Anything before `--` that is not an option is an error, so a path such as
  `--stdin` can never be taken for an option.
* `--stdin` reads one path per line, after any paths given after `--`.
  * The whole input is read before the first answer; memory use is about 25 times the input size.
  * Lines are split on `\n` only, so a `\r` stays part of the name.
* `--base` defaults to the first `--allow` root.
* `--allow /` is refused, so that an empty variable in `--allow "$ROOT/"` cannot allow every path.
  Use `--allow-all` if that is what you mean.
  * `--allow-all` counts as a root after all `--allow` roots, wherever it appears.
  * With no `--allow` root, the base for relative paths is `/`.
* One JSON object per path, in order, in ASCII (other characters are `\u` escapes). Allowed results
  carry `root` and `rel`.
* Exit status: 0 if at least one path was checked and every path is allowed, 1 if any is denied or
  rejected, and 2 for a usage error, including no paths at all.
* Input that is not UTF-8 is rejected with reason `encoding`, instead of being checked as a
  different string. See `Main.lean`.

From Lean, depend on this package. Build the policy with `PathFence.Policy.make`, which refuses
non-canonical roots, then call `Policy.checkString` and `Policy.allowedUnder`. Policies whose roots
contain invalid segments are not checked for you: such a deny root would deny nothing.

### Opening an allowed path

Open `rel` relative to a directory handle for `root`, refusing symlinks and any escape at open
time. On Linux:

```c
int rootfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
struct open_how how = { .flags = O_RDONLY | O_CLOEXEC,
                        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS };
int fd = syscall(SYS_openat2, rootfd, rel, &how, sizeof how);
```

Opening the returned `path` with a plain `open()` follows symlinks and defeats the check.

Go's `os.Root` (`os.OpenRoot(root)`, then `Root.Open(rel)`) and Rust's `cap_std::fs::Dir` stop
escapes from `root`. They still follow symlinks that stay inside it, so they do **not** enforce deny
roots. With `--deny /w/.git`, a link `/w/cfg -> .git` makes `cfg/config` an allowed path that opens
`/w/.git/config`. Where deny roots matter, refuse symlinks (`RESOLVE_NO_SYMLINKS`, or `O_NOFOLLOW` on
every component), or make sure nobody can create symlinks inside the roots.

## What it does not cover

PathFence decides on the string. Between that decision and the file access, the file system can
disagree:

* **Symbolic links.** `/w/link/secret` is "within" `/w` even if `link` points to `/etc`. Agents can
  plant symlinks themselves, in cloned repositories, extracted archives or through shell tools.
* **Absolute inputs are rewritten, not refused.** `/w/link/../x` becomes `/w/x`, while the kernel
  would follow `link` first and reach a different file.
* **Races.** A directory can be replaced by a symlink after the check (TOCTOU). Only resolving at
  open time, relative to a directory handle, closes this.
* **Hard links, bind mounts, mount points and `/proc/self/fd`.** These and similar aliases are not
  seen. To stay on one file system, add `RESOLVE_NO_XDEV` when opening.
* **What the file is.** FIFOs and device files inside a root are allowed like any other name.
* **What the caller does.** The policy covers paths only. Read, write and create are not
  distinguished.
* **Case-insensitive or normalising file systems** (macOS, Windows). `/W` and `/w`, or the NFC and
  NFD forms of a name, are different strings to PathFence but may be the same file.
* **Where the kernel disagrees.** Some inputs fail when the kernel opens them as written, but
  PathFence normalises them lexically and allows them:
  * `file/..`, `file/` and `file/.` give `ENOTDIR` from the kernel when `file` is not a directory;
  * `missing/../d` gives `ENOENT`.

  Their `rel` (`.`, `file` and `d`) opens fine. Nothing escapes the root, but the file opened can
  differ from the one the original input would have reached, or the input would have failed
  entirely.
* **Windows paths.** No drive letters, UNC paths or `\` separators. POSIX only.
* **Bytes that are not UTF-8.** The library works on Unicode text and the CLI rejects such input, so
  POSIX names that are not UTF-8 cannot be allowed.
* **Leading `//`.** POSIX lets an implementation give it a special meaning; PathFence treats it as
  `/`.

Use PathFence as the policy layer, to decide which paths an agent may ask for with a precise
answer, and use a confined open for the actual access.

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

Copyright 2026 the PathFence authors. Apache-2.0; see [LICENSE](LICENSE).

Written with AI assistance (Claude Code, Claude Opus 5.5). It was reviewed in separate AI-assisted
review sessions (also Claude Opus 5.5), not yet by a human expert.
