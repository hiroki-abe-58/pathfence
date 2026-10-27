import PathFence.Api
import PathFence.Prefix

/-!
# Examples, checked at build time

Each `#guard` runs the proven functions on a concrete input when the library is built. The first
groups follow published bugs in path-confinement checks (CWE-22):

* CVE-2025-54794 and CVE-2025-53110: a check of the form "the path starts with the root string"
  accepted a sibling directory whose name starts with the root's name.
* CVE-2025-22873 (Go `os.Root`): a path ending in `../` reached the parent of the root.

They show what PathFence decides for those inputs. They do not reproduce the original programs.
-/

namespace PathFence.Examples
open PathFence

/-- A root from a string (examples only). A string that is not a canonical root gives `[[]]`, which
is not a valid path and contains no resolved path, so a typo makes the examples fail instead of
silently meaning `/`. -/
def root (s : String) : Path := (parseRoot s).getD [[]]

def check1 (r s : String) : Decision := confineString (root r) s

-- A sibling whose name starts with the root's name is outside the root …
#guard check1 "/tmp/allowed_dir" "/tmp/allowed_dir_malicious/secret" = .deny (root "/tmp/allowed_dir_malicious/secret")
-- … although a plain string-prefix test accepts it.
#guard "/tmp/allowed_dir".toList.isPrefixOf "/tmp/allowed_dir_malicious/secret".toList = true
-- The root itself and paths below it are inside.
#guard check1 "/tmp/allowed_dir" "/tmp/allowed_dir" = .allow (root "/tmp/allowed_dir")
#guard check1 "/tmp/allowed_dir" "/tmp/allowed_dir/" = .allow (root "/tmp/allowed_dir")
#guard check1 "/tmp/allowed_dir" "/tmp/allowed_dir/x" = .allow (root "/tmp/allowed_dir/x")

-- A trailing `../` does not reach the parent of the root.
#guard check1 "/w" "../" = .reject .escapes
#guard check1 "/w" ".." = .reject .escapes
#guard check1 "/w" "a/../" = .allow (root "/w")
#guard check1 "/w" "a/../.." = .reject .escapes

-- Relative paths may not step above the root, not even temporarily.
#guard check1 "/w" "../etc/passwd" = .reject .escapes
#guard check1 "/w" "a/../../w/b" = .reject .escapes
#guard check1 "/w" "a/b/../../c" = .allow (root "/w/c")

-- Absolute paths are normalised lexically, then checked.
#guard check1 "/w" "/w/../etc/passwd" = .deny (root "/etc/passwd")
#guard check1 "/w" "/w/x/../y" = .allow (root "/w/y")
#guard check1 "/w" "//w///x/./y" = .allow (root "/w/x/y")
#guard check1 "/w" "/../w/x" = .allow (root "/w/x")

-- Empty pieces and `.` change nothing; an empty input and NUL are always rejected.
#guard check1 "/w" "" = .reject .empty
#guard check1 "/w" "." = .allow (root "/w")
#guard check1 "/w" "./a//b/" = .allow (root "/w/a/b")
#guard check1 "/w" "a\x00b" = .reject .nul

-- Backslashes and percent signs are ordinary characters in POSIX names.
#guard check1 "/w" "..\\..\\etc" = .allow (root "/w/..\\..\\etc")
#guard check1 "/w" "%2e%2e/x" = .allow (root "/w/%2e%2e/x")

-- A workspace whose `.git` directory is denied.
def gitPolicy : Policy := { base := root "/w", allow := [root "/w"], deny := [root "/w/.git"] }

#guard gitPolicy.checkString "src/main.rs" = .allow (root "/w/src/main.rs")
#guard gitPolicy.checkString ".git/config" = .deny (root "/w/.git/config")
#guard gitPolicy.checkString "src/../.git/hooks/pre-commit" = .deny (root "/w/.git/hooks/pre-commit")
#guard gitPolicy.checkString ".gitignore" = .allow (root "/w/.gitignore")
#guard gitPolicy.checkString "/w/.git" = .deny (root "/w/.git")

-- Several allowed roots, with the base separate from them.
def twoRoots : Policy :=
  { base := root "/home/u/project", allow := [root "/home/u/project", root "/tmp/scratch"], deny := [] }

#guard twoRoots.checkString "/tmp/scratch/out.txt" = .allow (root "/tmp/scratch/out.txt")
#guard twoRoots.checkString "/tmp/scratchpad/out.txt" = .deny (root "/tmp/scratchpad/out.txt")
#guard twoRoots.checkString "../other/file" = .reject .escapes

-- An allowed path, split into the root that allows it and the rest below that root.
#guard twoRoots.allowedUnder (root "/tmp/scratch/out/x") = some (root "/tmp/scratch", [['o','u','t'], ['x']])
#guard twoRoots.allowedUnder (root "/home/u/project") = some (root "/home/u/project", [])
#guard twoRoots.allowedUnder (root "/tmp/scratchpad") = none

-- Roots are taken literally: only the canonical form is accepted.
#guard parseRoot "/" = some []
#guard (root "/w/a b/c").toString = "/w/a b/c"
#guard parseRoot "/w/.." = none
#guard parseRoot "/w/" = none
#guard parseRoot "//w" = none
#guard parseRoot "/w/./x" = none
#guard parseRoot "w" = none
#guard parseRoot "" = none

end PathFence.Examples
