import PathFence.Policy

/-!
# String-level API

The proofs work on lists of characters. These wrappers are the entry points for Lean callers and the
command-line tool: they convert with `String.toList` / `String.ofList` and call the proven functions.
-/

namespace PathFence

/-- Parse a root directory: it must be absolute and contain no NUL; it is normalised lexically. -/
def parseRoot (s : String) : Option Path :=
  let l := s.toList
  if '\x00' ∈ l then none
  else if isAbs l then some (walkL [] (split l.tail)).reverse
  else none

/-- Print a path. -/
def Path.toString (p : Path) : String := String.ofList (render p)

/-- Check a requested path against a policy. -/
def Policy.checkString (pol : Policy) (s : String) : Decision := pol.check s.toList

/-- Confine a requested path to one root. -/
def confineString (root : Path) (s : String) : Decision := confine root s.toList

/-- A parsed root consists of valid segments. -/
theorem parseRoot_valid (s : String) (p : Path) (h : parseRoot s = some p) : ∀ x ∈ p, Seg.Valid x := by
  unfold parseRoot at h
  simp only at h
  split at h
  · exact absurd h (by simp)
  · rename_i h0
    split at h
    · rename_i ha
      have hr : resolve [] s.toList = .ok p := by
        rw [resolve_abs [] _ h0 ha]
        injection h with h
        rw [h]
      exact resolve_valid [] s.toList p (by simp) hr
    · exact absurd h (by simp)

end PathFence
