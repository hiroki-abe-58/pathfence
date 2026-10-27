import PathFence.Policy

/-!
# String-level API

The proofs work on lists of characters. These wrappers are the entry points for Lean callers and the
command-line tool: they convert with `String.toList` / `String.ofList` and call the proven functions.

Roots are taken literally. `parseRoot` accepts only the canonical form of a directory (`/`, or `/`
followed by valid segments separated by single slashes) and refuses anything else instead of
normalising it, so that `/w/..` or `/w/` never silently becomes a different root
(`parseRoot_render`). Build policies with `Policy.make`: a root with an invalid segment would never
contain a resolved path, so as a denied root it would deny nothing (`Policy.make_valid`).
-/

namespace PathFence

/-- Parse a root directory written canonically: `/`, or `/` followed by valid segments separated by
single `/`, with no `.`, `..`, empty segment, trailing `/` or NUL. -/
def parseRoot (s : String) : Option Path :=
  match s.toList with
  | ['/'] => some []
  | '/' :: rest => if (split rest).all (fun x => decide (Seg.Valid x)) then some (split rest) else none
  | _ => none

/-- Print a path. -/
def Path.toString (p : Path) : String := String.ofList (render p)

/-- Check a requested path against a policy. -/
def Policy.checkString (pol : Policy) (s : String) : Decision := pol.check s.toList

/-- Confine a requested path to one root. -/
def confineString (root : Path) (s : String) : Decision := confine root s.toList

/-- A parsed root consists of valid segments. -/
theorem parseRoot_valid (s : String) (p : Path) (h : parseRoot s = some p) : ∀ x ∈ p, Seg.Valid x := by
  unfold parseRoot at h
  split at h
  · injection h with h; subst h; simp
  · split at h
    · rename_i hall
      injection h with h; subst h
      intro x hx
      exact of_decide_eq_true (List.all_eq_true.mp hall x hx)
    · exact absurd h (by simp)
  · exact absurd h (by simp)

/-- A root is exactly the directory its string names: printing it gives the string back. -/
theorem parseRoot_render (s : String) (p : Path) (h : parseRoot s = some p) : render p = s.toList := by
  unfold parseRoot at h
  split at h
  · rename_i hs
    injection h with h; subst h
    simp [render, hs]
  · rename_i rest _ hs
    split at h
    · injection h with h; subst h
      simp [render, hs, split_ne_nil rest, join_split]
    · exact absurd h (by simp)
  · exact absurd h (by simp)

/-- Parse a list of roots; `none` if any one is not canonical. -/
def parseRoots : List String → Option (List Path)
  | [] => some []
  | s :: ss => do
    let p ← parseRoot s
    let ps ← parseRoots ss
    pure (p :: ps)

theorem parseRoots_valid (ss : List String) (ps : List Path) (h : parseRoots ss = some ps) :
    ∀ p ∈ ps, ∀ x ∈ p, Seg.Valid x := by
  induction ss generalizing ps with
  | nil => simp [parseRoots] at h; subst h; simp
  | cons s ss ih =>
    simp only [parseRoots, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
      Option.some.injEq] at h
    obtain ⟨p, hp, qs, hqs, rfl⟩ := h
    intro q hq
    simp only [List.mem_cons] at hq
    rcases hq with rfl | hq
    · exact parseRoot_valid s q hp
    · exact ih qs hqs q hq

/-- All roots of a policy consist of valid segments. -/
def Policy.Valid (pol : Policy) : Prop :=
  (∀ x ∈ pol.base, Seg.Valid x) ∧ (∀ r ∈ pol.allow, ∀ x ∈ r, Seg.Valid x) ∧
    (∀ r ∈ pol.deny, ∀ x ∈ r, Seg.Valid x)

/-- A policy from canonical root strings; `none` if any root is not canonical. -/
def Policy.make (base : String) (allow deny : List String) : Option Policy := do
  let base ← parseRoot base
  let allow ← parseRoots allow
  let deny ← parseRoots deny
  pure { base, allow, deny }

theorem Policy.make_valid (base : String) (allow deny : List String) (pol : Policy)
    (h : Policy.make base allow deny = some pol) : pol.Valid := by
  simp only [Policy.make, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
    Option.some.injEq] at h
  obtain ⟨b, hb, a, ha, d, hd, rfl⟩ := h
  exact ⟨parseRoot_valid base b hb, parseRoots_valid allow a ha, parseRoots_valid deny d hd⟩

end PathFence
