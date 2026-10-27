import PathFence.Resolve

/-!
# Policies: allowed and denied roots

A policy names the base directory that relative paths start from, the roots that may be accessed,
and roots inside them that may not. `Policy.check` resolves the requested path and allows it exactly
when it lies within some allowed root and within no denied root (`check_allow_iff`). "Within" is the
segment-wise prefix order `<+:` on paths: `/tmp/a` is within `/tmp/a` and `/tmp/a/b`, never
`/tmp/ab`.

Adding a denied root never allows more (`check_allow_of_add_deny`), and adding an allowed root never
allows less (`check_allow_add_allow`).
-/

namespace PathFence

/-- An access policy. -/
structure Policy where
  /-- The directory that relative paths start from. -/
  base : Path
  /-- Roots that may be accessed. -/
  allow : List Path
  /-- Roots that may not be accessed, even inside an allowed root. -/
  deny : List Path

/-- The decision for one requested path. -/
inductive Decision where
  /-- Allowed; the resolved path. -/
  | allow (p : Path)
  /-- Resolved to `p`, but `p` is outside every allowed root or inside a denied one. -/
  | deny (p : Path)
  /-- Rejected before any root was consulted. -/
  | reject (r : Reason)
  deriving DecidableEq, Repr

/-- Check the requested path `s` against the policy. -/
def Policy.check (pol : Policy) (s : List Char) : Decision :=
  match resolve pol.base s with
  | .error r => .reject r
  | .ok p =>
    if pol.allow.any (fun a => a.isPrefixOf p) && !pol.deny.any (fun d => d.isPrefixOf p) then .allow p
    else .deny p

/-- `check` allows `p` exactly when `s` resolves to `p`, `p` is within some allowed root, and `p` is
within no denied root. -/
theorem check_allow_iff (pol : Policy) (s : List Char) (p : Path) :
    pol.check s = .allow p ↔
      resolve pol.base s = .ok p ∧ (∃ a ∈ pol.allow, a <+: p) ∧ ∀ d ∈ pol.deny, ¬ d <+: p := by
  unfold Policy.check
  cases hr : resolve pol.base s with
  | error r => simp
  | ok q =>
    simp only [Except.ok.injEq]
    by_cases hq : pol.allow.any (fun a => a.isPrefixOf q) && !pol.deny.any (fun d => d.isPrefixOf q)
    · rw [if_pos hq]
      simp only [Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, List.any_eq_true,
        List.isPrefixOf_iff_prefix, List.any_eq_false] at hq
      simp only [Decision.allow.injEq]
      constructor
      · rintro rfl
        exact ⟨rfl, hq.1, fun d hd h => hq.2 d hd (by simpa [List.isPrefixOf_iff_prefix] using h)⟩
      · rintro ⟨rfl, -, -⟩; rfl
    · rw [if_neg hq]
      simp only [reduceCtorEq, false_iff]
      rintro ⟨rfl, ⟨a, ha, hap⟩, hd⟩
      apply hq
      simp only [Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, List.any_eq_true,
        List.isPrefixOf_iff_prefix, List.any_eq_false]
      exact ⟨⟨a, ha, hap⟩, fun d hd' h => hd d hd' (by simpa [List.isPrefixOf_iff_prefix] using h)⟩

/-- An allowed relative path is within the base directory. -/
theorem check_allow_rel_within_base (pol : Policy) (s : List Char) (p : Path) (ha : isAbs s = false)
    (h : pol.check s = .allow p) : pol.base <+: p :=
  resolve_rel_within pol.base s p ha ((check_allow_iff pol s p).mp h).1

/-- Adding a denied root never allows more. -/
theorem check_allow_of_add_deny (pol : Policy) (d : Path) (s : List Char) (p : Path)
    (h : ({ pol with deny := d :: pol.deny } : Policy).check s = .allow p) : pol.check s = .allow p := by
  rw [check_allow_iff] at h ⊢
  exact ⟨h.1, h.2.1, fun d' hd' => h.2.2 d' (by simp [hd'])⟩

/-- Adding an allowed root never allows less. -/
theorem check_allow_add_allow (pol : Policy) (a : Path) (s : List Char) (p : Path)
    (h : pol.check s = .allow p) : ({ pol with allow := a :: pol.allow } : Policy).check s = .allow p := by
  rw [check_allow_iff] at h ⊢
  obtain ⟨h1, ⟨a', ha', hp⟩, h3⟩ := h
  exact ⟨h1, ⟨a', by simp [ha'], hp⟩, h3⟩

/-- The common case: one root that is both the base and the only allowed root. -/
def confine (root : Path) (s : List Char) : Decision :=
  ({ base := root, allow := [root], deny := [] } : Policy).check s

theorem confine_allow_iff (root : Path) (s : List Char) (p : Path) :
    confine root s = .allow p ↔ resolve root s = .ok p ∧ root <+: p := by
  unfold confine
  rw [check_allow_iff]
  simp

end PathFence
