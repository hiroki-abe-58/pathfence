import PathFence.Resolve

/-!
# Policies: allowed and denied roots

A policy names the base directory that relative paths start from, the roots that may be accessed,
and roots inside them that may not. `Policy.check` resolves the requested path and allows it exactly
when it lies within some allowed root and within no denied root (`check_allow_iff`). "Within" is the
segment-wise prefix order `<+:` on paths: `/tmp/a` and `/tmp/a/b` are within `/tmp/a`; `/tmp/ab` is
not.

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
    · rw [ite_eq_left hq]
      simp only [Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, List.any_eq_true,
        List.isPrefixOf_iff_prefix, List.any_eq_false] at hq
      simp only [Decision.allow.injEq]
      constructor
      · rintro rfl
        exact ⟨rfl, hq.1, fun d hd h => hq.2 d hd (by simpa [List.isPrefixOf_iff_prefix] using h)⟩
      · rintro ⟨rfl, -, -⟩; rfl
    · rw [ite_eq_right hq]
      simp only [reduceCtorEq, false_iff]
      rintro ⟨rfl, ⟨a, ha, hap⟩, hd⟩
      apply hq
      simp only [Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true, List.any_eq_true,
        List.isPrefixOf_iff_prefix, List.any_eq_false]
      exact ⟨⟨a, ha, hap⟩, fun d hd' h => hd d hd' (by simpa [List.isPrefixOf_iff_prefix] using h)⟩

/-- `check` rejects exactly when `resolve` does, for the same reason. -/
theorem check_reject_iff (pol : Policy) (s : List Char) (r : Reason) :
    pol.check s = .reject r ↔ resolve pol.base s = .error r := by
  unfold Policy.check
  cases resolve pol.base s with
  | error e => simp
  | ok q => simp only [reduceCtorEq, iff_false]; split <;> simp

theorem check_of_resolve_ok (pol : Policy) (s : List Char) (p : Path) (hr : resolve pol.base s = .ok p) :
    pol.check s = .allow p ∨ pol.check s = .deny p := by
  unfold Policy.check
  rw [hr]
  simp only
  split <;> simp

/-- `check` denies `p` exactly when `s` resolves to `p` and `p` is not allowed. -/
theorem check_deny_iff (pol : Policy) (s : List Char) (p : Path) :
    pol.check s = .deny p ↔
      resolve pol.base s = .ok p ∧ ¬ ((∃ a ∈ pol.allow, a <+: p) ∧ ∀ d ∈ pol.deny, ¬ d <+: p) := by
  constructor
  · intro h
    cases hr : resolve pol.base s with
    | error e => simp [Policy.check, hr] at h
    | ok q =>
      have hq : q = p := by
        rcases check_of_resolve_ok pol s q hr with h' | h' <;> rw [h'] at h <;> simp_all
      subst hq
      refine ⟨rfl, fun hall => ?_⟩
      rw [(check_allow_iff pol s q).mpr ⟨hr, hall⟩] at h
      simp at h
  · rintro ⟨hr, hn⟩
    rcases check_of_resolve_ok pol s p hr with h | h
    · exact absurd ((check_allow_iff pol s p).mp h).2 hn
    · exact h

/-- The first allowed root that `p` is within, and the rest of `p` below it. A caller can open the
rest relative to that root with a confined open such as `openat2(RESOLVE_BENEATH)`. -/
def Policy.allowedUnder (pol : Policy) (p : Path) : Option (Path × Path) :=
  (pol.allow.find? fun a => a.isPrefixOf p).map fun a => (a, p.drop a.length)

/-- `allowedUnder` names an allowed root, and the root followed by the rest is the path. -/
theorem allowedUnder_spec (pol : Policy) (p r rel : Path) (h : pol.allowedUnder p = some (r, rel)) :
    r ∈ pol.allow ∧ r ++ rel = p := by
  simp only [Policy.allowedUnder, Option.map_eq_some_iff, Prod.mk.injEq] at h
  obtain ⟨a, hfind, rfl, rfl⟩ := h
  have hpre : a <+: p := by
    have := List.find?_some hfind
    simpa [List.isPrefixOf_iff_prefix] using this
  refine ⟨List.mem_of_find?_eq_some hfind, ?_⟩
  obtain ⟨t, rfl⟩ := hpre
  simp

/-- Every allowed path has a root to open it under. -/
theorem allowedUnder_of_allow (pol : Policy) (s : List Char) (p : Path) (h : pol.check s = .allow p) :
    ∃ r rel, pol.allowedUnder p = some (r, rel) := by
  obtain ⟨-, ⟨a, ha, hap⟩, -⟩ := (check_allow_iff pol s p).mp h
  have hsome : (pol.allow.find? fun a => a.isPrefixOf p).isSome := by
    rw [List.find?_isSome]
    exact ⟨a, ha, List.isPrefixOf_iff_prefix.mpr hap⟩
  obtain ⟨r, hr⟩ := Option.isSome_iff_exists.mp hsome
  exact ⟨r, p.drop r.length, by simp [Policy.allowedUnder, hr]⟩

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
