import PathFence.Walk

/-!
# Resolving a requested path

`resolve base s` turns a requested path `s` into a directory, given the base directory `base` that
relative paths start from:

* an input containing NUL is rejected (`Reason.nul`);
* an absolute input (`/…`) is normalised lexically from `/`;
* a relative input is walked from `base` with the beneath rule: it may not step above `base` with
  `..`, not even temporarily (`Reason.escapes`).

The results are paths of valid segments (`resolve_valid`). A relative input always stays beneath the
base (`resolve_rel_within`). `render` prints a path, and resolving the printed form gives the same
path back (`resolve_render`), so the string a caller passes on is exactly the path that was checked.
-/

namespace PathFence

/-- A directory as a list of segments, root first. `[]` is `/`. -/
abbrev Path := List Seg

/-- Why a requested path was rejected before any policy was consulted. -/
inductive Reason where
  /-- The input contains a NUL character. -/
  | nul
  /-- A relative input steps above the base directory with `..`. -/
  | escapes
  deriving DecidableEq, Repr

/-- Whether a requested path is absolute (starts with `/`). -/
def isAbs : List Char → Bool
  | '/' :: _ => true
  | _ => false

/-- Resolve the requested path `s` against the base directory `base`. -/
def resolve (base : Path) (s : List Char) : Except Reason Path :=
  if '\x00' ∈ s then .error .nul
  else if isAbs s then .ok (walkL [] (split s.tail)).reverse
  else match walkB base.length base.reverse (split s) with
    | some o => .ok o.reverse
    | none => .error .escapes

/-- Print a path: `/` for the root, otherwise `/` before each segment. -/
def render (p : Path) : List Char :=
  if p = [] then ['/'] else '/' :: join p

theorem resolve_nul (base : Path) (s : List Char) (h : '\x00' ∈ s) : resolve base s = .error .nul := by
  simp [resolve, h]

/-- An absolute input is normalised lexically from the root. -/
theorem resolve_abs (base : Path) (s : List Char) (h0 : '\x00' ∉ s) (ha : isAbs s = true) :
    resolve base s = .ok (walkL [] (split s.tail)).reverse := by
  simp [resolve, h0, ha]

/-- A relative input resolves to `p` exactly when `p` is its lexical walk from the base and every
`..` is taken strictly inside the base. -/
theorem resolve_rel_spec (base : Path) (s : List Char) (p : Path) (h0 : '\x00' ∉ s) (ha : isAbs s = false) :
    resolve base s = .ok p ↔
      p = (walkL base.reverse (split s)).reverse ∧ PopsAbove base.length base.reverse (split s) := by
  simp only [resolve, h0, ha, ite_false, Bool.false_eq_true]
  constructor
  · intro h
    split at h
    · rename_i o ho
      have hp : p = o.reverse := by injection h with h; exact h.symm
      rw [walkB_spec] at ho
      exact ⟨by rw [hp, ho.1], ho.2⟩
    · exact absurd h (by simp)
  · rintro ⟨hp, hpop⟩
    have ho : walkB base.length base.reverse (split s) = some (walkL base.reverse (split s)) :=
      (walkB_spec _ _ _ _).mpr ⟨rfl, hpop⟩
    rw [ho, hp]

/-- A relative input never resolves outside the base directory. -/
theorem resolve_rel_within (base : Path) (s : List Char) (p : Path) (ha : isAbs s = false)
    (h : resolve base s = .ok p) : base <+: p := by
  by_cases h0 : '\x00' ∈ s
  · simp [resolve_nul base s h0] at h
  · simp only [resolve, h0, ha, ite_false, Bool.false_eq_true] at h
    split at h
    · rename_i o ho
      have hp : p = o.reverse := by injection h with h; exact h.symm
      have := walkB_keeps_base base.reverse (split s) [] o (by simpa using ho)
      obtain ⟨e', rfl⟩ := this
      subst hp
      exact ⟨e'.reverse, by simp⟩
    · exact absurd h (by simp)

theorem mem_splitAux (l acc : List Char) (c : Seg) (x : Char) (hc : c ∈ splitAux l acc) (hx : x ∈ c) :
    x ∈ l ∨ x ∈ acc := by
  induction l generalizing acc with
  | nil =>
    simp only [splitAux, List.mem_singleton] at hc
    subst hc
    right; simpa using hx
  | cons d ds ih =>
    unfold splitAux at hc
    split at hc
    · simp only [List.mem_cons] at hc
      rcases hc with rfl | hc
      · right; simpa using hx
      · rcases ih [] hc with h | h
        · left; exact List.mem_cons_of_mem _ h
        · simp at h
    · rcases ih (d :: acc) hc with h | h
      · left; exact List.mem_cons_of_mem _ h
      · simp only [List.mem_cons] at h
        rcases h with rfl | h
        · left; exact List.mem_cons_self
        · right; exact h

/-- Every character of a piece of a split is a character of the input. -/
theorem mem_of_mem_split (l : List Char) (c : Seg) (x : Char) (hc : c ∈ split l) (hx : x ∈ c) : x ∈ l := by
  rcases mem_splitAux l [] c x hc hx with h | h
  · exact h
  · simp at h

theorem split_pieces_ok (l : List Char) (h0 : '\x00' ∉ l) : ∀ c ∈ split l, '/' ∉ c ∧ '\x00' ∉ c :=
  fun c hc => ⟨split_noSlash l c hc, fun h => h0 (mem_of_mem_split l c _ hc h)⟩

/-- Every resolved path consists of valid segments, when the base does. -/
theorem resolve_valid (base : Path) (s : List Char) (p : Path) (hb : ∀ x ∈ base, Seg.Valid x)
    (h : resolve base s = .ok p) : ∀ x ∈ p, Seg.Valid x := by
  by_cases h0 : '\x00' ∈ s
  · simp [resolve_nul base s h0] at h
  · cases ha : isAbs s
    · rw [resolve_rel_spec base s p h0 ha] at h
      rw [h.1]
      intro x hx
      exact walkL_valid base.reverse _ (fun y hy => hb y (by simpa using hy)) (split_pieces_ok s h0) x
        (by simpa using hx)
    · rw [resolve_abs base s h0 ha] at h
      injection h with h
      subst h
      have hs : '\x00' ∉ s.tail := fun hm => h0 (List.mem_of_mem_tail hm)
      intro x hx
      exact walkL_valid [] _ (by simp) (split_pieces_ok s.tail hs) x (by simpa using hx)

theorem mem_join (ps : List Seg) (x : Char) (h : x ∈ join ps) : x = '/' ∨ ∃ q ∈ ps, x ∈ q := by
  induction ps with
  | nil => simp [join] at h
  | cons q t ih =>
    cases t with
    | nil => exact Or.inr ⟨q, by simp, by simpa [join] using h⟩
    | cons y rest =>
      simp only [join, List.mem_append, List.mem_cons] at h
      rcases h with h | h | h
      · exact Or.inr ⟨q, by simp, h⟩
      · exact Or.inl h
      · rcases ih h with h | ⟨q', hq', hx⟩
        · exact Or.inl h
        · exact Or.inr ⟨q', by simp [hq'], hx⟩

/-- Resolving a printed path gives the same path back. -/
theorem resolve_render (base : Path) (p : Path) (hp : ∀ x ∈ p, Seg.Valid x) :
    resolve base (render p) = .ok p := by
  by_cases hne : p = []
  · subst hne
    rfl
  · have hrender : render p = '/' :: join p := by simp [render, hne]
    have h0 : '\x00' ∉ render p := by
      rw [hrender]
      intro hm
      simp only [List.mem_cons] at hm
      rcases hm with h | hm
      · exact absurd h (by decide)
      · rcases mem_join p _ hm with h | ⟨q, hq, hx⟩
        · exact absurd h (by decide)
        · exact (hp q hq).2.2.2.2 hx
    rw [resolve_abs base _ h0 (by rw [hrender]; rfl), hrender]
    simp only [List.tail_cons]
    rw [split_join p hne (fun q hq => (hp q hq).2.2.2.1), walkL_of_valid [] p hp]
    simp

end PathFence
