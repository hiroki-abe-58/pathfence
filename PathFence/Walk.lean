import PathFence.Split

/-!
# Walking the pieces of a path

A *stack* is a directory as a list of segments, **deepest segment first** (the reverse of the usual
order), so that entering and leaving a directory are `cons` and `tail`.

* `walkL` is ordinary lexical normalisation: an empty piece or `.` does nothing, `..` leaves the
  current directory (at the top it stays at the top, as in POSIX), anything else enters a directory.
* `walkB k` is the *beneath* walk: the same, except that `..` taken at depth `k` or less fails. With
  the starting directory at depth `k`, a path may never leave it, not even temporarily. This is the
  rule of Linux `openat2(RESOLVE_BENEATH)` for `..`.

`walkB_spec` characterises `walkB` without reference to its code: it succeeds exactly when every
`..` in the path is taken strictly above depth `k` of the lexical walk, and then it returns the
lexical result. `walkB_keeps_base` shows the starting directory is never left.
-/

namespace PathFence

/-- The piece `..`. -/
abbrev dotdot : Seg := ['.', '.']

/-- One lexical step. -/
def stepL (st : List Seg) (c : Seg) : List Seg :=
  if c = [] ∨ c = ['.'] then st else if c = dotdot then st.tail else c :: st

/-- Lexical normalisation of the pieces `cs`, starting from the stack `st`. -/
def walkL (st : List Seg) : List Seg → List Seg
  | [] => st
  | c :: cs => walkL (stepL st c) cs

/-- The beneath walk: like `walkL`, but `..` at depth `k` or less fails. -/
def walkB (k : Nat) (st : List Seg) : List Seg → Option (List Seg)
  | [] => some st
  | c :: cs =>
    if c = dotdot then (if k < st.length then walkB k st.tail cs else none)
    else walkB k (stepL st c) cs

/-- Every `..` in `cs` is taken strictly above depth `k`: at the point where the lexical walk from
`st` reaches it, the stack is deeper than `k`. -/
def PopsAbove (k : Nat) (st : List Seg) (cs : List Seg) : Prop :=
  ∀ pre post, cs = pre ++ dotdot :: post → k < (walkL st pre).length

theorem walkL_append (st : List Seg) (xs ys : List Seg) : walkL st (xs ++ ys) = walkL (walkL st xs) ys := by
  induction xs generalizing st with
  | nil => rfl
  | cons c cs ih => exact ih (stepL st c)

theorem popsAbove_nil (k : Nat) (st : List Seg) : PopsAbove k st [] := by
  intro pre post h
  cases pre <;> simp at h

theorem popsAbove_cons (k : Nat) (st : List Seg) (c : Seg) (cs : List Seg) :
    PopsAbove k st (c :: cs) ↔ (c = dotdot → k < st.length) ∧ PopsAbove k (stepL st c) cs := by
  constructor
  · intro h
    refine ⟨fun hc => ?_, fun pre post hcs => ?_⟩
    · have := h [] cs (by simp [hc])
      simpa [walkL] using this
    · have := h (c :: pre) post (by simp [hcs])
      simpa [walkL] using this
  · rintro ⟨h1, h2⟩ pre post hcs
    cases pre with
    | nil =>
      simp only [List.nil_append, List.cons.injEq] at hcs
      simpa [walkL] using h1 hcs.1
    | cons d pre =>
      simp only [List.cons_append, List.cons.injEq] at hcs
      obtain ⟨rfl, hcs⟩ := hcs
      simpa [walkL] using h2 pre post hcs

/-- The beneath walk succeeds with `o` exactly when `o` is the lexical result and every `..` is taken
strictly above depth `k`. -/
theorem walkB_spec (k : Nat) (st : List Seg) (cs : List Seg) (o : List Seg) :
    walkB k st cs = some o ↔ o = walkL st cs ∧ PopsAbove k st cs := by
  induction cs generalizing st with
  | nil =>
    simp only [walkB, walkL, Option.some.injEq]
    exact ⟨fun h => ⟨h.symm, popsAbove_nil k st⟩, fun h => h.1.symm⟩
  | cons c cs ih =>
    rw [popsAbove_cons]
    have hwalk : walkL st (c :: cs) = walkL (stepL st c) cs := rfl
    by_cases hc : c = dotdot
    · have hstep : stepL st c = st.tail := by simp [stepL, hc]
      by_cases hk : k < st.length
      · have e1 : walkB k st (c :: cs) = walkB k st.tail cs := by simp [walkB, hc, hk]
        rw [e1, ih, hwalk, hstep]
        exact ⟨fun ⟨h1, h2⟩ => ⟨h1, fun _ => hk, h2⟩, fun ⟨h1, _, h2⟩ => ⟨h1, h2⟩⟩
      · have e1 : walkB k st (c :: cs) = none := by simp [walkB, hc, hk]
        rw [e1]
        exact ⟨fun h => absurd h (by simp), fun ⟨_, h, _⟩ => absurd (h hc) hk⟩
    · have e1 : walkB k st (c :: cs) = walkB k (stepL st c) cs := by simp [walkB, hc]
      rw [e1, ih, hwalk]
      exact ⟨fun ⟨h1, h2⟩ => ⟨h1, fun h => absurd h hc, h2⟩, fun ⟨h1, _, h2⟩ => ⟨h1, h2⟩⟩

/-- The beneath walk never leaves its starting directory: if the stack starts as some entries above a
fixed bottom `bot` of depth `k`, it still ends as some entries above `bot`. -/
theorem walkB_keeps_base (bot : List Seg) (cs : List Seg) :
    ∀ (e : List Seg) (o : List Seg), walkB bot.length (e ++ bot) cs = some o → ∃ e', o = e' ++ bot := by
  induction cs with
  | nil =>
    intro e o h
    simp only [walkB, Option.some.injEq] at h
    exact ⟨e, h.symm⟩
  | cons c cs ih =>
    intro e o h
    by_cases hc : c = dotdot
    · have e1 : walkB bot.length (e ++ bot) (c :: cs) =
          if bot.length < (e ++ bot).length then walkB bot.length (e ++ bot).tail cs else none := by
        simp [walkB, hc]
      rw [e1] at h
      split at h
      · rename_i hk
        cases e with
        | nil => simp at hk
        | cons x e => exact ih e o (by simpa using h)
      · exact absurd h (by simp)
    · have e1 : walkB bot.length (e ++ bot) (c :: cs) = walkB bot.length (stepL (e ++ bot) c) cs := by
        simp [walkB, hc]
      rw [e1] at h
      by_cases hs : c = [] ∨ c = ['.']
      · have : stepL (e ++ bot) c = e ++ bot := by simp [stepL, hs]
        rw [this] at h
        exact ih e o h
      · have : stepL (e ++ bot) c = c :: (e ++ bot) := by simp [stepL, hs, hc]
        rw [this] at h
        exact ih (c :: e) o (by simpa using h)

/-- A segment is valid: non-empty, neither `.` nor `..`, and without `/` or NUL. -/
def Seg.Valid (s : Seg) : Prop :=
  s ≠ [] ∧ s ≠ ['.'] ∧ s ≠ dotdot ∧ '/' ∉ s ∧ '\x00' ∉ s

instance (s : Seg) : Decidable (Seg.Valid s) := by unfold Seg.Valid; infer_instance

/-- A step keeps every segment on the stack valid, if the piece has no `/` or NUL. -/
theorem stepL_valid (st : List Seg) (c : Seg) (hst : ∀ s ∈ st, Seg.Valid s) (hc1 : '/' ∉ c) (hc2 : '\x00' ∉ c) :
    ∀ s ∈ stepL st c, Seg.Valid s := by
  unfold stepL
  split
  · exact hst
  · split
    · intro s hs; exact hst s (List.mem_of_mem_tail hs)
    · rename_i h1 h2
      intro s hs
      simp only [List.mem_cons] at hs
      rcases hs with rfl | hs
      · exact ⟨fun h => h1 (Or.inl h), fun h => h1 (Or.inr h), h2, hc1, hc2⟩
      · exact hst s hs

theorem walkL_valid (st : List Seg) (cs : List Seg) (hst : ∀ s ∈ st, Seg.Valid s)
    (hcs : ∀ c ∈ cs, '/' ∉ c ∧ '\x00' ∉ c) : ∀ s ∈ walkL st cs, Seg.Valid s := by
  induction cs generalizing st with
  | nil => exact hst
  | cons c cs ih =>
    have hc := hcs c (by simp)
    exact ih _ (stepL_valid st c hst hc.1 hc.2) (fun d hd => hcs d (by simp [hd]))

/-- Walking valid segments enters each of them in turn. -/
theorem walkL_of_valid (st : List Seg) (p : List Seg) (hp : ∀ s ∈ p, Seg.Valid s) :
    walkL st p = p.reverse ++ st := by
  induction p generalizing st with
  | nil => rfl
  | cons x p ih =>
    have hx := hp x (by simp)
    have h1 : ¬ (x = [] ∨ x = ['.']) := fun h => h.elim hx.1 hx.2.1
    simp only [walkL, stepL, h1, if_false, hx.2.2.1]
    rw [ih (x :: st) (fun s hs => hp s (by simp [hs]))]
    simp

end PathFence
