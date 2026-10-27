/-!
# Splitting a path at `/`

Paths are handled as lists of characters. `split` cuts a list at every `'/'`; `join` puts the pieces
back with `'/'` between them. The two are inverse to each other (`join_split`, `split_join`), and no
piece contains a `'/'` (`split_noSlash`), so splitting loses nothing and invents nothing.
-/

namespace PathFence

/-- A path segment, or one piece of a path split at `/`. -/
abbrev Seg := List Char

/-- `splitAux l acc` splits `l`, where `acc` holds the characters of the current piece so far, in
reverse. -/
def splitAux : List Char → List Char → List Seg
  | [], acc => [acc.reverse]
  | c :: cs, acc => if c = '/' then acc.reverse :: splitAux cs [] else splitAux cs (c :: acc)

/-- Split at every `'/'`: `"a/b"` gives `["a", "b"]`, `"/a"` gives `["", "a"]`, `""` gives `[""]`.
The result is never empty. -/
def split (l : List Char) : List Seg := splitAux l []

/-- Join pieces with `'/'` between them (the inverse of `split`). -/
def join : List Seg → List Char
  | [] => []
  | [x] => x
  | x :: y :: rest => x ++ '/' :: join (y :: rest)

theorem splitAux_ne_nil (l acc : List Char) : splitAux l acc ≠ [] := by
  induction l generalizing acc with
  | nil => simp [splitAux]
  | cons c cs ih =>
    unfold splitAux
    split <;> simp_all

theorem split_ne_nil (l : List Char) : split l ≠ [] := splitAux_ne_nil l []

theorem join_cons_of_ne_nil (x : Seg) {t : List Seg} (h : t ≠ []) : join (x :: t) = x ++ '/' :: join t := by
  cases t with
  | nil => exact absurd rfl h
  | cons y rest => rfl

theorem join_splitAux (l acc : List Char) : join (splitAux l acc) = acc.reverse ++ l := by
  induction l generalizing acc with
  | nil => simp [splitAux, join]
  | cons c cs ih =>
    unfold splitAux
    split
    · rename_i hc
      subst hc
      rw [join_cons_of_ne_nil _ (splitAux_ne_nil cs []), ih]
      simp
    · rw [ih]
      simp

/-- Joining the pieces gives back the original list. -/
theorem join_split (l : List Char) : join (split l) = l := by
  simp [split, join_splitAux]

theorem splitAux_noSlash (l acc : List Char) (hacc : '/' ∉ acc) :
    ∀ p ∈ splitAux l acc, '/' ∉ p := by
  induction l generalizing acc with
  | nil => simpa [splitAux] using hacc
  | cons c cs ih =>
    unfold splitAux
    split
    · intro p hp
      simp only [List.mem_cons] at hp
      rcases hp with rfl | hp
      · simpa using hacc
      · exact ih [] (by simp) p hp
    · rename_i hc
      exact ih (c :: acc) (by simp_all [eq_comm])

/-- No piece of a split contains `'/'`. -/
theorem split_noSlash (l : List Char) : ∀ p ∈ split l, '/' ∉ p :=
  splitAux_noSlash l [] (by simp)

theorem splitAux_append_of_noSlash (x rest acc : List Char) (hx : '/' ∉ x) :
    splitAux (x ++ rest) acc = splitAux rest (x.reverse ++ acc) := by
  induction x generalizing acc with
  | nil => simp
  | cons c cs ih =>
    have hc : c ≠ '/' := by intro h; exact hx (by simp [h])
    have hcs : '/' ∉ cs := by intro h; exact hx (by simp [h])
    simp [List.cons_append, splitAux, hc, ih (c :: acc) hcs]

/-- Splitting a join gives back the pieces, when no piece contains `'/'`. -/
theorem split_join (ps : List Seg) (hne : ps ≠ []) (hps : ∀ p ∈ ps, '/' ∉ p) : split (join ps) = ps := by
  induction ps with
  | nil => exact absurd rfl hne
  | cons x t ih =>
    cases t with
    | nil =>
      have hx := hps x (by simp)
      simp only [join, split]
      rw [← List.append_nil x, splitAux_append_of_noSlash x [] [] hx]
      simp [splitAux]
    | cons y rest =>
      have hx := hps x (by simp)
      have ht : ∀ p ∈ y :: rest, '/' ∉ p := fun p hp => hps p (by simp [hp])
      have ih' := ih (by simp) ht
      simp only [join, split] at ih' ⊢
      rw [splitAux_append_of_noSlash x _ [] hx]
      simp [splitAux, ih']

end PathFence
