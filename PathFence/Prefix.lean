import PathFence.Resolve

/-!
# Containment as a string check

Containment of paths is the segment-wise prefix order: `r <+: p`. `within_iff_render` states the
same thing on the printed strings: `p` is within a non-root `r` exactly when `render p` equals
`render r` or starts with `render r` followed by `/`.

The `/` matters. Checking only that `render p` starts with `render r` is the "colliding prefix"
mistake: it treats `/tmp/allowed_dir_malicious` as inside `/tmp/allowed_dir` (see `Examples.lean`).
-/

namespace PathFence

theorem join_append (x y : List Seg) (hx : x ≠ []) (hy : y ≠ []) : join (x ++ y) = join x ++ '/' :: join y := by
  induction x with
  | nil => exact absurd rfl hx
  | cons a t ih =>
    cases t with
    | nil => rw [List.singleton_append]; exact join_cons_of_ne_nil a hy
    | cons b rest =>
      simp only [List.cons_append, join]
      rw [← List.cons_append, ih (by simp)]
      simp

theorem split_join_append_slash (r : List Seg) (u : List Char) (hr : r ≠ []) (hs : ∀ x ∈ r, '/' ∉ x) :
    split (join r ++ '/' :: u) = r ++ split u := by
  induction r with
  | nil => exact absurd rfl hr
  | cons x t ih =>
    have hx := hs x (by simp)
    cases t with
    | nil =>
      simp only [join, split, List.cons_append, List.nil_append]
      rw [splitAux_append_of_noSlash x _ [] hx]
      simp [splitAux]
    | cons y rest =>
      have ih' := ih (by simp) (fun z hz => hs z (by simp [hz]))
      simp only [join, split] at ih' ⊢
      rw [List.append_assoc, List.cons_append, splitAux_append_of_noSlash x _ [] hx]
      simp [splitAux, ih']

theorem join_ne_nil (r : List Seg) (hr : r ≠ []) (hv : ∀ x ∈ r, Seg.Valid x) : join r ≠ [] := by
  cases r with
  | nil => exact absurd rfl hr
  | cons x t =>
    have hx := (hv x (by simp)).1
    cases t with
    | nil => simpa [join] using hx
    | cons y rest => simp [join, hx]

/-- `p` is within a non-root `r` exactly when the printed `p` equals the printed `r`, or starts with
the printed `r` followed by `/`. -/
theorem within_iff_render (r p : Path) (hr : r ≠ []) (hrv : ∀ x ∈ r, Seg.Valid x) (hpv : ∀ x ∈ p, Seg.Valid x) :
    r <+: p ↔ render p = render r ∨ (render r ++ ['/']) <+: render p := by
  have hrs : ∀ x ∈ r, '/' ∉ x := fun x hx => (hrv x hx).2.2.2.1
  have hps : ∀ x ∈ p, '/' ∉ x := fun x hx => (hpv x hx).2.2.2.1
  have hrr : render r = '/' :: join r := by simp [render, hr]
  constructor
  · rintro ⟨t, rfl⟩
    by_cases ht : t = []
    · subst ht; simp
    · right
      have hp : r ++ t ≠ [] := by simp [hr]
      rw [show render (r ++ t) = '/' :: join (r ++ t) by simp [render, hp], hrr, join_append r t hr ht]
      exact ⟨join t, by simp⟩
  · rintro (h | h)
    · by_cases hp : p = []
      · subst hp
        rw [hrr] at h
        simp only [render, if_pos, List.cons.injEq, true_and] at h
        exact absurd h.symm (join_ne_nil r hr hrv)
      · rw [show render p = '/' :: join p by simp [render, hp], hrr] at h
        have hj : join p = join r := by injection h
        have : p = r := by
          rw [← split_join p hp hps, ← split_join r hr hrs, hj]
        rw [this]
        exact List.prefix_refl r
    · by_cases hp : p = []
      · subst hp
        rw [hrr] at h
        have := h.length_le
        simp [render] at this
      · rw [show render p = '/' :: join p by simp [render, hp], hrr] at h
        obtain ⟨u, hu⟩ := h
        have hu' : join p = join r ++ '/' :: u := by
          simp only [List.cons_append, List.append_assoc, List.cons.injEq, true_and] at hu
          simpa using hu.symm
        have : p = r ++ split u := by
          rw [← split_join p hp hps, hu', split_join_append_slash r u hr hrs]
        exact ⟨split u, this.symm⟩

end PathFence
