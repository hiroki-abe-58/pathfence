import PathFence

/-! Print the axioms behind each published theorem. `scripts/audit.sh` checks that the only ones
are Lean's standard `propext`, `Classical.choice` and `Quot.sound`. -/

open PathFence

#print axioms join_split
#print axioms split_join
#print axioms walkB_spec
#print axioms walkB_keeps_base
#print axioms walkL_of_valid
#print axioms resolve_nul
#print axioms resolve_abs
#print axioms resolve_rel_spec
#print axioms resolve_rel_within
#print axioms resolve_valid
#print axioms resolve_render
#print axioms within_iff_render
#print axioms check_allow_iff
#print axioms check_allow_rel_within_base
#print axioms check_allow_of_add_deny
#print axioms check_allow_add_allow
#print axioms confine_allow_iff
#print axioms parseRoot_valid
