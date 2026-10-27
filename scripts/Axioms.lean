import PathFence
import Lean

/-! Print every declaration of the PathFence modules (private ones included) with the axioms it
depends on, one `AXIOMS <kind> <name>: [<axioms>]` line each. `scripts/audit.sh` checks the list, so
it does not have to be kept by hand. -/

open Lean Elab Command

run_cmd do
  let env ← getEnv
  let mut lines : Array String := #[]
  for (name, ci) in env.constants.map₁.toList do
    let some idx := env.getModuleIdxFor? name | continue
    let some m := env.header.moduleNames[idx.toNat]? | continue
    unless (`PathFence).isPrefixOf m do continue
    let kind := match ci with
      | .thmInfo _ => "theorem"
      | .axiomInfo _ => "axiom"
      | .opaqueInfo _ => "opaque"
      | _ => "def"
    let axs ← collectAxioms name
    lines := lines.push s!"AXIOMS {kind} {name}: {axs.toList}"
  for l in lines.qsort (· < ·) do
    IO.println l
