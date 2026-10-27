import PathFence
import Lean

/-! Facts about the PathFence modules for `scripts/audit.sh`, one line each:

* `AXIOMS <kind> <name>: [<axioms>]` for every declaration (private ones included), with the axioms
  it depends on. The list is generated, so it does not have to be kept by hand.
* `IMPORT <module> <imported>` for every import of a PathFence module. Only `Init` and PathFence
  modules may be imported, so no other code can reach the library.
* `IMPLBY <name> <impl>` and `EXTERN <name>` for every PathFence declaration whose compiled code is
  replaced (`implemented_by`, `extern`). There must be none: the binary must run the code the
  theorems are about.
* `STATEMENT <name> : <type>` for every theorem, pretty-printed on one line, so that the published
  statements can be compared with `scripts/statements.expected`.
* `DEPHASH <name> <hash>` for every theorem: a hash of its statement and of every PathFence
  definition the statement depends on, directly or indirectly (types and bodies, not proofs). A
  change to `Policy.Valid`, `resolve` or anything else a statement refers to changes the hash, even
  when the printed statement stays the same. -/

open Lean Elab Command

/-- The PathFence constants reachable from `todo` through types and definition bodies (theorem
proofs are not followed). -/
partial def depClosure (env : Environment) (isOurs : Name → Bool) (todo : List Name) (seen : NameSet) : NameSet :=
  match todo with
  | [] => seen
  | n :: rest =>
    if seen.contains n then depClosure env isOurs rest seen else
    let ours := (env.getModuleIdxFor? n).bind (fun i => env.header.moduleNames[i.toNat]?) |>.map isOurs
    if ours != some true then depClosure env isOurs rest seen else
    match env.find? n with
    | none => depClosure env isOurs rest seen
    | some ci =>
      let body := match ci with
        | .thmInfo _ => []
        | _ => (ci.value?.map Expr.getUsedConstants).getD #[] |>.toList
      depClosure env isOurs (ci.type.getUsedConstants.toList ++ body ++ rest) (seen.insert n)

/-- A hash of a theorem's statement and of the definitions it depends on. -/
def depHash (env : Environment) (isOurs : Name → Bool) (ci : ConstantInfo) : UInt64 :=
  let deps := depClosure env isOurs ci.type.getUsedConstants.toList {}
  let names := deps.toList.toArray.qsort (fun a b => a.toString < b.toString)
  names.foldl (init := hash ci.type) fun h n =>
    match env.find? n with
    | some d => mixHash h (mixHash (hash n) (mixHash (hash d.type) (hash (d.value?.getD (.sort .zero)))))
    | none => h

run_cmd do
  let env ← getEnv
  let mut lines : Array String := #[]
  let isOurs (m : Name) : Bool := (`PathFence).isPrefixOf m
  for h : i in [0:env.header.moduleNames.size] do
    let m := env.header.moduleNames[i]
    unless isOurs m do continue
    for imp in (env.header.moduleData[i]?.map (·.imports)).getD #[] do
      lines := lines.push s!"IMPORT {m} {imp.module}"
  for (name, ci) in env.constants.map₁.toList do
    let some idx := env.getModuleIdxFor? name | continue
    let some m := env.header.moduleNames[idx.toNat]? | continue
    unless isOurs m do continue
    let kind := match ci with
      | .thmInfo _ => "theorem"
      | .axiomInfo _ => "axiom"
      | .opaqueInfo _ => "opaque"
      | _ => "def"
    let axs ← collectAxioms name
    lines := lines.push s!"AXIOMS {kind} {name}: {axs.toList}"
    if kind == "theorem" then
      let fmt ← liftTermElabM (Meta.ppExpr ci.type)
      let raw := (fmt.pretty 100000).replace "\n" " "
      let stmt := " ".intercalate ((raw.splitOn " ").filter (· ≠ ""))
      lines := lines.push s!"STATEMENT {name} : {stmt}"
      lines := lines.push s!"DEPHASH {name} {depHash env isOurs ci}"
    if let some impl := Compiler.getImplementedBy? env name then
      lines := lines.push s!"IMPLBY {name} {impl}"
    if isExtern env name then
      lines := lines.push s!"EXTERN {name}"
  for l in lines.qsort (· < ·) do
    IO.println l
