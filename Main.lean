import PathFence

/-!
# `pathfence` command-line tool

    pathfence check --allow DIR [--allow DIR …] [--deny DIR …] [--base DIR] [--stdin] [--] PATH …

Each requested path is checked with the proven `PathFence.Policy.check`, and one JSON object is
printed per path:

    {"input":"a/../b","decision":"allow","path":"/w/b"}
    {"input":"../x","decision":"reject","reason":"escapes"}

The base directory for relative paths defaults to the first `--allow` root. With `--stdin`, paths are
read one per line. The exit status is 0 when every path is allowed, 1 when any is denied or rejected,
and 2 for a usage error.

This file only parses arguments and prints results; the decisions come from the library.
-/

open PathFence

structure Args where
  base : Option String := none
  allow : Array String := #[]
  deny : Array String := #[]
  stdin : Bool := false
  paths : Array String := #[]

def parseArgs : List String → Args → Except String Args
  | [], a => .ok a
  | "--" :: rest, a => .ok { a with paths := a.paths ++ rest.toArray }
  | "--allow" :: d :: rest, a => parseArgs rest { a with allow := a.allow.push d }
  | "--deny" :: d :: rest, a => parseArgs rest { a with deny := a.deny.push d }
  | "--base" :: d :: rest, a => parseArgs rest { a with base := some d }
  | "--stdin" :: rest, a => parseArgs rest { a with stdin := true }
  | opt :: rest, a =>
    if opt.startsWith "--" then .error s!"unknown or incomplete option: {opt}"
    else parseArgs rest { a with paths := a.paths.push opt }

/-- A JSON string literal. -/
def jsonString (s : String) : String :=
  let hex (n : Nat) : Char := "0123456789abcdef".toList.getD n '0'
  let esc (c : Char) : String :=
    if c = '"' then "\\\"" else if c = '\\' then "\\\\"
    else if c = '\n' then "\\n" else if c = '\r' then "\\r" else if c = '\t' then "\\t"
    else if c.toNat < 0x20 then
      String.ofList ['\\', 'u', '0', '0', hex (c.toNat / 16), hex (c.toNat % 16)]
    else String.singleton c
  "\"" ++ String.join (s.toList.map esc) ++ "\""

def reasonName : Reason → String
  | .nul => "nul"
  | .escapes => "escapes"

def decisionJson (input : String) : Decision → String
  | .allow p => s!"\{\"input\":{jsonString input},\"decision\":\"allow\",\"path\":{jsonString p.toString}}"
  | .deny p => s!"\{\"input\":{jsonString input},\"decision\":\"deny\",\"path\":{jsonString p.toString}}"
  | .reject r => s!"\{\"input\":{jsonString input},\"decision\":\"reject\",\"reason\":\"{reasonName r}\"}"

def usage : String :=
  "usage: pathfence check --allow DIR [--allow DIR ...] [--deny DIR ...] [--base DIR] [--stdin] [--] PATH ..."

def parseRoots (xs : Array String) : Except String (List Path) :=
  xs.toList.mapM fun x => match parseRoot x with
    | some p => .ok p
    | none => .error s!"not an absolute directory without NUL: {x}"

partial def readLines (h : IO.FS.Stream) (acc : Array String) : IO (Array String) := do
  let line ← h.getLine
  if line.isEmpty then return acc
  let line := if line.endsWith "\n" then (line.dropEnd 1).toString else line
  readLines h (acc.push line)

def run (argv : List String) : IO UInt32 := do
  match argv with
  | "check" :: rest =>
    match parseArgs rest {} with
    | .error e => IO.eprintln e; IO.eprintln usage; return 2
    | .ok a =>
      match parseRoots a.allow, parseRoots a.deny, parseRoots (a.base.toArray) with
      | .ok allow, .ok deny, .ok base =>
        if allow.isEmpty then IO.eprintln "at least one --allow root is required"; IO.eprintln usage; return 2
        let pol : Policy := { base := base.headD (allow.headD []), allow, deny }
        let paths ← if a.stdin then readLines (← IO.getStdin) a.paths else pure a.paths
        let mut ok := true
        for s in paths do
          let d := pol.checkString s
          if !(d matches .allow _) then ok := false
          IO.println (decisionJson s d)
        return if ok then 0 else 1
      | .error e, _, _ | _, .error e, _ | _, _, .error e => IO.eprintln e; return 2
  | ["--version"] => IO.println "pathfence 0.1.0"; return 0
  | _ => IO.eprintln usage; return 2

def main (argv : List String) : IO UInt32 := run argv
