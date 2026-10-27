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

Paths must be UTF-8. A path that is not is rejected with reason `encoding` instead of being checked
with replacement characters, which would be a different path from the one the caller holds. On
stdin the bytes are decoded exactly, and an invalid line is reported by its bytes:

    {"input_hex":"78ff79","decision":"reject","reason":"encoding"}

Command-line arguments reach the program already decoded, with U+FFFD in place of invalid bytes, so
an argument containing U+FFFD is rejected too (even a genuine one); use `--stdin` for such names.

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

/-- What the runtime puts in place of bytes that are not UTF-8. -/
def replacementChar : Char := Char.ofNat 0xFFFD

def parseRoots (xs : Array String) : Except String (List Path) :=
  xs.toList.mapM fun x => match parseRoot x with
    | some p => if x.contains replacementChar then .error s!"not UTF-8: {x}" else .ok p
    | none => .error s!"not an absolute directory without NUL: {x}"

/-- A requested path. -/
inductive Input where
  /-- Decoded exactly. -/
  | text (s : String)
  /-- A command-line argument containing U+FFFD, which may stand for bytes that were not UTF-8. -/
  | lossy (s : String)
  /-- A stdin line that is not UTF-8. -/
  | invalid (bytes : ByteArray)

def argInput (s : String) : Input := if s.contains replacementChar then .lossy s else .text s

def hexBytes (b : ByteArray) : String :=
  let hex (n : Nat) : Char := "0123456789abcdef".toList.getD n '0'
  String.ofList (b.toList.flatMap fun x => [hex (x.toNat / 16), hex (x.toNat % 16)])

partial def readAll (h : IO.FS.Stream) (acc : ByteArray) : IO ByteArray := do
  let chunk ← h.read 65536
  if chunk.isEmpty then return acc
  readAll h (acc ++ chunk)

/-- Split stdin into lines (a final newline does not start another line) and decode each. -/
def stdinInputs (b : ByteArray) : Array Input :=
  let lines := b.toList.splitOn 10
  let lines := if lines.getLast? == some [] then lines.dropLast else lines
  lines.toArray.map fun l =>
    let bytes := ByteArray.mk l.toArray
    match String.fromUTF8? bytes with
    | some s => .text s
    | none => .invalid bytes

/-- The result line for one input, and whether it was allowed. -/
def checkInput (pol : Policy) : Input → String × Bool
  | .text s => let d := pol.checkString s; (decisionJson s d, d matches .allow _)
  | .lossy s => (s!"\{\"input\":{jsonString s},\"decision\":\"reject\",\"reason\":\"encoding\"}", false)
  | .invalid b => (s!"\{\"input_hex\":\"{hexBytes b}\",\"decision\":\"reject\",\"reason\":\"encoding\"}", false)

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
        let fromStdin ← if a.stdin then pure (stdinInputs (← readAll (← IO.getStdin) .empty)) else pure #[]
        let mut ok := true
        for i in a.paths.map argInput ++ fromStdin do
          let (line, allowed) := checkInput pol i
          if !allowed then ok := false
          IO.println line
        return if ok then 0 else 1
      | .error e, _, _ | _, .error e, _ | _, _, .error e => IO.eprintln e; return 2
  | ["--version"] => IO.println "pathfence 0.1.0"; return 0
  | _ => IO.eprintln usage; return 2

def main (argv : List String) : IO UInt32 := run argv
