import PathFence

/-!
# `pathfence` command-line tool

    pathfence check (--allow DIR | --allow-all) … [--deny DIR …] [--base DIR] [--stdin] [-- PATH …]

Each requested path is checked with the proven `PathFence.Policy.check`, and one JSON object is
printed per path. An allowed path also names the allowed root it is under and the rest of the path
below that root (`Policy.allowedUnder`), for opening it with a confined call such as
`openat2(rootfd, rel, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`:

    {"input":"a/../b","decision":"allow","path":"/w/b","root":"/w","rel":"b"}
    {"input":"/etc/x","decision":"deny","path":"/etc/x"}
    {"input":"../x","decision":"reject","reason":"escapes"}

* Paths come after `--`, or one per line on stdin with `--stdin` (read to the end first). A path
  given before `--` is a usage error, so a path such as `--stdin` can never be taken for an option.
* Roots must be canonical (`PathFence.parseRoot`): `/w/`, `/w/..` or `//w` are refused, not
  normalised. Allowing every path takes `--allow-all`; `--allow /` is refused, so that an empty
  variable in `--allow "$ROOT/"` cannot allow everything.
* The base directory for relative paths defaults to the first `--allow` root.
* The exit status is 0 when at least one path was checked and every path is allowed, 1 when any is
  denied or rejected, and 2 for a usage error, including no paths at all.

Paths must be UTF-8. A path that is not is rejected with reason `encoding` instead of being checked
with replacement characters, which would be a different path from the one the caller holds. On
stdin the bytes are decoded exactly, and an invalid line is reported by its bytes:

    {"input_hex":"78ff79","decision":"reject","reason":"encoding"}

Command-line arguments reach the program already decoded, with U+FFFD in place of invalid bytes, so
an argument containing U+FFFD is rejected too (even a genuine one); use `--stdin` for such names.

The output is ASCII: every character outside printable ASCII is written as a `\u` escape, so no
line splitter can split a result line.

This file only parses arguments and prints results; the decisions come from the library.
-/

open PathFence

structure Args where
  base : Option String := none
  allow : Array String := #[]
  allowAll : Bool := false
  deny : Array String := #[]
  stdin : Bool := false
  paths : Array String := #[]

def parseArgs : List String → Args → Except String Args
  | [], a => .ok a
  | "--" :: rest, a => .ok { a with paths := a.paths ++ rest.toArray }
  | "--allow" :: d :: rest, a => parseArgs rest { a with allow := a.allow.push d }
  | "--allow-all" :: rest, a => parseArgs rest { a with allowAll := true }
  | "--deny" :: d :: rest, a => parseArgs rest { a with deny := a.deny.push d }
  | "--base" :: d :: rest, a => parseArgs rest { a with base := some d }
  | "--stdin" :: rest, a => parseArgs rest { a with stdin := true }
  | opt :: _, _ =>
    if opt.startsWith "--" then .error s!"unknown or incomplete option: {opt}"
    else .error s!"paths go after `--`: {opt}"

/-- A JSON string literal in ASCII. -/
def jsonString (s : String) : String :=
  let hex (n : Nat) : Char := "0123456789abcdef".toList.getD n '0'
  let u (n : Nat) : String :=
    String.ofList ['\\', 'u', hex (n / 4096 % 16), hex (n / 256 % 16), hex (n / 16 % 16), hex (n % 16)]
  let esc (c : Char) : String :=
    if c = '"' then "\\\"" else if c = '\\' then "\\\\"
    else if c = '\n' then "\\n" else if c = '\r' then "\\r" else if c = '\t' then "\\t"
    else if c.toNat < 0x20 || c.toNat ≥ 0x7f then
      -- Outside the BMP: a UTF-16 surrogate pair.
      if c.toNat ≥ 0x10000 then
        let v := c.toNat - 0x10000
        u (0xD800 + v / 1024) ++ u (0xDC00 + v % 1024)
      else u c.toNat
    else String.singleton c
  "\"" ++ String.join (s.toList.map esc) ++ "\""

def reasonName : Reason → String
  | .empty => "empty"
  | .nul => "nul"
  | .escapes => "escapes"

/-- A relative path: its segments joined by `/`, or `.` for none. -/
def relString (rel : Path) : String := if rel = [] then "." else String.ofList (join rel)

def decisionJson (pol : Policy) (input : String) : Decision → String
  | .allow p =>
    let under := match pol.allowedUnder p with
      | some (r, rel) => s!",\"root\":{jsonString r.toString},\"rel\":{jsonString (relString rel)}"
      | none => ""  -- unreachable: `allowedUnder_of_allow`
    s!"\{\"input\":{jsonString input},\"decision\":\"allow\",\"path\":{jsonString p.toString}{under}}"
  | .deny p => s!"\{\"input\":{jsonString input},\"decision\":\"deny\",\"path\":{jsonString p.toString}}"
  | .reject r => s!"\{\"input\":{jsonString input},\"decision\":\"reject\",\"reason\":\"{reasonName r}\"}"

def usage : String :=
  "usage: pathfence check (--allow DIR | --allow-all) ... [--deny DIR ...] [--base DIR] [--stdin] [-- PATH ...]"

/-- What the runtime puts in place of bytes that are not UTF-8. -/
def replacementChar : Char := Char.ofNat 0xFFFD

def parseRootArgs (xs : Array String) : Except String (List Path) :=
  xs.toList.mapM fun x => match parseRoot x with
    | some p => if x.contains replacementChar then .error s!"not UTF-8: {x}" else .ok p
    | none => .error s!"not a canonical absolute directory (no `.`, `..`, empty segment, trailing `/` or NUL): {x}"

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
  | .text s => let d := pol.checkString s; (decisionJson pol s d, d matches .allow _)
  | .lossy s => (s!"\{\"input\":{jsonString s},\"decision\":\"reject\",\"reason\":\"encoding\"}", false)
  | .invalid b => (s!"\{\"input_hex\":\"{hexBytes b}\",\"decision\":\"reject\",\"reason\":\"encoding\"}", false)

def run (argv : List String) : IO UInt32 := do
  match argv with
  | "check" :: rest =>
    match parseArgs rest {} with
    | .error e => IO.eprintln e; IO.eprintln usage; return 2
    | .ok a =>
      if a.allow.contains "/" then
        IO.eprintln "--allow / would allow every path; say --allow-all if that is intended"; return 2
      match parseRootArgs a.allow, parseRootArgs a.deny, parseRootArgs a.base.toArray with
      | .ok allow, .ok deny, .ok base =>
        let allow := if a.allowAll then allow ++ [[]] else allow
        if allow.isEmpty then IO.eprintln "at least one --allow root is required"; IO.eprintln usage; return 2
        let pol : Policy := { base := base.headD (allow.headD []), allow, deny }
        let fromStdin ← if a.stdin then pure (stdinInputs (← readAll (← IO.getStdin) .empty)) else pure #[]
        let inputs := a.paths.map argInput ++ fromStdin
        if inputs.isEmpty then IO.eprintln "no paths to check"; return 2
        let mut ok := true
        for i in inputs do
          let (line, allowed) := checkInput pol i
          if !allowed then ok := false
          IO.println line
        return if ok then 0 else 1
      | .error e, _, _ | _, .error e, _ | _, _, .error e => IO.eprintln e; return 2
  | ["--version"] => IO.println "pathfence 0.1.0"; return 0
  | _ => IO.eprintln usage; return 2

def main (argv : List String) : IO UInt32 := run argv
