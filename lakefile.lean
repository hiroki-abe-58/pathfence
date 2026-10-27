import Lake
open Lake DSL

package pathfence where
  version := v!"0.1.0"

@[default_target]
lean_lib PathFence

@[default_target]
lean_exe pathfence where
  root := `Main
