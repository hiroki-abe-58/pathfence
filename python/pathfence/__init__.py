"""Launch the bundled Lean CLI; path decisions remain in the verified implementation."""

import os
from pathlib import Path
import sys


def main() -> None:
    """Replace the launcher, preserving stdin, stdout, stderr and exit status."""
    binary = Path(__file__).parent / "bin" / "pathfence"
    os.execv(binary, [str(binary), *sys.argv[1:]])
