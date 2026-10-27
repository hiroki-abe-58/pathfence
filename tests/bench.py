"""Bounded throughput and memory check of the CLI (not part of the test suite).

    python3 tests/bench.py

Each case runs the built binary once and prints the wall time, the peak resident memory of the
process (from getrusage) and the number of results. Inputs are generated, so nothing is read from
disk. The cases stay small enough to finish in well under a minute on a laptop.
"""
import os
import random
import resource
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import BIN  # noqa: E402

PIECES = ["a", "src", "lib", "..", ".", "", "x.txt", "é", "node_modules", ".git"]


def run(name, args, data=None):
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    t0 = time.perf_counter()
    p = subprocess.run([BIN] + args, input=data, capture_output=True, check=False)
    dt = time.perf_counter() - t0
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss  # KiB, max over children so far
    lines = p.stdout.count(b"\n")
    size = len(data) if data else 0
    print(f"{name:<44} exit={p.returncode} results={lines:>7} input={size / 1e6:6.2f} MB "
          f"time={dt:6.2f} s peak_rss={peak / 1024:7.1f} MiB{'' if peak > before else ' (<= earlier case)'}")


def main():
    rng = random.Random(1)
    paths = ["/".join(rng.choice(PIECES) for _ in range(rng.randint(1, 8))) or "." for _ in range(100_000)]
    policy = ["check", "--allow", "/home/u/project", "--allow", "/tmp/scratch", "--deny", "/home/u/project/.git"]
    # Smallest first, so that each peak reading belongs to its own case.
    run("1,000 paths on the command line", policy + ["--"] + paths[:1000])
    run("10,000 paths on stdin", policy + ["--stdin"], "".join(p + "\n" for p in paths[:10_000]).encode())
    run("100,000 paths on stdin", policy + ["--stdin"], "".join(p + "\n" for p in paths).encode())
    run("one path of 100,000 segments", policy + ["--stdin"], ("/".join(["a"] * 100_000) + "\n").encode())
    run("one 1 MB name", policy + ["--stdin"], ("x" * 1_000_000 + "\n").encode())
    run("one path of 50,000 `a/..` pairs", policy + ["--stdin"], ("a/.." * 50_000 + "\n").replace("..a", "../a").encode())


if __name__ == "__main__":
    main()
