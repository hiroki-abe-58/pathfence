"""Compile the Lean CLI and include it in a platform-specific, Python-ABI-free wheel."""

from pathlib import Path
import os
import platform
import subprocess
import sys
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from packaging.tags import platform_tags


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if sys.platform not in {"linux", "darwin"}:
            raise RuntimeError("PathFence wheels support Linux and macOS. Use WSL on Windows.")
        root = Path(self.root)
        env = os.environ.copy()
        if sys.platform == "darwin":
            # Leanc otherwise defaults to 99.0 to suppress linker warnings.
            # Rebuild objects too: Lake's cache may have used that default.
            env.setdefault("MACOSX_DEPLOYMENT_TARGET", platform.mac_ver()[0])
            subprocess.run(["lake", "clean"], cwd=root, env=env, check=True)
        subprocess.run(["lake", "build"], cwd=root, env=env, check=True)
        prefix = Path(subprocess.check_output(
            ["lean", "--print-prefix"], cwd=root, text=True
        ).strip())
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{next(platform_tags())}"
        build_data["force_include"][str(root / ".lake/build/bin/pathfence")] = "pathfence/bin/pathfence"
        # Lean's runtime and bundled native libraries are linked into the executable.
        for name in ("LICENSE", "LICENSES"):
            source = prefix / name
            if not source.exists():
                raise FileNotFoundError(f"Missing Lean redistribution license: {source}")
            build_data["force_include"][str(source)] = f"pathfence/licenses/lean/{name}"
