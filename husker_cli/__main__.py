"""Shim that locates the native husker binary installed by maturin and execs it."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _find_native_binary() -> str:
    """Return the path to the native husker binary shipped in the wheel."""
    bin_name = "husker.exe" if sys.platform == "win32" else "husker"

    # maturin installs the binary into the environment's Scripts/bin dir,
    # which is already on PATH for an activated venv or system install.
    on_path = shutil.which(bin_name)
    if on_path and Path(on_path).resolve() != Path(sys.argv[0]).resolve():
        return on_path

    # Fallback: look next to the sys.executable (common on Windows, useful
    # when the shim is invoked via an explicit python -m husker_cli).
    candidate = Path(sys.executable).parent / bin_name
    if candidate.exists():
        return str(candidate)

    raise FileNotFoundError(
        "Could not find the native husker binary. Reinstall the package with "
        "'pip install --force-reinstall husker' or build from source."
    )


def main() -> int:
    try:
        native = _find_native_binary()
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    args = [native, *sys.argv[1:]]
    if sys.platform == "win32":
        return subprocess.run(args).returncode
    os.execv(native, args)
    return 0  # unreachable on POSIX


if __name__ == "__main__":
    sys.exit(main())
