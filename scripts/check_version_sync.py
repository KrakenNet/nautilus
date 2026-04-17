"""Verify that pyproject.toml and nautilus/__init__.py declare the same version."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def main() -> int:
    pyproject = ROOT / "pyproject.toml"
    init = ROOT / "nautilus" / "__init__.py"

    pp_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
    if not pp_match:
        print("ERROR: no version in pyproject.toml")
        return 1

    init_match = re.search(r'^__version__\s*=\s*"([^"]+)"', init.read_text(), re.MULTILINE)
    if not init_match:
        print("ERROR: no __version__ in nautilus/__init__.py")
        return 1

    pp_ver, init_ver = pp_match.group(1), init_match.group(1)
    if pp_ver != init_ver:
        print(f"ERROR: version mismatch — pyproject.toml={pp_ver}, __init__.py={init_ver}")
        return 1

    print(f"OK: version {pp_ver}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
