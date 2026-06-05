"""``nautilus version`` subcommand."""

from __future__ import annotations

import sys
from importlib import metadata


def _cmd_version() -> int:
    try:
        ver = metadata.version("nautilus")
    except metadata.PackageNotFoundError:
        print("nautilus (version unknown — package metadata missing)", file=sys.stderr)
        return 1
    print(ver)
    return 0


__all__ = ["_cmd_version"]
