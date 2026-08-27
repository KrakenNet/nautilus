"""``nautilus version`` subcommand."""

from __future__ import annotations

import sys
from importlib import metadata


def _cmd_version() -> int:
    try:
        # The distribution is ``nautilus-rkm``; the import package is
        # ``nautilus``. Looking up the import name raised
        # ``PackageNotFoundError`` on every real install -- the two tests that
        # cover this command monkeypatch ``metadata.version`` with a lambda that
        # ignores its argument, so neither could see it.
        ver = metadata.version("nautilus-rkm")
    except metadata.PackageNotFoundError:
        print("nautilus (version unknown — package metadata missing)", file=sys.stderr)
        return 1
    print(ver)
    return 0


__all__ = ["_cmd_version"]
