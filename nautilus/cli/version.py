"""``nautilus version`` subcommand."""

from __future__ import annotations

import sys
from importlib import metadata

from nautilus.build import build_rev


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
    # Two lines, because they answer different questions and only one of them
    # moves between two builds of the same release line. The version stays on
    # line 1 by itself so ``nautilus version | head -1`` keeps working; the
    # build revision is a second line rather than a suffix for the same reason.
    # This is the only way to ask an image which build it is without starting
    # it as a server, which matters on the distroless runtime image: there is no
    # shell in it to read a file with.
    print(ver)
    print(f"build: {build_rev()}")
    return 0


__all__ = ["_cmd_version"]
