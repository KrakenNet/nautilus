"""``nautilus version`` subcommand."""

from __future__ import annotations

import sys
from importlib import metadata

from nautilus.build import BUILD_REV_ENV, build_rev, build_rev_override


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
    # stderr, so the two documented stdout lines stay two lines and
    # ``nautilus version | head -1`` keeps printing the bare version. Not an
    # error: the command answered, and it answered correctly -- the warning is
    # that someone asked it to answer something else.
    override = build_rev_override()
    if override is not None:
        print(
            f"warning: {BUILD_REV_ENV}={override} was ignored: the build answer "
            f"comes from the artifact, which reports {build_rev()}",
            file=sys.stderr,
        )
    return 0


__all__ = ["_cmd_version"]
