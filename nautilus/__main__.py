"""Entry shim so ``python -m nautilus ...`` routes to :func:`nautilus.cli.main`."""

from __future__ import annotations

import sys

from nautilus.cli import main

if __name__ == "__main__":
    sys.exit(main())
