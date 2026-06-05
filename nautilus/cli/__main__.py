"""Entry shim so ``python -m nautilus.cli ...`` routes to :func:`nautilus.cli.main`.

The pre-split monolith (``nautilus/cli.py``) was directly runnable via
``-m nautilus.cli``; the package split (OQ4) requires this ``__main__``
to keep that invocation working (e.g. the MCP stdio server subprocess).
"""

from __future__ import annotations

import sys

from nautilus.cli import main

if __name__ == "__main__":
    sys.exit(main())
