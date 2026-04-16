"""Nautilus transport package — HTTP/MCP surfaces over the :class:`Broker`.

Phase-2 module; houses:

- :mod:`nautilus.transport.auth` — shared ``X-API-Key`` dependency and
  optional ``X-Forwarded-User`` proxy-trust helpers (design §3.12, D-11).
- :mod:`nautilus.transport.fastapi_app` — :func:`create_app` factory wiring
  lifespan-managed :class:`Broker` into FastAPI routes (design §3.12,
  FR-25, FR-26, AC-12.*).

Both entrypoints are side-effect free at import time: constructing a
:class:`FastAPI` instance costs nothing until the ASGI lifespan runs.
"""

from __future__ import annotations
