# pyright: reportPrivateUsage=false
"""WAVE 15 -- two doors that authenticated on one thing and authorised on another.

Both defects survived a green suite, and both were found by adversarially
re-reading commits whose messages said the area was fixed.

* **The MCP gate and ``caller_identity`` read different bytes.** The ASGI gate
  at ``mcp_server.py`` collapsed the raw header list with ``dict(...)``, which
  keeps the **last** value of a repeated header; ``caller_identity`` reads it
  through Starlette's ``Headers``, which keeps the **first**. Sending
  ``X-API-Key`` twice let the gate pass on a valid key while the identity layer
  matched nothing and fell through to the unauthenticated default -- which is
  ``ALL_CAPABILITIES``, bound to no agent. REST and the console read the first
  value in *both* layers, so they agree; MCP was the sole divergence.

* **``GET /admin/sources/events`` carried no capability check.** Its page
  sibling ``/admin/sources`` requires ``query`` and filters the catalogue by the
  caller's clearance. The SSE stream that feeds the same table required only
  authentication and rendered ``broker.sources`` unfiltered, so a credential the
  API refuses got the whole catalogue on a five-second loop.
"""

from __future__ import annotations

import pytest
from starlette.datastructures import Headers

pytestmark = [pytest.mark.unit]


def test_w15_repeated_header_reads_the_same_value_in_both_layers() -> None:
    """The gate and the identity layer must agree on which value is the credential.

    This is the whole defect in one assertion: two readers, one raw header
    list, two answers.
    """
    from nautilus.transport.mcp_server import _api_key_from_scope

    raw = [(b"x-api-key", b"FIRST-KEY"), (b"x-api-key", b"LAST-KEY")]
    gate_sees = _api_key_from_scope({"type": "http", "headers": raw})
    identity_sees = Headers(raw=raw).get("X-API-Key")

    assert gate_sees == identity_sees, (
        f"the MCP gate authenticates on {gate_sees!r} while caller_identity "
        f"authorises on {identity_sees!r}; a caller who sends the header twice "
        f"is admitted on one key and identified as another"
    )


def test_w15_sse_source_stream_requires_the_same_capability_as_its_page() -> None:
    """The stream and the page feed one table, so they need one guard."""
    import importlib

    # Importing the module is what registers the route on the shared router.
    importlib.import_module("nautilus.ui.sse")
    from nautilus.ui.router import router

    def _deps(path: str) -> str:
        for route in router.routes:
            if getattr(route, "path", None) == path:
                return repr(getattr(route, "dependencies", []))
        raise AssertionError(f"route {path} is not registered")

    page, stream = _deps("/admin/sources"), _deps("/admin/sources/events")
    assert "require_capability" in page, "the page's own guard vanished"
    assert "require_capability" in stream, (
        "/admin/sources/events has no capability dependency while /admin/sources "
        "requires one; an audit_read-only credential is refused by the page and "
        "served the catalogue by the stream"
    )


def test_w15_sse_stream_filters_by_clearance_like_its_page() -> None:
    """The guard decides *whether*; the filter decides *which*.

    ``/admin/sources`` and ``/v1/sources`` both trim the catalogue to what the
    caller's agent may see. The stream rendered ``broker.sources`` whole.
    """
    import inspect

    from nautilus.ui import sse

    body = inspect.getsource(sse._source_event_generator)  # noqa: SLF001
    assert "sources_visible_to" in body, (
        "the SSE generator renders the unfiltered catalogue; a query-capable "
        "credential bound to a low-clearance agent sees sources the page and "
        "the API both refuse it"
    )
    assert "broker.sources\n" not in body, "the unfiltered read is still there"


def test_w15_every_door_to_the_source_catalogue_filters_by_clearance() -> None:
    """Four surfaces publish the catalogue; all four must trim it the same way.

    ``GET /v1/sources`` and ``/admin/sources`` already did. The SSE stream and
    the MCP ``nautilus_sources`` tool did not -- the MCP one while carrying a
    docstring worrying about "a door with a second entrance", which is exactly
    what it was.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    doors = {
        "REST /v1/sources": root / "nautilus/transport/fastapi_app.py",
        "console page": root / "nautilus/ui/router.py",
        "console SSE": root / "nautilus/ui/sse.py",
        "MCP nautilus_sources": root / "nautilus/transport/mcp_server.py",
    }
    missing = [
        name
        for name, path in doors.items()
        if "sources_visible_to" not in path.read_text(encoding="utf-8")
    ]
    assert not missing, (
        f"these surfaces publish the source catalogue without the clearance "
        f"filter every other surface applies: {missing}"
    )
