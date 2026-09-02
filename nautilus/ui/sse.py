"""SSE endpoint for live source status updates (FR-2, AC-1.3).

Streams source-health changes to the admin sources page via
``sse-starlette``'s ``EventSourceResponse``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, Request
from sse_starlette import EventSourceResponse

# Runtime import, not TYPE_CHECKING: ``from __future__ import annotations``
# makes every annotation a string, and FastAPI resolves them at route-
# registration time to build the signature and the OpenAPI schema. A
# type-only Broker leaves an unresolvable name, which 500s /openapi.json.
from nautilus.core.broker import Broker
from nautilus.transport.auth import caller_identity
from nautilus.ui.dependencies import get_auth_user, get_broker
from nautilus.ui.router import require_capability, router, templates


async def _source_event_generator(
    request: Request,
    broker: Broker,
    agent_id: str | None,
) -> AsyncGenerator[dict[str, str]]:
    """Yield SSE events when source table data may have changed."""
    while True:
        if await request.is_disconnected():
            break

        # Same clearance filter the page applies. The capability dependency
        # above decides whether you may see a catalogue at all; this decides
        # which one. Without it a ``query`` credential bound to a low-clearance
        # agent got the whole catalogue here while /admin/sources and
        # /v1/sources both trimmed it.
        sources = broker.sources_visible_to(agent_id)
        source_rows = [
            {
                "id": s.id,
                "type": s.type,
                "classification": s.classification,
                "data_types": s.data_types,
                "allowed_purposes": getattr(s, "allowed_purposes", None),
                "last_query": getattr(s, "last_query", None),
            }
            for s in sources
        ]

        html = templates.get_template("partials/source_table_body.html").render(sources=source_rows)

        yield {"event": "source-update", "data": html}

        await asyncio.sleep(5)


@router.get(
    "/sources/events",
    dependencies=[Depends(require_capability("query"))],
)
async def source_events(
    request: Request,
    broker: Annotated[Broker, Depends(get_broker)],
    user: Annotated[str, Depends(get_auth_user)],  # noqa: ARG001
) -> EventSourceResponse:
    """SSE stream of source table updates for the admin dashboard."""
    state = request.app.state
    caller = caller_identity(
        request,
        auth_mode=getattr(state, "auth_mode", "api_key"),
        keys=list(getattr(state, "api_keys", []) or []),
        agent_subjects=dict(getattr(state, "agent_subjects", {}) or {}),
        trusted_proxies=list(getattr(state, "trusted_proxies", []) or []),
    )
    return EventSourceResponse(
        _source_event_generator(request, broker, caller["agent_id"]),
    )
