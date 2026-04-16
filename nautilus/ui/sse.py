"""SSE endpoint for live source status updates (FR-2, AC-1.3).

Streams source-health changes to the admin sources page via
``sse-starlette``'s ``EventSourceResponse``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request
from sse_starlette import EventSourceResponse

from nautilus.ui.dependencies import get_auth_user, get_broker
from nautilus.ui.router import router, templates

if TYPE_CHECKING:
    from nautilus.core.broker import Broker


async def _source_event_generator(
    request: Request,
    broker: Broker,
) -> AsyncGenerator[dict[str, str]]:
    """Yield SSE events when source table data may have changed."""
    while True:
        if await request.is_disconnected():
            break

        sources = broker.sources
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


@router.get("/sources/events")
async def source_events(
    request: Request,
    broker: Annotated[Broker, Depends(get_broker)],
    user: Annotated[str, Depends(get_auth_user)],  # noqa: ARG001
) -> EventSourceResponse:
    """SSE stream of source table updates for the admin dashboard."""
    return EventSourceResponse(
        _source_event_generator(request, broker),
    )
