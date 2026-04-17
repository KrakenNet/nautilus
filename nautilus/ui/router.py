"""Admin UI route handlers for the Nautilus operator dashboard.

Implements the source-status page (FR-1, FR-2, AC-1.1, AC-1.3), the
decisions / audit-log viewer (FR-4, FR-5, AC-2.1, AC-2.3), the audit
event log (FR-6, FR-7, FR-8, AC-3.1), and attestation verification
(FR-9, AC-4.1, AC-4.2).
Each endpoint serves a full page for normal requests or an HTMX partial
when the ``HX-Request`` header is present.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.responses import Response
from fastapi.templating import Jinja2Templates

from nautilus.core.broker import Broker
from nautilus.ui.audit_reader import AuditReader
from nautilus.ui.dependencies import get_auth_user

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------

_BROKER_NOT_READY_HTML = (
    "<!doctype html><html><head><title>Service Unavailable</title>"
    '<meta http-equiv="refresh" content="5"></head>'
    "<body><h1>503 &mdash; Broker starting&hellip;</h1>"
    "<p>The data-routing broker is still initialising. "
    "This page will refresh automatically.</p></body></html>"
)


def _broker_not_ready() -> HTMLResponse:
    """Return a 503 HTML page when the broker is not yet available."""
    return HTMLResponse(content=_BROKER_NOT_READY_HTML, status_code=503)


def _error_page(title: str, detail: str, *, status_code: int = 500) -> HTMLResponse:
    """Return a minimal HTML error page."""
    html = (
        f"<!doctype html><html><head><title>{title}</title></head>"
        f"<body><h1>{status_code} &mdash; {title}</h1>"
        f"<p>{detail}</p></body></html>"
    )
    return HTMLResponse(content=html, status_code=status_code)


async def _safe_broker(request: Request) -> Broker | None:
    """Return the broker or *None* if it is not yet initialised."""
    return getattr(request.app.state, "broker", None)  # type: ignore[no-any-return]


async def _safe_audit_path(request: Request) -> str | None:
    """Return the audit path, or *None* when the broker is unavailable."""
    broker: Broker | None = getattr(request.app.state, "broker", None)
    if broker is None:
        return None
    return str(broker._config.audit.path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


async def _safe_auth_user(request: Request) -> str | Response:
    """Authenticate, returning a redirect to login on failure.

    Wraps :func:`get_auth_user` so that authentication failures redirect
    the browser to ``/admin/login`` instead of showing raw JSON errors.
    """
    try:
        return await get_auth_user(request)
    except HTTPException as exc:
        if exc.status_code == 401:
            return RedirectResponse(url="/admin/login", status_code=302)
        title = "Forbidden"
        return _error_page(title, str(exc.detail), status_code=exc.status_code)


@router.get("/", include_in_schema=False)
async def admin_index() -> RedirectResponse:
    """Redirect /admin to /admin/playground."""
    return RedirectResponse(url="/admin/playground", status_code=302)


@router.get("/login", include_in_schema=False)
async def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    """Render the API key login form."""
    return templates.TemplateResponse(
        request, "pages/login.html", {"request": request, "error": error}
    )


@router.post("/login", include_in_schema=False)
async def login_submit(request: Request, api_key: str = Form(...)) -> Response:
    """Validate the API key and set a session cookie."""
    from nautilus.transport.auth import verify_api_key

    keys: list[str] = list(getattr(request.app.state, "api_keys", []) or [])
    try:
        verify_api_key(api_key, keys)
    except HTTPException:
        return templates.TemplateResponse(
            request,
            "pages/login.html",
            {"request": request, "error": "Invalid API key"},
            status_code=401,
        )
    response = RedirectResponse(url="/admin/sources", status_code=302)
    response.set_cookie(
        key="nautilus_key",
        value=api_key,
        httponly=True,
        samesite="lax",
        max_age=86400,
    )
    return response


@router.get("/logout", include_in_schema=False)
async def logout() -> Response:
    """Clear the session cookie and redirect to login."""
    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie(key="nautilus_key")
    return response


@router.get("/playground")
async def playground(
    request: Request,
    user: Annotated[str | Response, Depends(_safe_auth_user)],
) -> HTMLResponse:
    """Playground page — submit queries to the broker interactively."""
    if isinstance(user, Response):
        return user
    context = {"request": request, "user": user}
    return templates.TemplateResponse(request, "pages/playground.html", context)


@router.post("/api/query")
async def playground_query(
    request: Request,
    broker: Annotated[Broker | None, Depends(_safe_broker)],
    user: Annotated[str | Response, Depends(_safe_auth_user)],
) -> JSONResponse:
    """Proxy endpoint for playground queries.

    Accepts the same JSON body as ``/v1/request`` but authenticates via
    the admin session cookie, avoiding the httponly cookie / JS barrier.
    """
    if isinstance(user, Response):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if broker is None:
        return JSONResponse({"error": "Broker not ready"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    agent_id = body.get("agent_id", "unknown")
    intent = body.get("intent", "")
    context = body.get("context", {})

    if not intent:
        return JSONResponse({"error": "intent is required"}, status_code=400)

    try:
        result = await broker.arequest(agent_id, intent, context)
        return JSONResponse(result.model_dump(mode="json"))
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/sources")
async def source_status(
    request: Request,
    broker: Annotated[Broker | None, Depends(_safe_broker)],
    user: Annotated[str | Response, Depends(_safe_auth_user)],
) -> HTMLResponse:
    """Source status page — lists configured sources with metadata.

    SECURITY: ``SourceConfig.connection`` is never passed to the template
    (it contains credentials / DSNs).  Only ``id``, ``type``,
    ``classification``, ``description``, and ``data_types`` are exposed.

    When the ``HX-Request`` header is present, returns only the table-body
    partial (``partials/source_table_body.html``) for HTMX swap; otherwise
    returns the full page (``pages/sources.html``).
    """
    if isinstance(user, Response):
        return user
    if broker is None:
        return _broker_not_ready()

    sources = broker.sources
    source_rows = [
        {
            "id": s.id,
            "type": s.type,
            "classification": s.classification,
            "description": s.description,
            "data_types": s.data_types,
            "allowed_purposes": s.allowed_purposes or [],
        }
        for s in sources
    ]

    context = {
        "request": request,
        "user": user,
        "sources": source_rows,
        "source_count": len(source_rows),
    }

    is_htmx = request.headers.get("HX-Request") == "true"
    template_name = "partials/source_table_body.html" if is_htmx else "pages/sources.html"
    return templates.TemplateResponse(request, template_name, context)


@router.get("/decisions")
async def decisions(
    request: Request,
    audit_path: Annotated[str | None, Depends(_safe_audit_path)],
    user: Annotated[str | Response, Depends(_safe_auth_user)],
    agent_id: str | None = None,
    start: str | None = None,
    end: str | None = None,
    outcome: str | None = None,
    search: str | None = None,
) -> HTMLResponse:
    """Decisions page — lists audit entries with filters.

    Query params ``agent_id``, ``start``, ``end``, ``outcome``, and
    ``search`` narrow results.  ``outcome`` maps to whether the entry has
    denial records (``"denied"``) or not (``"allowed"``).

    When the ``HX-Request`` header is present, returns only the table-body
    partial (``partials/decision_row.html`` rows) for HTMX swap; otherwise
    returns the full page (``pages/decisions.html``).
    """
    if isinstance(user, Response):
        return user
    if audit_path is None:
        return _broker_not_ready()

    reader = AuditReader(audit_path)
    start_dt = _parse_dt(start)
    end_dt = _parse_dt(end)
    page = reader.read_page(agent_id=agent_id, start=start_dt, end=end_dt)

    entries = page.entries

    # Filter by outcome (allowed / denied)
    if outcome == "denied":
        entries = [e for e in entries if e.denial_records]
    elif outcome == "allowed":
        entries = [e for e in entries if not e.denial_records]

    # Free-text search across request_id, agent_id, raw_intent
    if search:
        term = search.lower()
        entries = [
            e
            for e in entries
            if term in e.request_id.lower()
            or term in e.agent_id.lower()
            or term in e.raw_intent.lower()
        ]

    decisions_list = [
        {
            "timestamp": e.timestamp,
            "request_id": e.request_id,
            "agent_id": e.agent_id,
            "sources_queried": ", ".join(e.sources_queried) if e.sources_queried else "—",
            "sources_denied": ", ".join(e.sources_denied) if e.sources_denied else "—",
            "duration_ms": e.duration_ms,
        }
        for e in entries
    ]

    filters = {
        "agent_id": agent_id or "",
        "start": start or "",
        "end": end or "",
        "outcome": outcome or "",
        "search": search or "",
    }

    context = {
        "request": request,
        "user": user,
        "decisions": decisions_list,
        "filters": filters,
    }

    is_htmx = request.headers.get("HX-Request") == "true"
    if is_htmx:
        # Return just the table rows for HTMX swap
        rows = "".join(
            templates.get_template("partials/decision_row.html").render(decision=d)
            for d in decisions_list
        )
        if not decisions_list:
            rows = (
                '<tr><td colspan="6"><div class="empty-state">'
                "<p>No decisions found</p></div></td></tr>"
            )
        return HTMLResponse(content=rows)
    return templates.TemplateResponse(request, "pages/decisions.html", context)


@router.get("/decisions/{request_id}")
async def decision_detail(
    request: Request,
    request_id: str,
    audit_path: Annotated[str | None, Depends(_safe_audit_path)],
    user: Annotated[str | Response, Depends(_safe_auth_user)],
) -> HTMLResponse:
    """Decision detail modal — returns the full trace for a specific request.

    Returns a ``decision_detail.html`` modal fragment containing rule trace,
    routing decisions, scope constraints, denial records, and facts summary
    for the given ``request_id``.
    """
    if isinstance(user, Response):
        return user
    if audit_path is None:
        return _broker_not_ready()

    reader = AuditReader(audit_path)
    page = reader.read_page()

    entry = None
    for e in page.entries:
        if e.request_id == request_id:
            entry = e
            break

    if entry is None:
        return HTMLResponse(content='<div class="empty-state"><p>Decision not found</p></div>')

    decision = {
        "request_id": entry.request_id,
        "timestamp": str(entry.timestamp),
        "agent_id": entry.agent_id,
        "rule_trace": entry.rule_trace,
        "routing_decisions": [rd.model_dump(mode="json") for rd in entry.routing_decisions],
        "scope_constraints": [sc.model_dump(mode="json") for sc in entry.scope_constraints],
        "denial_records": [dr.model_dump(mode="json") for dr in entry.denial_records],
        "facts_asserted_summary": entry.facts_asserted_summary,
        "sources_queried": entry.sources_queried,
        "sources_denied": entry.sources_denied,
        "duration_ms": entry.duration_ms,
    }

    context = {"request": request, "user": user, "decision": decision}
    return templates.TemplateResponse(request, "partials/decision_detail.html", context)


@router.get("/audit")
async def audit(
    request: Request,
    audit_path: Annotated[str | None, Depends(_safe_audit_path)],
    user: Annotated[str | Response, Depends(_safe_auth_user)],
    agent_id: str | None = None,
    source_id: str | None = None,
    event_type: str | None = None,
    start: str | None = None,
    end: str | None = None,
    cursor: str | None = None,
    sort: str = "-timestamp",
) -> HTMLResponse:
    """Audit event log — paginated view of all audit entries.

    Query params filter by ``agent_id``, ``source_id``, ``event_type``,
    ``start``/``end`` date range.  Cursor-based pagination via ``cursor``.
    ``sort`` accepts ``"-timestamp"`` (desc, default) or ``"timestamp"``
    (asc).

    When the ``HX-Request`` header is present, returns the table-body
    partial (``audit_rows.html``) and pagination fragment; otherwise
    returns the full page (``pages/audit.html``).
    """
    if isinstance(user, Response):
        return user
    if audit_path is None:
        return _broker_not_ready()

    reader = AuditReader(audit_path)
    start_dt = _parse_dt(start)
    end_dt = _parse_dt(end)

    # Map sort param to AuditReader's Literal["asc", "desc"]
    sort_order: str = "asc" if sort == "timestamp" else "desc"

    page = reader.read_page(
        cursor=cursor,
        agent_id=agent_id,
        source_id=source_id,
        event_type=event_type,
        start=start_dt,
        end=end_dt,
        sort=sort_order,  # pyright: ignore[reportArgumentType]
    )

    entries = [
        {
            "timestamp": e.timestamp,
            "request_id": e.request_id,
            "agent_id": e.agent_id,
            "event_type": getattr(e, "event_type", "decision"),
            "sources_queried": (", ".join(e.sources_queried) if e.sources_queried else "—"),
            "duration_ms": e.duration_ms,
        }
        for e in page.entries
    ]

    filters = {
        "agent_id": agent_id or "",
        "source_id": source_id or "",
        "event_type": event_type or "",
        "start": start or "",
        "end": end or "",
        "sort": sort,
    }

    context = {
        "request": request,
        "user": user,
        "entries": entries,
        "filters": filters,
        "next_cursor": page.next_cursor,
        "prev_cursor": page.prev_cursor,
        "total_estimate": page.total_estimate,
    }

    is_htmx = request.headers.get("HX-Request") == "true"
    if is_htmx:
        rows = templates.get_template("partials/audit_rows.html").render(entries=entries)
        pagination = templates.get_template("partials/pagination.html").render(
            next_cursor=page.next_cursor,
            prev_cursor=page.prev_cursor,
            total_estimate=page.total_estimate,
            filters=filters,
        )
        return HTMLResponse(content=rows + pagination)
    return templates.TemplateResponse(request, "pages/audit.html", context)


@router.get("/attestation")
async def attestation(
    request: Request,
    broker: Annotated[Broker | None, Depends(_safe_broker)],
    user: Annotated[str | Response, Depends(_safe_auth_user)],
) -> HTMLResponse:
    """Attestation verification page — form for verifying EdDSA JWTs."""
    if isinstance(user, Response):
        return user
    has_attestation = broker is not None and getattr(broker, "_attestation", None) is not None
    context = {
        "request": request,
        "user": user,
        "signing_key_configured": has_attestation,
    }
    return templates.TemplateResponse(request, "pages/attestation.html", context)


@router.post("/attestation/verify")
async def attestation_verify(
    request: Request,
    broker: Annotated[Broker | None, Depends(_safe_broker)],
    user: Annotated[str | Response, Depends(_safe_auth_user)],
    token: str = Form(...),
) -> HTMLResponse:
    """Verify an attestation token (EdDSA JWT)."""
    if isinstance(user, Response):
        return user

    import jwt as pyjwt

    att_svc = getattr(broker, "_attestation", None) if broker else None
    if att_svc is None:
        result = {
            "valid": False,
            "error": "Attestation not configured on this broker instance",
            "token_preview": token[:64] + "..." if len(token) > 64 else token,
            "claims": None,
        }
    else:
        try:
            public_key = att_svc.public_key
            claims = pyjwt.decode(token, public_key, algorithms=["EdDSA"])
            result = {
                "valid": True,
                "error": None,
                "token_preview": token[:64] + "..." if len(token) > 64 else token,
                "claims": claims,
            }
        except pyjwt.ExpiredSignatureError:
            result = {
                "valid": False,
                "error": "Token has expired",
                "token_preview": token[:64] + "..." if len(token) > 64 else token,
                "claims": None,
            }
        except pyjwt.InvalidTokenError as exc:
            result = {
                "valid": False,
                "error": str(exc),
                "token_preview": token[:64] + "..." if len(token) > 64 else token,
                "claims": None,
            }

    context = {"request": request, "user": user, "result": result}
    return templates.TemplateResponse(request, "partials/attestation_result.html", context)


def _parse_dt(value: str | None) -> datetime | None:
    """Parse an ISO datetime string, returning *None* on failure."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


__all__ = ["router"]
