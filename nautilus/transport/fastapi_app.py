"""FastAPI surface for Nautilus (design §3.12, FR-25, FR-26, AC-12.*).

Single public entrypoint — :func:`create_app` — returns a fully-wired
:class:`FastAPI` instance whose lifespan owns a singleton :class:`Broker`.
The broker is constructed once at startup (``Broker.from_config`` +
``setup``) and released once at shutdown (``aclose``); request handlers
access it via ``request.app.state.broker``.

Endpoints (all under ``/v1`` except health probes):

- ``POST /v1/request`` — primary query entrypoint, body ``BrokerRequest``,
  response ``BrokerResponse``. Delegates directly to ``broker.arequest``
  with no thread executor (FR-25, AC-12.1).
- ``POST /v1/query`` — literal alias of ``/v1/request`` (D-9 / UQ-3);
  same handler, two route registrations, identical audit signal.
- ``GET /v1/sources`` — metadata-only listing (id, type, description,
  classification, data_types); never exposes DSNs or credentials
  (AC-12.3).
- ``GET /healthz`` — static 200 liveness probe; no broker dependency
  (AC-12.4).
- ``GET /readyz`` — 200 iff startup finished AND the session store's
  ``aget('_ready_probe_')`` succeeds; else 503 (AC-12.5).

Write endpoints (``POST /v1/request``, ``POST /v1/query``) are gated on
:func:`nautilus.transport.auth.require_api_key` when
``config.api.auth.mode == "api_key"`` (default, D-11) and on
:func:`proxy_trust_dependency` when the mode is ``"proxy_trust"``.
Probes are never gated — they must work during unauthenticated rolling
restarts.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from nautilus.core.broker import Broker
from nautilus.core.models import BrokerRequest, BrokerResponse
from nautilus.core.source_state import SourceState
from nautilus.transport.auth import api_key_header, proxy_trust_dependency, verify_api_key
from nautilus.ui import create_admin_router

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


_READY_PROBE_KEY = "_ready_probe_"


class DisableSourceRequest(BaseModel):
    """Request body for ``POST /v1/sources/{id}/disable`` (US-3, AC-3.4)."""

    reason: str = Field(min_length=1)


def _serialize_source_state(state: SourceState) -> dict[str, Any]:
    """Project a :class:`SourceState` onto JSON-safe primitives."""
    return {
        "enabled": state.enabled,
        "reason": state.reason,
        "actor": state.actor,
        "changed_at": state.changed_at.isoformat(),
    }


def _resolve_auth_config(broker: Broker | None) -> tuple[str, list[str]]:
    """Extract ``(mode, keys)`` from the broker's config, tolerating absent fields.

    ``ApiConfig`` is still a minimal shell in Phase 2 (host/port only). The
    design pins ``mode: "api_key" | "proxy_trust"`` and ``keys: list[str]``
    but later tasks formalize the pydantic model; until then we look them
    up defensively via ``getattr`` on both ``config.api`` and any nested
    ``auth`` object.

    Returns:
        Tuple of ``(mode, keys)``. ``mode`` defaults to ``"api_key"``;
        ``keys`` defaults to ``[]`` (which forces fail-closed 401 under
        :func:`verify_api_key`).
    """
    if broker is None:
        return ("api_key", [])
    api_cfg = getattr(broker, "_config", None)
    api_cfg = getattr(api_cfg, "api", None) if api_cfg is not None else None
    # auth.mode — nested discriminated object, still TBD in pydantic.
    auth_obj = getattr(api_cfg, "auth", None)
    mode_raw = getattr(auth_obj, "mode", None) if auth_obj is not None else None
    mode = mode_raw if mode_raw in ("api_key", "proxy_trust") else "api_key"
    # keys — flat list on api_cfg (design §3.12).
    keys_raw: object = getattr(api_cfg, "keys", None)
    keys: list[str] = []
    if isinstance(keys_raw, list):
        for k in keys_raw:  # pyright: ignore[reportUnknownVariableType]
            keys.append(str(k))  # pyright: ignore[reportUnknownArgumentType]
    return (mode, keys)


def create_app(
    config_path: str | Path | None,
    *,
    existing_broker: Broker | None = None,
) -> FastAPI:
    """Construct the Nautilus FastAPI application.

    Args:
        config_path: Path to ``nautilus.yaml``. Ignored when
            ``existing_broker`` is provided (tests inject a pre-built or
            mock broker to skip YAML loading).
        existing_broker: Pre-constructed broker. When supplied, the
            lifespan skips :meth:`Broker.from_config` but still awaits
            :meth:`Broker.setup` and :meth:`Broker.aclose` — the factory
            owns the lifecycle regardless of who constructed the broker.

    Returns:
        FastAPI app with lifespan, routes, and dependencies wired.

    Raises:
        ValueError: if ``config_path`` is ``None`` and ``existing_broker``
            is also ``None`` — the factory has no way to produce a broker.
    """
    if existing_broker is None and config_path is None:
        raise ValueError(
            "create_app requires either config_path or existing_broker",
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        """ASGI lifespan — build/setup broker on startup, close on shutdown."""
        if existing_broker is not None:
            broker = existing_broker
        else:
            # config_path is guaranteed non-None by the guard above.
            assert config_path is not None  # noqa: S101 — lifespan precondition
            broker = Broker.from_config(config_path)
        await broker.setup()
        app.state.broker = broker
        mode, keys = _resolve_auth_config(broker)
        app.state.auth_mode = mode
        app.state.api_keys = keys
        app.state.ready = True
        try:
            from nautilus.observability import setup_otel

            setup_otel(app)
        except ImportError:
            pass
        try:
            yield
        finally:
            app.state.ready = False
            await broker.aclose()

    app = FastAPI(
        title="Nautilus",
        description="Intent-aware scoped query broker (design §3.12).",
        version="0.1.0",
        lifespan=lifespan,
    )
    # Pre-populate defaults so routes don't AttributeError before lifespan
    # fires (e.g. startup-phase health checks during ASGI boot).
    app.state.broker = None
    app.state.auth_mode = "api_key"
    app.state.api_keys = []
    app.state.ready = False

    # ------------------------------------------------------------------
    # Auth dependency — resolved at request time so tests that mutate
    # ``app.state.auth_mode`` between requests get the new behaviour.
    # ------------------------------------------------------------------

    async def _write_guard(request: Request) -> str:
        """Delegate to api_key or proxy_trust based on current ``auth_mode``."""
        mode = getattr(request.app.state, "auth_mode", "api_key")
        if mode == "proxy_trust":
            return await proxy_trust_dependency(request)
        # api_key path pulls X-API-Key via APIKeyHeader directly — FastAPI's
        # sub-dependency resolver is not reachable from inside a dispatch
        # dependency, so we invoke the security scheme as a plain callable.
        header_value = await api_key_header(request)
        # APIKeyHeader(auto_error=True) raises HTTPException(403) on missing
        # header before we get here, so header_value is a non-None string.
        assert header_value is not None  # noqa: S101
        verify_api_key(header_value, list(getattr(request.app.state, "api_keys", [])))
        return header_value

    # ------------------------------------------------------------------
    # Shared handler — /v1/request and /v1/query alias to the same body.
    # D-9 / UQ-3: alias, NOT a separate code path.
    # ------------------------------------------------------------------

    async def _handle_request(
        body: BrokerRequest,
        request: Request,
    ) -> BrokerResponse:
        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:  # pragma: no cover — lifespan guards this.
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        return await broker.arequest(
            body.agent_id,
            body.intent,
            body.context,
            fact_set_hash=body.fact_set_hash,
        )

    async def _mutate_source_state(
        request: Request,
        source_id: str,
        *,
        enabled: bool,
        reason: str | None,
        actor: str,
    ) -> dict[str, Any]:
        """Shared body for ``POST /v1/sources/{id}/{disable,enable}`` (US-3).

        * 404 when ``source_id`` is not in the broker's source registry.
        * 503 when the broker has no ``SourceStateStore`` wired — state
          writes cannot be persisted under the Phase-1 memory/redis
          session backend (design §3.2 / US-3 prereq).
        """
        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        known_ids = {s.id for s in broker.sources}
        if source_id not in known_ids:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown source id: {source_id}",
            )
        store = getattr(broker, "_source_state_store", None)
        if store is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="source_state_store not configured",
            )
        new_state: SourceState = await store.set_enabled(
            source_id, enabled=enabled, reason=reason, actor=actor
        )
        return {"source_id": source_id, **_serialize_source_state(new_state)}

    # ------------------------------------------------------------------
    # Route registrations
    # ------------------------------------------------------------------

    @app.post(
        "/v1/request",
        response_model=BrokerResponse,
        dependencies=[Depends(_write_guard)],
        tags=["broker"],
    )
    async def post_request(  # pyright: ignore[reportUnusedFunction]
        body: BrokerRequest,
        request: Request,
    ) -> BrokerResponse:
        """Primary query entrypoint (FR-25, AC-12.1)."""
        return await _handle_request(body, request)

    @app.post(
        "/v1/query",
        response_model=BrokerResponse,
        dependencies=[Depends(_write_guard)],
        tags=["broker"],
    )
    async def post_query(  # pyright: ignore[reportUnusedFunction]
        body: BrokerRequest,
        request: Request,
    ) -> BrokerResponse:
        """Literal alias of ``/v1/request`` (D-9 / UQ-3)."""
        return await _handle_request(body, request)

    @app.get("/v1/sources", tags=["broker"])
    async def get_sources(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> dict[str, list[dict[str, Any]]]:
        """Metadata-only source listing (AC-12.3 — no DSN / credentials).

        Extended for US-3 to additionally surface per-source enable state
        (``enabled``, ``reason``, ``actor``, ``changed_at``). Unknown /
        never-toggled sources default to ``enabled=True`` with ``reason``,
        ``actor``, ``changed_at`` all ``None`` so Phase-1 YAML configs
        remain byte-compatible (NFR-5).
        """
        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            return {"sources": []}
        states: dict[str, SourceState] = {}
        store = getattr(broker, "_source_state_store", None)
        if store is not None:
            states = await store.load_all()
        out: list[dict[str, Any]] = []
        for s in broker.sources:
            row: dict[str, Any] = {
                "id": s.id,
                "type": s.type,
                "description": s.description,
                "classification": s.classification,
                "data_types": list(s.data_types),
                "enabled": True,
                "reason": None,
                "actor": None,
                "changed_at": None,
            }
            st = states.get(s.id)
            if st is not None:
                row.update(_serialize_source_state(st))
            out.append(row)
        return {"sources": out}

    @app.post(
        "/v1/sources/{source_id}/disable",
        dependencies=[Depends(_write_guard)],
        tags=["broker"],
    )
    async def post_source_disable(  # pyright: ignore[reportUnusedFunction]
        source_id: str,
        body: DisableSourceRequest,
        request: Request,
        actor: str = Depends(_write_guard),
    ) -> dict[str, Any]:
        """Disable a source (US-3, AC-3.4 / AC-3.5 / AC-3.6).

        Idempotent: calling twice with the same payload is a 200 on each
        call and refreshes ``changed_at`` on every write (AC-3.6).
        Unknown ``source_id`` → 404 (AC-3.5).
        """
        return await _mutate_source_state(
            request, source_id, enabled=False, reason=body.reason, actor=actor
        )

    @app.post(
        "/v1/sources/{source_id}/enable",
        dependencies=[Depends(_write_guard)],
        tags=["broker"],
    )
    async def post_source_enable(  # pyright: ignore[reportUnusedFunction]
        source_id: str,
        request: Request,
        actor: str = Depends(_write_guard),
    ) -> dict[str, Any]:
        """Re-enable a source (US-3, AC-3.4).

        No request body — ``reason`` is cleared to ``None``. Unknown
        ``source_id`` → 404 (AC-3.5).
        """
        return await _mutate_source_state(
            request, source_id, enabled=True, reason=None, actor=actor
        )

    @app.get("/healthz", tags=["probes"])
    async def healthz() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        """Static liveness probe — AC-12.4 (no broker dependency)."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["probes"])
    async def readyz(  # pyright: ignore[reportUnusedFunction]
        request: Request,
        response: Response,
    ) -> dict[str, str]:
        """Readiness probe — AC-12.5.

        200 iff the lifespan finished startup AND the session store can
        serve an ``aget`` against the sentinel key ``_ready_probe_``.
        Any exception from the store downgrades to 503 so rolling
        restarts take the pod out of rotation cleanly.
        """
        broker: Broker | None = getattr(request.app.state, "broker", None)
        ready = bool(getattr(request.app.state, "ready", False))
        if broker is None or not ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "not_ready", "reason": "startup_incomplete"}
        store: Any = getattr(broker, "session_store", None)
        if store is None:
            # Broker without an exposed session_store still counts as ready
            # (the probe is best-effort — AC-12.5).
            return {"status": "ok"}
        try:
            if hasattr(store, "aget"):
                await store.aget(_READY_PROBE_KEY)
            elif hasattr(store, "get"):
                store.get(_READY_PROBE_KEY)
        except Exception as exc:  # noqa: BLE001 — any backend failure → 503.
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "not_ready", "reason": type(exc).__name__}
        return {"status": "ok"}

    # ------------------------------------------------------------------
    # Root redirect — / → /admin
    # ------------------------------------------------------------------

    @app.get("/", include_in_schema=False)
    async def root_redirect() -> Response:  # pyright: ignore[reportUnusedFunction]
        from fastapi.responses import RedirectResponse

        return RedirectResponse(url="/admin", status_code=302)

    # ------------------------------------------------------------------
    # Admin UI — operator-facing dashboard (FR-1, AC-1.1)
    # ------------------------------------------------------------------

    app.include_router(create_admin_router())

    _ui_static_dir = Path(__file__).resolve().parent.parent / "ui" / "static"
    app.mount(
        "/admin/static",
        StaticFiles(directory=str(_ui_static_dir)),
        name="admin-static",
    )

    return app


__all__ = ["create_app"]
