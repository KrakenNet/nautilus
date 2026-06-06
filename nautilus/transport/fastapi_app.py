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
- ``GET /v1/rkm/queue`` — list proposals (AC-35.9.b).
- ``GET /v1/rkm/queue/{proposal_id}`` — show single proposal (AC-35.9.c).
- ``POST /v1/rkm/queue/{proposal_id}/approve`` — approve (AC-35.9.d).
- ``POST /v1/rkm/queue/{proposal_id}/reject`` — reject (AC-35.9.d).
- ``GET /v1/rules/{rule_name}/lineage`` — lineage DAG (AC-35.10.b).
- ``POST /v1/rules/{rule_name}/retract`` — retract rule (AC-35.10.a/d).
- ``POST /v1/rules/{rule_name}/rollback`` — rollback to version (AC-35.10.d).
- ``GET /v1/audit`` — paginated audit-entry query with server-side filters
  (agent_id, source_id, event_type, start/end, cursor, limit, order); auth
  required (#32).
- ``GET /v1/audit/{request_id}`` — single audit-entry lookup; 404 when
  absent; auth required (#32).

Write endpoints (``POST /v1/request``, ``POST /v1/query``) are gated on
:func:`nautilus.transport.auth.require_api_key` when
``config.api.auth.mode == "api_key"`` (default, D-11) and on
:func:`proxy_trust_dependency` when the mode is ``"proxy_trust"``.
Probes are never gated — they must work during unauthenticated rolling
restarts.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import Depends, FastAPI, Query, Request, Response, status
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from nautilus.attestation.jwks import export_jwks
from nautilus.attestation.key_ring import KeyRing
from nautilus.attestation.session_token import SessionTokenService
from nautilus.core.broker import Broker
from nautilus.core.metrics import register_rkm_queue
from nautilus.core.models import BrokerRequest, BrokerResponse
from nautilus.transport.auth import api_key_header, proxy_trust_dependency, verify_api_key
from nautilus.ui import create_admin_router
from nautilus.ui.audit_reader import AuditReader
from nautilus.ui.dependencies import get_auth_user

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


_READY_PROBE_KEY = "_ready_probe_"

# Hard cap on /v1/audit page size — bounds result set for SIEM / dashboard
# pulls regardless of caller-supplied ``limit`` (#32 acceptance: bounded
# result set size).
_AUDIT_MAX_LIMIT = 500
_AUDIT_DEFAULT_LIMIT = 50


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


def _find_audit_entry(reader: AuditReader, request_id: str) -> Any:
    """Page through the audit log (newest-first) for ``request_id``.

    Returns the matching ``AuditEntry`` or ``None``. Cursor pagination
    keeps memory bounded on GB-sized logs; the loop terminates when the
    reader stops handing back a ``next_cursor``.
    """
    cursor: str | None = None
    while True:
        page = reader.read_page(cursor=cursor, sort="desc")
        for entry in page.entries:
            if entry.request_id == request_id:
                return entry
        if not page.next_cursor or page.next_cursor == cursor:
            return None
        cursor = page.next_cursor


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
        # Key ring for session-token endpoints (AC-18.a–g). One shared
        # instance per process; rotated in-place via KeyRing.rotate().
        app.state.key_ring = KeyRing()
        app.state.broker_instance_id = getattr(broker, "_instance_id", "default")
        app.state.ready = True
        # Wire Prometheus RKM queue collector (AC-35.9.f).
        register_rkm_queue(lambda: getattr(app.state, "proposal_queue", None))
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
        )

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
        """Metadata-only source listing (AC-12.3 — no DSN / credentials)."""
        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            return {"sources": []}
        return {
            "sources": [
                {
                    "id": s.id,
                    "type": s.type,
                    "description": s.description,
                    "classification": s.classification,
                    "data_types": list(s.data_types),
                }
                for s in broker.sources
            ],
        }

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
    # Session-token endpoints (AC-18.a–g)
    # ------------------------------------------------------------------

    @app.get("/v1/keys/jwks.json", tags=["attestation"])
    async def get_jwks(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> dict[str, Any]:
        """JWKS endpoint per RFC 7517 (AC-18.c)."""
        key_ring: KeyRing | None = getattr(request.app.state, "key_ring", None)
        if key_ring is None:
            return {"keys": []}
        return export_jwks(key_ring)

    @app.post("/v1/sessions", tags=["attestation"])
    async def post_sessions(  # pyright: ignore[reportUnusedFunction]
        body: dict[str, Any],
        request: Request,
    ) -> dict[str, Any]:
        """Issue a session token (AC-18.a). Body: session_id, agent_id, purpose, clearance."""
        key_ring: KeyRing | None = getattr(request.app.state, "key_ring", None)
        if key_ring is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Key ring not ready",
            )
        broker_instance_id: str = getattr(request.app.state, "broker_instance_id", "default")
        service = SessionTokenService(key_ring=key_ring, broker_instance_id=broker_instance_id)
        token = service.issue(
            session_id=body.get("session_id", ""),
            agent_id=body.get("agent_id", ""),
            purpose=body.get("purpose", ""),
            clearance=body.get("clearance", ""),
        )
        claims = service.verify(token)
        return {
            "token": token,
            "session_id": claims.session_id,
            "agent_id": claims.agent_id,
            "purpose": claims.purpose,
            "clearance": claims.clearance,
            "issued_at": claims.issued_at,
            "expires_at": claims.expires_at,
            "broker_instance_id": claims.broker_instance_id,
            "kid": claims.kid,
        }

    # ------------------------------------------------------------------
    # Adapter schema endpoint (AC-21.a)
    # ------------------------------------------------------------------

    @app.get("/v1/adapters/{name}/schema", tags=["adapters"])
    async def get_adapter_schema(  # pyright: ignore[reportUnusedFunction]
        name: str,
        request: Request,
    ) -> dict[str, Any]:
        """Return the current AdapterSchema for the named adapter. AC-21.a."""
        import dataclasses

        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        adapter = getattr(broker, "_adapters", {}).get(name)
        if adapter is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Adapter '{name}' not found",
            )
        if not hasattr(adapter, "get_schema"):
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail=f"Adapter '{name}' does not support schema introspection",
            )
        try:
            schema = await adapter.get_schema()
        except Exception as exc:  # noqa: BLE001
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Schema fetch failed: {exc}",
            ) from exc
        return dataclasses.asdict(schema)

    # ------------------------------------------------------------------
    # Prometheus metrics endpoint — AC-35.9.f
    # ------------------------------------------------------------------

    @app.get("/metrics", tags=["observability"], include_in_schema=False)
    async def get_metrics() -> Response:  # pyright: ignore[reportUnusedFunction]
        """Prometheus metrics scrape endpoint (AC-35.9.f)."""
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        data = generate_latest()
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    # ------------------------------------------------------------------
    # RKM queue endpoints — AC-35.9.b/c/d (thin wrappers over review.py)
    # ------------------------------------------------------------------

    def _get_queue(request: Request) -> Any:
        """Return app.state.proposal_queue or a default in-memory instance."""
        from nautilus.rkm.queue import ProposalQueue

        q = getattr(request.app.state, "proposal_queue", None)
        if q is None:
            from pathlib import Path as _Path

            default_dir = _Path.cwd() / ".nautilus" / "rkm" / "queue"
            q = ProposalQueue(default_dir)
            request.app.state.proposal_queue = q
        return q

    def _get_lineage(request: Request) -> Any:
        """Return app.state.lineage_store or a default in-memory instance."""
        from nautilus.rkm.lineage import LineageStore

        ls = getattr(request.app.state, "lineage_store", None)
        if ls is None:
            from pathlib import Path as _Path

            default_dir = _Path.cwd() / ".nautilus" / "rkm" / "lineage"
            ls = LineageStore(default_dir)
            request.app.state.lineage_store = ls
        return ls

    def _require_reviewer(request: Request) -> str:
        """Extract X-Nautilus-Reviewer header or raise 400 (AC-35.9.d / DQ4)."""
        from fastapi import HTTPException

        reviewer = request.headers.get("X-Nautilus-Reviewer") or request.headers.get("X-Reviewer")
        if not reviewer:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="X-Nautilus-Reviewer header required",
            )
        return reviewer

    @app.get("/v1/rkm/queue", tags=["rkm"])
    async def get_rkm_queue(  # pyright: ignore[reportUnusedFunction]
        request: Request,
        status_filter: str | None = Query(default=None, alias="status"),
        limit: int = 100,
    ) -> dict[str, Any]:
        """List proposals with optional status filter (AC-35.9.b)."""
        import dataclasses

        queue = _get_queue(request)
        proposals = queue.list(status=status_filter)  # type: ignore[arg-type]
        if limit > 0:
            proposals = proposals[:limit]
        return {
            "proposals": [
                {**dataclasses.asdict(p), "proposed_at": p.proposed_at.isoformat()}
                for p in proposals
            ]
        }

    @app.get("/v1/rkm/queue/{proposal_id}", tags=["rkm"])
    async def get_rkm_proposal(  # pyright: ignore[reportUnusedFunction]
        proposal_id: str,
        request: Request,
    ) -> dict[str, Any]:
        """Show single proposal with full breakdown (AC-35.9.c)."""
        import dataclasses

        from fastapi import HTTPException

        queue = _get_queue(request)
        proposal = queue.get(proposal_id)
        if proposal is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"proposal not found: {proposal_id!r}",
            )
        d = dataclasses.asdict(proposal)
        d["proposed_at"] = proposal.proposed_at.isoformat()
        # Enrich with breakdown fields for AC-35.9.c (best-effort from artifact/validation)
        return {
            **d,
            "proposed_rule": proposal.artifact,
            "sandbox": proposal.validation.get("sandbox", {}),
            "confidence": proposal.validation.get("confidence", 0.0),
            "confidence_breakdown": proposal.validation.get("confidence_breakdown", {}),
            "shadow_flags": list(proposal.shadow_flags),
            "top_replayed": proposal.validation.get("top_replayed", []),
        }

    @app.post("/v1/rkm/queue/{proposal_id}/approve", tags=["rkm"])
    async def post_rkm_approve(  # pyright: ignore[reportUnusedFunction]
        proposal_id: str,
        request: Request,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Approve a pending proposal (AC-35.9.d). Requires X-Nautilus-Reviewer."""
        import dataclasses

        from fastapi import HTTPException

        from nautilus.rkm.review import AlreadyDecidedError, approve_proposal

        reviewer = _require_reviewer(request)
        queue = _get_queue(request)
        lineage = _get_lineage(request)
        try:
            result = approve_proposal(
                proposal_id,
                reviewer,
                queue=queue,
                lineage=lineage,
                router=None,
                audit_logger=None,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except AlreadyDecidedError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "already_decided", "current_status": exc.current_status},
            ) from exc
        return dataclasses.asdict(result)

    @app.post("/v1/rkm/queue/{proposal_id}/reject", tags=["rkm"])
    async def post_rkm_reject(  # pyright: ignore[reportUnusedFunction]
        proposal_id: str,
        request: Request,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Reject a pending proposal (AC-35.9.d). Requires X-Nautilus-Reviewer + reason."""
        import dataclasses

        from fastapi import HTTPException

        from nautilus.rkm.review import AlreadyDecidedError, reject_proposal

        reviewer = _require_reviewer(request)
        parsed_body: dict[str, Any] = body or {}
        reason: str | None = parsed_body.get("reason")
        if not reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="reason is required for rejection",
            )
        queue = _get_queue(request)
        try:
            result = reject_proposal(
                proposal_id,
                reviewer,
                reason,
                queue=queue,
                audit_logger=None,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except AlreadyDecidedError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "already_decided", "current_status": exc.current_status},
            ) from exc
        return dataclasses.asdict(result)

    # ------------------------------------------------------------------
    # Rules endpoints — AC-35.10.a/b/c/d (lineage DAG + retract + rollback)
    # ------------------------------------------------------------------

    @app.get("/v1/rules/{rule_name}/lineage", tags=["rules"])
    async def get_rule_lineage(  # pyright: ignore[reportUnusedFunction]
        rule_name: str,
        request: Request,
    ) -> dict[str, Any]:
        """Show lineage DAG for a rule (AC-35.10.b)."""
        import dataclasses

        from fastapi import HTTPException

        lineage = _get_lineage(request)
        versions = lineage.history(rule_name)
        if not versions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"rule not found: {rule_name!r}",
            )
        latest = versions[-1]
        serialized_versions: list[dict[str, Any]] = []
        for r in versions:
            d = dataclasses.asdict(r)
            d["promoted_at"] = r.promoted_at.isoformat()
            if r.retired_at is not None:
                d["retired_at"] = r.retired_at.isoformat()
            serialized_versions.append(d)
        return {
            "rule_name": rule_name,
            "proposer": latest.proposer,
            "approver": latest.approver,
            "observation_ids": latest.observation_ids,
            "derived_from": list(latest.derived_from),
            "versions": serialized_versions,
        }

    @app.post("/v1/rules/{rule_name}/retract", tags=["rules"])
    async def post_rule_retract(  # pyright: ignore[reportUnusedFunction]
        rule_name: str,
        request: Request,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Retract a rule (AC-35.10.a/d). Requires X-Nautilus-Reviewer + yes=true."""
        from fastapi import HTTPException

        from nautilus.rkm.review import retract_rule

        reviewer = _require_reviewer(request)
        parsed_body: dict[str, Any] = body or {}
        if not parsed_body.get("yes", False) and not parsed_body.get("confirm", False):
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail="yes=true required for destructive operation",
            )
        reason: str = parsed_body.get("reason", "")
        if not reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="reason is required for retraction",
            )
        cascade: str = parsed_body.get("cascade", "none")
        # Normalize cascade mode aliases from postman contracts
        if cascade in ("orphan_children", "orphan-children"):
            cascade = "orphan-children"
        elif cascade == "cascade":
            cascade = "cascade"
        else:
            cascade = "none"

        # Determine version to retract (latest by default)
        lineage = _get_lineage(request)
        version_param = parsed_body.get("version")
        if version_param is not None:
            version = int(version_param)
        else:
            latest = lineage.get(rule_name)
            if latest is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"rule not found: {rule_name!r}",
                )
            version = latest.version

        try:
            affected = retract_rule(
                rule_name,
                version=version,
                reason=reason,
                reviewer=reviewer,
                cascade=cascade,  # type: ignore[arg-type]
                lineage=lineage,
                audit_logger=None,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        return {"rule_name": rule_name, "version": version, "affected_descendants": affected}

    @app.post("/v1/rules/{rule_name}/rollback", tags=["rules"])
    async def post_rule_rollback(  # pyright: ignore[reportUnusedFunction]
        rule_name: str,
        request: Request,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Roll back a rule to a prior version (AC-35.10.d). Requires yes=true."""
        import dataclasses

        from fastapi import HTTPException

        reviewer = _require_reviewer(request)
        parsed_body: dict[str, Any] = body or {}
        if not parsed_body.get("yes", False) and not parsed_body.get("confirm", False):
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail="yes=true required for destructive operation",
            )
        to_version_raw = parsed_body.get("to_version")
        if to_version_raw is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="to_version is required for rollback",
            )
        to_version = int(to_version_raw)
        lineage = _get_lineage(request)
        target = lineage.get(rule_name, version=to_version)
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"rule {rule_name!r} version {to_version} not found",
            )
        # Re-activate by inserting a new version record copied from the target.
        # Version = current_latest + 1 to preserve append-only semantics.
        latest = lineage.get(rule_name)
        new_version = (latest.version + 1) if latest is not None else to_version
        from datetime import UTC
        from datetime import datetime as _datetime

        from nautilus.rkm.lineage import LineageRecord

        rolled_back = LineageRecord(
            rule_name=rule_name,
            version=new_version,
            proposer=target.proposer,
            observation_ids=target.observation_ids,
            sandbox_results=target.sandbox_results,
            approver=reviewer,
            derived_from=target.derived_from,
            promoted_at=_datetime.now(UTC),
        )
        lineage.insert(rolled_back)
        d = dataclasses.asdict(rolled_back)
        d["promoted_at"] = rolled_back.promoted_at.isoformat()
        return {
            "rule_name": rule_name,
            "rolled_back_from_version": to_version,
            "new_version": new_version,
            "record": d,
        }

    # ------------------------------------------------------------------
    # Public audit query API — #32 (SIEM ingestion, compliance pipelines)
    # ------------------------------------------------------------------

    async def _read_guard(request: Request) -> str:
        """Authenticate a read request via the shared admin/API auth path.

        Wraps :func:`get_auth_user` so FastAPI introspects *this* function's
        signature (``Request`` is resolvable here) rather than the imported
        dependency's, whose ``Request`` annotation is TYPE_CHECKING-only.
        """
        return await get_auth_user(request)

    def _audit_reader(request: Request, page_size: int = _AUDIT_DEFAULT_LIMIT) -> AuditReader:
        """Build an :class:`AuditReader` over the broker's configured log."""
        from fastapi import HTTPException

        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        # Mirror nautilus.ui.dependencies.get_audit_path — the audit log path
        # lives on the broker's config (the same source the admin UI reads).
        audit_path = str(broker._config.audit.path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        return AuditReader(audit_path, page_size=page_size)

    def _parse_audit_dt(value: str | None) -> datetime | None:
        """Parse an ISO-8601 datetime query param, or 400 on bad input."""
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError as exc:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid datetime: {value!r}",
            ) from exc

    @app.get(
        "/v1/audit",
        dependencies=[Depends(_read_guard)],
        tags=["audit"],
    )
    async def get_audit(  # pyright: ignore[reportUnusedFunction]
        request: Request,
        agent_id: str | None = None,
        source_id: str | None = None,
        event_type: str | None = None,
        start: str | None = None,
        end: str | None = None,
        cursor: str | None = None,
        limit: int = Query(default=_AUDIT_DEFAULT_LIMIT, ge=1, le=_AUDIT_MAX_LIMIT),
        order: str = Query(default="desc", pattern="^(asc|desc)$"),
    ) -> dict[str, Any]:
        """Paginated audit-entry query with server-side filters (#32).

        Filters (``agent_id``, ``source_id``, ``event_type``,
        ``start``/``end``) and cursor pagination are delegated to
        :class:`AuditReader`. ``limit`` is capped at ``_AUDIT_MAX_LIMIT`` to
        bound the result set. Returns ``{"entries": [...], "next_cursor":
        ...}`` where each entry is a JSON-mode ``AuditEntry`` dump.
        """
        reader = _audit_reader(request, page_size=limit)
        page = await run_in_threadpool(
            reader.read_page,
            cursor,
            agent_id=agent_id,
            source_id=source_id,
            event_type=event_type,
            start=_parse_audit_dt(start),
            end=_parse_audit_dt(end),
            sort="asc" if order == "asc" else "desc",
        )
        return {
            "entries": [e.model_dump(mode="json") for e in page.entries],
            "next_cursor": page.next_cursor,
        }

    @app.get(
        "/v1/audit/{request_id}",
        dependencies=[Depends(_read_guard)],
        tags=["audit"],
    )
    async def get_audit_entry(  # pyright: ignore[reportUnusedFunction]
        request_id: str,
        request: Request,
    ) -> dict[str, Any]:
        """Single audit-entry lookup by ``request_id`` (#32); 404 when absent.

        Scans pages from newest to oldest (the common case is a recent
        request) until the entry is found or the log is exhausted.
        """
        from fastapi import HTTPException

        reader = _audit_reader(request)
        entry = await run_in_threadpool(_find_audit_entry, reader, request_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"audit entry not found: {request_id!r}",
            )
        return entry.model_dump(mode="json")

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
