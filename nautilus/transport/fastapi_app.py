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
- ``GET /healthz`` — 200 liveness probe naming the build (AC-12.4); no broker.
- ``GET /readyz`` — 200 iff startup finished AND the session store's
  ``aget('_ready_probe_')`` succeeds; else 503 (AC-12.5).
- ``POST /v1/rkm/queue`` — submit a rule; validates and queues a proposal.
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

Everything except the probes, ``GET /v1/keys/jwks.json`` (a public key by
definition) and ``GET /metrics`` is gated on :func:`nautilus.transport.auth.require_api_key`
when ``config.api.auth.mode == "api_key"`` (default, D-11) and on
:func:`proxy_trust_dependency` when the mode is ``"proxy_trust"``. That
includes the RKM queue and rule-governance routes: ``X-Nautilus-Reviewer``
names a reviewer, it does not authenticate one, so it is not a credential.
Probes are never gated — they must work during unauthenticated rolling
restarts.

``tests/unit/transport/test_route_auth_coverage.py`` enumerates the route
table and fails on any new route that is neither gated nor in its explicit
public allowlist; add routes there deliberately, not by omission.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from fastapi import Depends, FastAPI, Query, Request, Response, status
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp

from nautilus import __version__
from nautilus.attestation.jwks import export_jwks
from nautilus.attestation.key_ring import KeyRing
from nautilus.attestation.session_token import SessionTokenError, SessionTokenService
from nautilus.core import BrokerBusyError, PurposeNotPermittedError, SessionNotOwnedError
from nautilus.core.broker import Broker
from nautilus.core.metrics import register_rkm_queue, register_ruleset
from nautilus.core.models import BrokerRequest, BrokerResponse
from nautilus.transport.auth import (
    SESSION_TOKEN_HEADER,
    api_key_header,
    caller_identity,
    capability_refusal,
    proxy_trust_dependency,
    verify_api_key,
    verify_session_token,
)
from nautilus.ui import create_admin_router
from nautilus.ui.audit_reader import AuditReader
from nautilus.ui.dependencies import get_auth_user

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


log = logging.getLogger(__name__)

_READY_PROBE_KEY = "_ready_probe_"

# kids are ``str(uuid.uuid4())`` at generation (key_ring._generate_entry);
# validating the path segment keeps arbitrary caller bytes out of audit
# trace strings (#25 security review I1).
_KID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _clean_identity(value: Any) -> str:
    """Strip + reject control characters in reviewer/reason fields (#25 I1).

    Returns the cleaned string, or ``""`` when the value is missing or
    contains control characters — callers treat ``""`` as a 400.
    """
    text = str(value or "").strip()
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        return ""
    return text


# Hard cap on /v1/audit page size — bounds result set for SIEM / dashboard
# pulls regardless of caller-supplied ``limit`` (#32 acceptance: bounded
# result set size).
_AUDIT_MAX_LIMIT = 500
_AUDIT_DEFAULT_LIMIT = 50


def _resolve_auth_config(broker: Broker | None) -> tuple[str, list[Any], list[str]]:
    """Extract ``(mode, keys, trusted_proxies)`` from the broker's config.

    Looked up defensively via ``getattr`` so a test that injects a mock broker
    without a full :class:`NautilusConfig` still boots.

    ``keys`` comes back as the operator wrote it — bare strings, structured
    :class:`~nautilus.config.models.ApiKeyEntry` records, or a mix. Flattening
    to ``str`` here is what made every key a root key: the ``agent_id`` and
    ``capabilities`` a structured entry carries never reached the guard.

    Returns:
        Tuple of ``(mode, keys, trusted_proxies)``. ``mode`` defaults to
        ``"api_key"``; ``keys`` defaults to ``[]`` (which forces fail-closed
        401 under :func:`verify_api_key`); ``trusted_proxies`` is the peer
        allow-list :func:`proxy_trust_dependency` checks the socket against.
    """
    if broker is None:
        return ("api_key", [], [])
    api_cfg = getattr(broker, "_config", None)
    api_cfg = getattr(api_cfg, "api", None) if api_cfg is not None else None
    auth_obj = getattr(api_cfg, "auth", None)
    mode_raw = getattr(auth_obj, "mode", None) if auth_obj is not None else None
    mode = mode_raw if mode_raw in ("api_key", "proxy_trust") else "api_key"
    keys_raw: object = getattr(api_cfg, "keys", None)
    keys: list[Any] = list(cast("list[Any]", keys_raw)) if isinstance(keys_raw, list) else []
    proxies_raw: object = getattr(auth_obj, "trusted_proxies", None)
    proxies: list[str] = []
    if isinstance(proxies_raw, list):
        for entry in proxies_raw:  # pyright: ignore[reportUnknownVariableType]
            proxies.append(str(entry))  # pyright: ignore[reportUnknownArgumentType]
    return (mode, keys, proxies)


def _resolve_agent_subjects(broker: Broker | None) -> dict[str, str]:
    """Map ``agents.<id>.subject`` to the agent id, for ``proxy_trust``.

    Empty when no agent declares a subject, which leaves the forwarded identity
    bound to nothing and the request routed on its own ``agent_id`` — the
    behaviour every existing deployment has.
    """
    config = getattr(broker, "_config", None) if broker is not None else None
    agents: object = getattr(config, "agents", None)
    if not isinstance(agents, dict):
        return {}
    subjects: dict[str, str] = {}
    for agent_id, record in cast("dict[str, object]", agents).items():
        subject = getattr(record, "subject", None)
        if isinstance(subject, str) and subject:
            subjects[subject] = str(agent_id)
    return subjects


def _warn_about_unbound_keys(keys: list[Any], auth_mode: str = "api_key") -> None:
    """Say once, at startup, which keys are bound to nothing.

    A bare-string key is root: it may ask as any agent and call every
    governance route. That is the historical behaviour and it keeps working —
    silence about it is the part that does not.
    """
    if not keys and auth_mode == "api_key":
        # Empty fails closed, which is right, and silent, which is not: the
        # server starts clean, /healthz says 200, and every route that reads
        # data answers 401 with nothing anywhere saying why.
        log.warning(
            "api.keys is empty, so every data and governance route will answer "
            "401 Not authenticated. Only /healthz, /readyz and /metrics are "
            "reachable. Add a key under 'api: keys:' — 'nautilus init' writes "
            "one for you."
        )
        return
    bare = [i for i, entry in enumerate(keys) if isinstance(entry, str)]
    if bare:
        log.warning(
            "api.keys%s %s a bare string: bound to no agent_id, so it can ask as "
            "any agent and call every governance route. Use the "
            "{key, agent_id, capabilities} form to scope it.",
            f"[{bare[0]}]" if len(bare) == 1 else str(bare),
            "is" if len(bare) == 1 else "are",
        )


def _find_audit_entry(reader: AuditReader, request_id: str) -> Any:
    """Page through the audit log (newest-first) for ``request_id``.

    Returns the matching ``AuditEntry`` or ``None``. Cursor pagination
    keeps memory bounded on GB-sized logs; the loop terminates when the
    reader stops handing back a ``next_cursor``.
    """
    return reader.find_entry(request_id)


def _ui_enabled(config_path: str | Path | None, existing_broker: Broker | None) -> bool:
    """Whether to register the admin console's routes at all.

    Routes are registered when the app is built and the broker is built in the
    lifespan, so this reads the config a second time rather than waiting for
    one. A config that will not load is not this function's problem — the
    lifespan raises on it a moment later — so an unreadable one answers False
    and the console stays shut.
    """
    if existing_broker is not None:
        ui = getattr(getattr(existing_broker, "config", None), "ui", None)
        return bool(getattr(ui, "enabled", False))
    from nautilus.config.loader import load_config

    try:
        return bool(load_config(str(config_path)).ui.enabled)
    except Exception:
        return False


class BodyTooLargeError(Exception):
    """A request body ran past ``api.max_request_bytes`` mid-read."""


class _BodySizeLimit:
    """Refuse a request body larger than ``max_bytes``.

    There was no body limit anywhere -- uvicorn applies none -- and the audit
    entry stores the raw intent three times, so one authenticated ``query`` key
    could drive tens of MB/s onto the audit volume. That volume is the
    fail-closed path: ``/readyz`` reports 503 when ``audit_logger.probe()``
    complains, so filling it drains every replica rather than degrading one.

    Two checks, because they cover different callers. ``Content-Length`` is
    answered before a byte is read, which is every ordinary client. A client
    that sends no length (chunked) is counted as it streams and the read is
    aborted past the bound -- less graceful, deliberately so.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        declared = _declared_length(scope)
        if declared is not None and declared > self.max_bytes:
            await _send_too_large(send, declared, self.max_bytes)
            return

        seen = 0

        async def counted() -> Any:
            nonlocal seen
            message = await receive()
            if message.get("type") == "http.request":
                seen += len(message.get("body", b"") or b"")
                if seen > self.max_bytes:
                    raise BodyTooLargeError(
                        f"request body exceeded api.max_request_bytes ({self.max_bytes} bytes)"
                    )
            return message

        await self.app(scope, counted, send)


def _declared_length(scope: Any) -> int | None:
    """``Content-Length`` as an int, or ``None`` when absent or unparseable."""
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _send_too_large(send: Any, declared: int, limit: int) -> None:
    body = json.dumps(
        {
            "detail": (
                f"Request body is {declared} bytes; this broker accepts at most "
                f"{limit} (api.max_request_bytes)."
            )
        }
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status.HTTP_413_CONTENT_TOO_LARGE,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# Probes and the scrape endpoint are never gated: a full request queue must not
# take the pod out of rotation, which would turn saturation into a restart loop.
# How long /readyz waits on the session store before calling it not ready.
# Kubernetes probes default to a 1s timeout; anything past this is already
# a failed probe, so the only thing a longer wait buys is a stuck handler.
_READY_PROBE_TIMEOUT_S: float = 2.0

_UNGATED_PATHS = frozenset({"/healthz", "/readyz", "/metrics"})


class _ConcurrencyLimit:
    """Refuse past ``max_in_flight`` rather than grow the queue behind it.

    Throughput is flat from 1 concurrent client to 512 -- the per-request work
    is dominated by synchronous CPU on one event loop -- so offered concurrency
    buys latency, not rate: 12 ms at 1 client, 8470 ms at 512, with every
    request still returning 200, some after 17 seconds. A load balancer or
    agent framework in front of that has no way to tell a saturated broker from
    a healthy one, so it retries, and the retries join the same queue.

    503 + ``Retry-After`` is the signal that was missing. It is deliberately
    not 429: the caller did nothing wrong and the same request will work.
    """

    def __init__(self, app: ASGIApp, max_in_flight: int) -> None:
        self.app = app
        self.max_in_flight = max_in_flight
        self._semaphore = asyncio.Semaphore(max_in_flight)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path") in _UNGATED_PATHS:
            await self.app(scope, receive, send)
            return
        if self._semaphore.locked():
            await _send_busy(send, self.max_in_flight)
            return
        async with self._semaphore:
            await self.app(scope, receive, send)


async def _send_busy(send: Any, limit: int) -> None:
    body = json.dumps(
        {
            "detail": (
                f"Broker busy: {limit} requests are already in flight "
                f"(api.max_concurrent_requests). Retry."
            )
        }
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status.HTTP_503_SERVICE_UNAVAILABLE,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"retry-after", b"1"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# The console's own assets: htmx, the stylesheet, the favicon. Public bytes with
# no caller in them, served by Starlette's ``StaticFiles``, which already emits
# ``etag`` and ``last-modified`` -- so a shared cache stores them and revalidates
# them correctly on its own. This is the only prefix on the surface where
# caching is a win, so it is the only exemption.
_CACHEABLE_PREFIX = "/admin/static/"


class _CacheControl:
    """Deny-by-default ``Cache-Control``, because absence means *cacheable*.

    A 200 with no ``Cache-Control`` is heuristically cacheable (RFC 9111
    §4.2.2): a shared cache -- a CDN, a corporate forward proxy, a sidecar --
    may store it and hand it to the next caller. Measured against nginx with a
    URI-only cache key, ``GET /v1/audit`` went MISS then HIT, and the third
    request, carrying no credential at all, was answered from the cache with
    94 838 bytes of the decision trail. The broker had refused that caller
    correctly; nothing in the response it had already sent told the cache so.

    So the default is ``no-store`` and it is the *default*, not a route list:
    a route added next month is covered without anyone remembering to add it.

    Two exemptions, each earned:

    - ``/admin/static/`` (see :data:`_CACHEABLE_PREFIX`) is left alone.
    - :data:`_UNGATED_PATHS` -- ``/healthz``, ``/readyz``, ``/metrics`` -- get
      ``no-cache``, not ``no-store``. They hold nothing about a caller, so
      forbidding storage is over-broad; but each answers a question about a
      live process, and a cached ``readyz: ok`` from a draining pod or a
      flat-lined scrape is a wrong answer, not a stale one. ``no-cache``
      permits the copy and forbids serving it without revalidating.

    Nothing else is set. ``Pragma: no-cache`` is an HTTP/1.0 *request* header
    (RFC 9111 §5.4) that no 1.1 cache reads off a response, ``Expires: 0`` is
    overridden by ``Cache-Control`` wherever both appear, and ``Vary`` has
    nothing to key on once the response may not be stored.

    A handler that set the header itself wins: ``sse_starlette`` marks its own
    ``EventSourceResponse``, and a handler that thought about this knows more
    than the middleware does.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        path = scope.get("path", "")
        if scope.get("type") != "http" or path.startswith(_CACHEABLE_PREFIX):
            await self.app(scope, receive, send)
            return
        directive = b"no-cache" if path in _UNGATED_PATHS else b"no-store"

        async def stamped(message: Any) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                if not any(name.lower() == b"cache-control" for name, _ in headers):
                    headers.append((b"cache-control", directive))
                    message["headers"] = headers
            await send(message)

        await self.app(scope, receive, stamped)


def _max_request_bytes(
    config_path: str | Path | None, existing_broker: Broker | None
) -> int | None:
    """``api.max_request_bytes``, read the same way ``ui.enabled`` is.

    Middleware is installed when the app is built and the broker is not built
    until lifespan, so the config is read a second time here.
    """
    if existing_broker is not None:
        api = getattr(getattr(existing_broker, "config", None), "api", None)
        return getattr(api, "max_request_bytes", None)
    from nautilus.config.loader import load_config

    try:
        return load_config(str(config_path)).api.max_request_bytes
    except Exception:
        return None


def _max_concurrent_requests(
    config_path: str | Path | None, existing_broker: Broker | None
) -> int | None:
    """``api.max_concurrent_requests``, read the same way as the byte limit."""
    if existing_broker is not None:
        api = getattr(getattr(existing_broker, "config", None), "api", None)
        return getattr(api, "max_concurrent_requests", None)
    from nautilus.config.loader import load_config

    try:
        return load_config(str(config_path)).api.max_concurrent_requests
    except Exception:
        return None


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
    ui_enabled = _ui_enabled(config_path, existing_broker)
    max_request_bytes = _max_request_bytes(config_path, existing_broker)
    max_concurrent_requests = _max_concurrent_requests(config_path, existing_broker)

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
        mode, keys, trusted_proxies = _resolve_auth_config(broker)
        app.state.auth_mode = mode
        app.state.api_keys = keys
        app.state.trusted_proxies = trusted_proxies
        app.state.agent_subjects = _resolve_agent_subjects(broker)
        _warn_about_unbound_keys(keys, mode)
        # Key ring for session-token endpoints (AC-18.a–g). Reuse the
        # broker's ring when session tokens are enabled — the ring is
        # in-memory, so a separate transport-level instance could never
        # verify broker-minted tokens. Falls back to a standalone ring
        # (legacy behaviour) when the broker has none. The isinstance
        # guards keep mock-broker tests (MagicMock attrs) on the fallback.
        broker_ring = getattr(broker, "key_ring", None)
        app.state.key_ring = broker_ring if isinstance(broker_ring, KeyRing) else KeyRing()
        broker_iid = getattr(broker, "instance_id", None)
        app.state.broker_instance_id = broker_iid if isinstance(broker_iid, str) else "default"
        app.state.ready = True
        # Wire Prometheus RKM queue collector (AC-35.9.f).
        register_rkm_queue(lambda: getattr(app.state, "proposal_queue", None))
        # Name the policy this replica loaded, so a fleet mid-rollout can be
        # told apart from one running a single ruleset.
        register_ruleset(lambda: getattr(getattr(app.state, "broker", None), "ruleset_hash", None))
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
        version=__version__,
        lifespan=lifespan,
    )
    if max_request_bytes is not None:
        app.add_middleware(_BodySizeLimit, max_bytes=max_request_bytes)
    if max_concurrent_requests is not None:
        app.add_middleware(_ConcurrencyLimit, max_in_flight=max_concurrent_requests)
    # Added last, so it is outermost: the 413 and the 503 the two middlewares
    # above write themselves are responses too, and a cache that stored the
    # busy signal would serve it to everyone.
    app.add_middleware(_CacheControl)
    # Pre-populate defaults so routes don't AttributeError before lifespan
    # fires (e.g. startup-phase health checks during ASGI boot).
    app.state.broker = None
    app.state.auth_mode = "api_key"
    app.state.api_keys = []
    app.state.trusted_proxies = []
    app.state.agent_subjects = {}
    app.state.ready = False

    # ------------------------------------------------------------------
    # Auth dependency — resolved at request time so tests that mutate
    # ``app.state.auth_mode`` between requests get the new behaviour.
    # ------------------------------------------------------------------

    def _caller_identity(request: Request) -> dict[str, Any]:
        """This app's auth mode and key registry, then the shared derivation."""
        state = request.app.state
        return caller_identity(
            request,
            auth_mode=getattr(state, "auth_mode", "api_key"),
            keys=list(getattr(state, "api_keys", []) or []),
            agent_subjects=dict(getattr(state, "agent_subjects", {}) or {}),
        )

    def _require_capability(capability: str) -> Any:
        """Dependency: refuse a credential that does not hold ``capability``.

        Listed *after* the auth guard on every route that uses it, so an
        unauthenticated caller still gets 401 rather than 403. A bare-string key
        holds everything, which is why this changes nothing for the configs that
        do not opt in.
        """

        async def dependency(request: Request) -> None:
            from fastapi import HTTPException

            refusal = capability_refusal(_caller_identity(request), capability)
            if refusal is not None:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=refusal)

        return dependency

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
        """Shared body of ``/v1/request`` and ``/v1/query``.

        Both routes list ``verify_session_token`` in ``dependencies``: its
        docstring promised a 401 for a present-but-invalid
        ``X-Nautilus-Session-Token`` (AC-18.d) that nothing was wired to
        produce, so the header was declared, documented as verified, and read
        by nobody.
        """
        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:  # pragma: no cover — lifespan guards this.
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        # A header-borne token reaches the broker on the same channel as a
        # body-borne one, so the session binding it carries actually applies
        # (the broker re-verifies and lets the token's ``session_id`` override
        # the declared one). The body wins if a caller sends both.
        caller = _caller_identity(request)
        bound: str | None = caller["agent_id"]
        if bound is not None and bound != body.agent_id:
            # The key proved which agent is calling; the body asked as another.
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This credential is bound to agent_id={bound!r}, "
                    f"so it cannot ask as {body.agent_id!r}"
                ),
            )
        context = dict(body.context)
        header_token = request.headers.get(SESSION_TOKEN_HEADER)
        if header_token and "session_token" not in context:
            context["session_token"] = header_token
        try:
            return await broker.arequest(
                body.agent_id,
                body.intent,
                context,
                caller=caller,
                # Declared on ``BrokerRequest`` and therefore in the OpenAPI
                # schema. Dropping it here made REST return ``null`` where the
                # library echoes the caller's value back (US-6 / FR-62).
                fact_set_hash=body.fact_set_hash,
            )
        except BrokerBusyError as exc:
            # Backpressure, not failure: either the caller's own earlier request
            # still holds the exposure ledger, or the store is slow. A 500 says
            # "something broke"; this says "come back", which is the only thing
            # a client can act on.
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
                headers={"Retry-After": "1"},
            ) from exc
        except SessionNotOwnedError as exc:
            # The credential is real; the session it named is not its own.
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            ) from exc
        except SessionTokenError as exc:
            # A rejected token is a rejected credential wherever it was carried.
            # ``verify_session_token`` already answers 401 for the header; a
            # caller that put the same token in ``context`` got a 500, so the
            # status reported which field was used rather than what was wrong,
            # and every refused credential looked like a Nautilus fault.
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid session token ({exc.reason_code}): {exc}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        except OSError as exc:
            # The audit sink stopped accepting writes mid-request. Failing
            # closed is right — an unrecorded decision must not be served — but
            # this is our recorder being down, not a bad request, and the
            # caller's only useful move is to retry once /readyz clears. It
            # already reports the same sink, so the pod drains on its own.
            from fastapi import HTTPException

            log.error("audit write failed, refusing the request: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"Nautilus could not record this request and will not "
                    f"serve what it cannot account for: {exc}"
                ),
                headers={"Retry-After": "5"},
            ) from exc
        except ValueError as exc:
            # Malformed caller input inside ``context`` — notably
            # ``scope_constraints`` — which used to leave here as a 500.
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    # ------------------------------------------------------------------
    # Route registrations
    # ------------------------------------------------------------------

    @app.post(
        "/v1/request",
        response_model=BrokerResponse,
        dependencies=[
            Depends(_write_guard),
            Depends(_require_capability("query")),
            Depends(verify_session_token),
        ],
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
        dependencies=[
            Depends(_write_guard),
            Depends(_require_capability("query")),
            Depends(verify_session_token),
        ],
        tags=["broker"],
    )
    async def post_query(  # pyright: ignore[reportUnusedFunction]
        body: BrokerRequest,
        request: Request,
    ) -> BrokerResponse:
        """Literal alias of ``/v1/request`` (D-9 / UQ-3)."""
        return await _handle_request(body, request)

    @app.get(
        "/v1/sources",
        dependencies=[Depends(_write_guard), Depends(_require_capability("query"))],
        tags=["broker"],
    )
    async def get_sources(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> dict[str, list[dict[str, Any]]]:
        """Metadata-only source listing (AC-12.3 — no DSN / credentials).

        Filtered by the caller's clearance: a source's description and data
        types are what you need to ask for it, so listing one an agent can
        never reach hands it the map. A bare key has no bound agent and sees
        everything, as it does everywhere else.
        """
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
                    # The purposes this source accepts. Omitting it left a
                    # caller refused on purpose with no way to learn the
                    # vocabulary: it is the operator's own metadata, not a
                    # credential, and it is the difference between a dead end
                    # and a retry.
                    "allowed_purposes": list(s.allowed_purposes or []),
                }
                for s in broker.sources_visible_to(_caller_identity(request)["agent_id"])
            ],
        }

    @app.get("/healthz", tags=["probes"])
    async def healthz() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        """Liveness — AC-12.4 (no broker dependency) — and which build answered."""
        return {"status": "ok", "version": __version__}

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
        # The audit sink is checked first: an entry is written before any
        # request answers, so a sink that has stopped accepting writes fails
        # every request, and the probe that exists to drain a pod said ok.
        audit_logger: Any = getattr(broker, "audit_logger", None)
        audit_problem = audit_logger.probe() if audit_logger is not None else None
        if audit_problem is not None:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "not_ready", "reason": audit_problem}
        store: Any = getattr(broker, "session_store", None)
        if store is None:
            # Broker without an exposed session_store still counts as ready
            # (the probe is best-effort — AC-12.5).
            return {"status": "ok"}
        try:
            if hasattr(store, "aget"):
                # Bounded, because a store that is *down* answers fast and a
                # store that is reachable but frozen does not answer at all:
                # ``acquire_timeout_s`` covers taking a new pooled connection,
                # and the sentinel read runs on one that is already open. An
                # unbounded probe is a probe the kubelet gives up on, so the pod
                # is never drained and every probe leaves a wedged handler.
                await asyncio.wait_for(store.aget(_READY_PROBE_KEY), _READY_PROBE_TIMEOUT_S)
            elif hasattr(store, "get"):
                store.get(_READY_PROBE_KEY)
            # The schema stamp is checked at boot, which covers the replica
            # coming up and misses the one already serving: a rolling upgrade
            # migrates the shared store under every pod that has not been
            # replaced yet. Re-reading it here drains this pod instead of
            # letting it read-modify-write rows it does not understand.
            verify: Any = getattr(store, "averify_schema", None)
            if callable(verify):
                probe: Any = verify()
                await asyncio.wait_for(probe, _READY_PROBE_TIMEOUT_S)
        except TimeoutError:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "not_ready", "reason": "session_store_timeout"}
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

    @app.post(
        "/v1/sessions",
        tags=["attestation"],
        dependencies=[Depends(_write_guard), Depends(_require_capability("query"))],
    )
    async def post_sessions(  # pyright: ignore[reportUnusedFunction]
        body: dict[str, Any],
        request: Request,
    ) -> dict[str, Any]:
        """Issue a session token (AC-18.a). Body: session_id, agent_id, purpose.

        Auth-gated (#18 security review): an unauthenticated caller must not
        be able to mint broker-valid tokens bound to arbitrary agent/session
        ids — that would bypass the session-pinning property entirely.

        Authentication was the half that shipped. A credential bound to one
        agent could still mint for another, and ``clearance`` was taken from
        the body and signed verbatim: a key bound to ``intern`` minted
        ``{agent_id: cleared, clearance: top-secret}``, which verifies against
        the deliberately-unauthenticated JWKS and which Nautilus forwards
        downstream as ``X-Nautilus-Session-Token``. The binding is now checked
        here and the clearance comes from the AgentRegistry inside
        :meth:`Broker.issue_session_token`; ``body["clearance"]`` is ignored.
        """
        caller = _caller_identity(request)
        bound: str | None = caller.get("agent_id")
        requested_agent = str(body.get("agent_id", ""))
        if bound is not None and bound != requested_agent:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This credential is bound to agent_id={bound!r}, so it cannot "
                    f"mint a session token for {requested_agent!r}"
                ),
            )
        key_ring: KeyRing | None = getattr(request.app.state, "key_ring", None)
        if key_ring is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Key ring not ready",
            )
        broker_instance_id: str = getattr(request.app.state, "broker_instance_id", "default")
        service = SessionTokenService(key_ring=key_ring, broker_instance_id=broker_instance_id)
        # AC-18.f — issue through the broker when its token service is live so
        # the ``session_token_issued`` audit event lands in the JSONL stream.
        # The isinstance guard keeps mock-broker tests on the unaudited path.
        broker: Broker | None = getattr(request.app.state, "broker", None)
        broker_service = getattr(broker, "session_tokens", None) if broker is not None else None
        if isinstance(broker_service, SessionTokenService):
            service = broker_service
            assert broker is not None  # noqa: S101 — broker_service implies broker
            try:
                token = broker.issue_session_token(
                    session_id=body.get("session_id", ""),
                    agent_id=requested_agent,
                    purpose=body.get("purpose", ""),
                )
            except PurposeNotPermittedError as exc:
                from fastapi import HTTPException

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
                ) from exc
        else:
            # No broker to read a registry from (mock-broker tests). Signing an
            # empty clearance is the honest answer; the caller's is never it.
            token = service.issue(
                session_id=body.get("session_id", ""),
                agent_id=requested_agent,
                purpose=body.get("purpose", ""),
                clearance="",
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

    @app.post(
        "/v1/keys/rotate",
        tags=["attestation"],
        dependencies=[Depends(_write_guard), Depends(_require_capability("keys"))],
    )
    async def post_keys_rotate(  # pyright: ignore[reportUnusedFunction]
        body: dict[str, Any],
        request: Request,
    ) -> dict[str, Any]:
        """Rotate the live broker's session-token signing key (#25).

        Body: ``{"reviewer": "<operator identity>"}`` (required). The old
        primary moves to rotating-out (grace window — in-flight tokens keep
        verifying and are lazily re-signed); close the window via
        ``POST /v1/keys/{kid}/revoke``. 409 when session tokens are disabled.
        """
        from fastapi import HTTPException

        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        reviewer = _clean_identity(body.get("reviewer"))
        if not reviewer:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="reviewer is required (no control characters)",
            )
        try:
            new_kid = broker.rotate_signing_key(reviewer=reviewer)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return {"new_primary_kid": new_kid, "reviewer": reviewer}

    @app.post(
        "/v1/keys/{kid}/revoke",
        tags=["attestation"],
        dependencies=[Depends(_write_guard), Depends(_require_capability("keys"))],
    )
    async def post_keys_revoke(  # pyright: ignore[reportUnusedFunction]
        kid: str,
        body: dict[str, Any],
        request: Request,
    ) -> dict[str, Any]:
        """Revoke a signing key on the live broker (#25) — ends the grace window.

        Body: ``{"reviewer": "...", "reason": "..."}`` (both required).
        404 for unknown kid; 409 when session tokens are disabled.
        """
        from fastapi import HTTPException

        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        # kids are uuid4 strings at generation; reject anything else before
        # it reaches audit trace strings (security review I1).
        if not _KID_PATTERN.fullmatch(kid):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="kid must be a UUID",
            )
        reviewer = _clean_identity(body.get("reviewer"))
        reason = _clean_identity(body.get("reason"))
        if not reviewer or not reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="reviewer and reason are required (no control characters)",
            )
        try:
            broker.revoke_signing_key(kid, reason=reason, reviewer=reviewer)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            # Refusing to revoke the current primary (rotate first).
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"kid {kid!r} not found",
            ) from exc
        return {"revoked_kid": kid, "reviewer": reviewer, "reason": reason}

    # ------------------------------------------------------------------
    # Adapter schema endpoint (AC-21.a)
    # ------------------------------------------------------------------

    @app.get(
        "/v1/adapters",
        dependencies=[Depends(_write_guard), Depends(_require_capability("query"))],
        tags=["adapters"],
    )
    async def get_adapters(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> dict[str, list[dict[str, str]]]:
        """Adapters and their live status in *this* process.

        ``nautilus adapters list --url`` reads this. Quarantine state is
        in-memory and per-process, so it cannot be answered by rebuilding a
        broker from the config file -- which is what the CLI used to do, and
        why ``adapters list --status quarantined`` always reported nothing.
        """
        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            return {"adapters": []}
        quarantined: set[str] = getattr(broker, "_quarantined_adapters", set())
        return {
            "adapters": [
                {
                    "id": source.id,
                    "type": source.type,
                    "status": "quarantined" if source.id in quarantined else "active",
                }
                for source in broker.sources
            ],
        }

    @app.get(
        "/v1/adapters/{name}/schema",
        dependencies=[Depends(_write_guard), Depends(_require_capability("query"))],
        tags=["adapters"],
    )
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
        except NotImplementedError as exc:
            # The 501 above is unreachable: ``BaseAdapter`` *defines*
            # ``get_schema`` and raises here, so ``hasattr`` is true for every
            # adapter and an unimplemented one arrived as 503 "Schema fetch
            # failed" -- a transient-looking answer to a permanent condition,
            # which is a caller retrying forever. The hasattr branch stays for a
            # duck-typed object that has no such attribute at all.
            from fastapi import HTTPException

            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail=f"Adapter '{name}' does not support schema introspection",
            ) from exc
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

    def _get_audit_logger(request: Request) -> Any:
        """The serving broker's audit sink, or ``None`` when no broker is bound.

        Governance decisions over REST used to pass ``audit_logger=None``, so
        an approval that the docs said "lands in the audit trail" wrote
        nothing at all.
        """
        broker = getattr(request.app.state, "broker", None)
        return None if broker is None else broker.audit_logger

    def _get_router(request: Request) -> Any:
        """The serving broker's live ``FathomRouter``, or ``None``.

        Approval used to pass ``router=None`` here, so nothing was ever
        promoted: the response said ``promoted: false``, the proposal stayed
        ``approved`` and the rule never reached the engine -- with a live
        router sitting on ``app.state.broker`` the whole time.
        """
        broker = getattr(request.app.state, "broker", None)
        return None if broker is None else broker._router  # noqa: SLF001

    def _require_reviewer(request: Request) -> str:
        """Who is recorded as having decided this proposal (AC-35.9.d / DQ4).

        A credential bound to an agent *is* the reviewer: ``X-Nautilus-Reviewer``
        names a reviewer, it does not authenticate one (its own module docstring
        says so), so it cannot be the identity written into a lineage record
        when a better one is available. It stays required for the unbound
        bare-key path, where there is nothing else to derive.
        """
        from fastapi import HTTPException

        bound: str | None = _caller_identity(request)["agent_id"]
        if bound:
            return bound
        reviewer = request.headers.get("X-Nautilus-Reviewer") or request.headers.get("X-Reviewer")
        if not reviewer:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="X-Nautilus-Reviewer header required",
            )
        return reviewer

    @app.post(
        "/v1/rkm/queue",
        dependencies=[Depends(_write_guard), Depends(_require_capability("govern"))],
        tags=["rkm"],
        status_code=status.HTTP_201_CREATED,
    )
    async def post_rkm_queue(  # pyright: ignore[reportUnusedFunction]
        request: Request,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """Submit a rule for validation and queue the resulting proposal.

        The review queue had no producer anywhere in shipped code:
        ``run_pipeline`` was called only from tests, there was no route and no
        CLI subcommand, and the system-proposed path ships disabled. Every
        queue subcommand, every REST route below, lineage, rollback and the
        queue metrics collector were therefore dead in practice.

        Body: ``{"rule_yaml": "<contents of the rule file>"}``.
        """
        import uuid as _uuid
        from pathlib import Path as _Path

        from fastapi import HTTPException

        from nautilus.rkm.validator.pipeline import run_pipeline

        rule_yaml = body.get("rule_yaml")
        if not isinstance(rule_yaml, str) or not rule_yaml.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="body must carry 'rule_yaml': the contents of the rule file",
            )

        queue = _get_queue(request)
        # The proposal artifact references the rule by path, so the submitted
        # YAML has to outlive the request that carried it.
        rules_dir = _Path(queue._queue_dir) / "rules"  # noqa: SLF001
        rules_dir.mkdir(parents=True, exist_ok=True)
        rule_path = rules_dir / f"{_uuid.uuid4().hex}.yaml"
        rule_path.write_text(rule_yaml, encoding="utf-8")

        broker = getattr(request.app.state, "broker", None)
        if broker is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        audit_log = getattr(broker, "audit_path", None) or _Path("audit.jsonl")
        config = getattr(broker, "config", None)
        settings: dict[str, Any] = {}
        if config is not None:
            settings = {
                "min_entries": config.rkm.sandbox.min_entries,
                "rule_packs": list(config.rules.packs),
            }
        # The broker's own logger, not a second one over the same path: under
        # ``audit.chained`` the log is a hash chain with a single writer, and
        # a second sink here corrupted it beyond repair.
        proposal = run_pipeline(
            rule_path,
            queue=queue,
            audit_log=audit_log,
            audit_logger=broker.audit_logger,
            **settings,
        )
        return {
            "proposal_id": proposal.proposal_id,
            "status": proposal.status,
            "confidence": proposal.validation.get("confidence", 0.0),
            "static_ok": proposal.validation.get("static_ok"),
            "static_errors": proposal.validation.get("static_errors", []),
            "shadow_flags": list(proposal.shadow_flags),
            "sandbox": proposal.validation.get("sandbox", {}),
        }

    @app.get(
        "/v1/rkm/queue",
        dependencies=[Depends(_write_guard), Depends(_require_capability("govern"))],
        tags=["rkm"],
    )
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

    @app.get(
        "/v1/rkm/queue/{proposal_id}",
        dependencies=[Depends(_write_guard), Depends(_require_capability("govern"))],
        tags=["rkm"],
    )
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
                detail=f"proposal {proposal_id!r} not found",
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
            # AC-35.9.c calls these the sandbox's top triggers; the key was
            # ``top_replayed``, which nothing has ever written.
            "top_triggers": proposal.validation.get("sandbox", {}).get("top_triggers", []),
        }

    @app.post(
        "/v1/rkm/queue/{proposal_id}/approve",
        dependencies=[Depends(_write_guard), Depends(_require_capability("govern"))],
        tags=["rkm"],
    )
    async def post_rkm_approve(  # pyright: ignore[reportUnusedFunction]
        proposal_id: str,
        request: Request,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Approve a pending proposal (AC-35.9.d). Requires X-Nautilus-Reviewer."""
        import dataclasses

        from fastapi import HTTPException

        from nautilus.rkm.review import (
            AlreadyDecidedError,
            PromotionFailedError,
            approve_proposal,
        )

        reviewer = _require_reviewer(request)
        queue = _get_queue(request)
        lineage = _get_lineage(request)
        try:
            result = approve_proposal(
                proposal_id,
                reviewer,
                queue=queue,
                lineage=lineage,
                router=_get_router(request),
                audit_logger=_get_audit_logger(request),
            )
        except KeyError as exc:
            # ``str(KeyError("p-1"))`` is ``"'p-1'"`` -- quotes included, no
            # words. The 404 body was the id the caller already sent, wrapped in
            # apostrophes, saying nothing about what was not found.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"proposal {proposal_id!r} not found",
            ) from exc
        except AlreadyDecidedError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "already_decided", "current_status": exc.current_status},
            ) from exc
        except PromotionFailedError as exc:
            # The rule did not compile. That is the reviewer's to fix, and they
            # cannot fix what a 500 will not tell them. The proposal is left in
            # ``approved`` on purpose -- re-approving retries the promotion --
            # so the response says that too, or the state looks like a dead end.
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "error": "promotion_failed",
                    "message": str(exc),
                    "current_status": "approved",
                    "recovery": (
                        "fix the rule and re-approve to retry the promotion, "
                        "or reject the proposal"
                    ),
                },
            ) from exc
        return dataclasses.asdict(result)

    @app.post(
        "/v1/rkm/queue/{proposal_id}/reject",
        dependencies=[Depends(_write_guard), Depends(_require_capability("govern"))],
        tags=["rkm"],
    )
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
                audit_logger=_get_audit_logger(request),
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"proposal {proposal_id!r} not found",
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

    @app.get(
        "/v1/rules",
        dependencies=[Depends(_write_guard), Depends(_require_capability("query"))],
        tags=["rules"],
    )
    async def get_rules_in_force(  # pyright: ignore[reportUnusedFunction]
        request: Request,
    ) -> dict[str, Any]:
        """Every rule the running engine will fire, plus the ruleset identity.

        Built-ins, user rules and pack rules alike. ``ruleset_hash`` is the
        same value each audit entry records, so a deployment can be compared
        against the policy an operator believes it is running — and against
        the entries it produced.
        """
        from fastapi import HTTPException

        broker: Broker | None = getattr(request.app.state, "broker", None)
        if broker is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Broker not ready",
            )
        return {"ruleset_hash": broker.ruleset_hash, "rules": broker.rules_in_force()}

    @app.get(
        "/v1/rules/{rule_name}/lineage",
        dependencies=[Depends(_write_guard), Depends(_require_capability("govern"))],
        tags=["rules"],
    )
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
                detail=f"rule {rule_name!r} not found",
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

    @app.post(
        "/v1/rules/{rule_name}/retract",
        dependencies=[Depends(_write_guard), Depends(_require_capability("govern"))],
        tags=["rules"],
    )
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
                    detail=f"rule {rule_name!r} not found",
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
                audit_logger=_get_audit_logger(request),
            )
        except KeyError as exc:
            # The version is what is missing when the caller named one, and the
            # message that came through ``str(exc)`` said so -- wrapped in a
            # second layer of quotes by ``KeyError.__str__``. Keep the version,
            # drop the quoting, and match the shape ``rollback`` already uses.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"rule {rule_name!r} version {version} not found",
            ) from exc

        # Lineage says the rule is retired; the engine is what decides
        # requests. Retraction used to stop at the ledger, so a rule an
        # operator had been told was gone kept firing until the next restart.
        router = _get_router(request)
        engine_result: dict[str, bool] = (
            router.retract_rule(rule_name)
            if router is not None
            else {"engine_updated": False, "persisted": False}
        )
        if engine_result["engine_updated"] and not engine_result["persisted"]:
            note = (
                "removed from the running engine; its YAML is not in "
                "rules.user_rules_dirs, so a restart reloads it"
            )
        elif engine_result["engine_updated"]:
            note = "removed from the running engine and from its rule file"
        else:
            note = "the rule was not in force; only the lineage record changed"
        return {
            "rule_name": rule_name,
            "version": version,
            "affected_descendants": affected,
            "engine_updated": engine_result["engine_updated"],
            "engine_note": note,
        }

    @app.post(
        "/v1/rules/{rule_name}/rollback",
        dependencies=[Depends(_write_guard), Depends(_require_capability("govern"))],
        tags=["rules"],
    )
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

        from nautilus.rkm.review import rollback_rule

        try:
            result = rollback_rule(
                rule_name,
                to_version=to_version,
                reason=str(parsed_body.get("reason", "")),
                reviewer=reviewer,
                lineage=lineage,
                audit_logger=_get_audit_logger(request),
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"rule {rule_name!r} version {to_version} not found",
            ) from exc

        restored = lineage.get(rule_name, version=result.new_version)
        d = dataclasses.asdict(restored) if restored is not None else {}
        if restored is not None:
            d["promoted_at"] = restored.promoted_at.isoformat()
        return {
            "rule_name": rule_name,
            "rolled_back_from_version": to_version,
            "new_version": result.new_version,
            # A lineage record carries no rule text, so there is nothing to
            # reload: the running engine keeps deciding with the newer rule.
            # Saying so is the difference between a ledger entry and a deploy.
            "engine_updated": False,
            "engine_note": (
                "lineage only: the restored version's rule text is not stored, so the "
                "running engine still has the newer rule. Re-submit it through the RKM "
                "queue, or restart against the rule files you want in force."
            ),
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
        # Mirror nautilus.ui.dependencies.get_audit_path — the resolved path the
        # broker writes to, not the raw config string, which is relative to the
        # process cwd rather than to the config directory.
        resolved = broker.audit_path
        audit_path = str(resolved) if resolved is not None else str(broker.config.audit.path)
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
        dependencies=[Depends(_read_guard), Depends(_require_capability("audit_read"))],
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
        dependencies=[Depends(_read_guard), Depends(_require_capability("audit_read"))],
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
                detail=f"audit entry {request_id!r} not found",
            )
        return entry.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Root redirect — / → /admin
    # ------------------------------------------------------------------

    @app.get("/", include_in_schema=False)
    async def root_redirect() -> Response:  # pyright: ignore[reportUnusedFunction]
        """Send a browser to the console, and everyone else somewhere real.

        This route is registered unconditionally but ``/admin`` is mounted only
        when ``ui.enabled`` is true -- and it is false by default. The redirect
        used to be unconditional, so the first thing anyone does with a fresh
        deployment, curl its root, landed on ``/admin``: a 404 here, and on
        releases up to 0.2.5 (which mount the console unconditionally too) a
        ``401 Not authenticated`` after ``curl -L`` follows it. Neither answers
        "what is this". When the console is off, answer with the routes that do
        exist -- and see ``/healthz`` for the build.
        """
        from fastapi.responses import JSONResponse, RedirectResponse

        if ui_enabled:
            return RedirectResponse(url="/admin", status_code=302)
        return JSONResponse(
            {
                "service": "nautilus",
                "version": __version__,
                "admin_console": "disabled (set ui.enabled: true to serve /admin)",
                "routes": {
                    "openapi": "/docs",
                    "liveness": "/healthz",
                    "readiness": "/readyz",
                    "metrics": "/metrics",
                    "request": "POST /v1/request",
                    "sources": "/v1/sources",
                },
            }
        )

    # ------------------------------------------------------------------
    # Admin UI — operator-facing dashboard (FR-1, AC-1.1)
    # ------------------------------------------------------------------

    # Off unless the config asks for it. The console is a second front door to
    # the same broker, and not registering its routes is the difference between
    # a 404 and a login prompt on a port the operator did not know served one.
    if ui_enabled:
        app.include_router(create_admin_router())

        _ui_static_dir = Path(__file__).resolve().parent.parent / "ui" / "static"
        app.mount(
            "/admin/static",
            StaticFiles(directory=str(_ui_static_dir)),
            name="admin-static",
        )

    return app


__all__ = ["create_app"]
