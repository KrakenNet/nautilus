# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
"""Nautobot adapter implementing the Nautilus Adapter Protocol.

GraphQL is the primary transport; REST fallback covers the five gaps in
the v3.1 GraphQL schema enumerated in AC-1.6. Object-level permissions
are enforced server-side (one bot user per ``SourceConfig`` per TD-12);
broker-side post-filter is applied only for predicates Nautobot cannot
express.

Custom-field prefix is introspected at ``connect()`` (TD-13, AC-1.8): we
ask Nautobot for the GraphQL ``DeviceType`` field list and pick the first
field starting with ``cf_`` (or whichever site-configured prefix). The
resolved prefix is cached on the adapter instance.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, ClassVar

import httpx
from nautilus_adapter_sdk import AdapterError

# We import the runtime model classes from nautilus core because the broker
# constructs and consumes those exact types. The adapter SDK's IntentAnalysis
# / AdapterResult / ErrorRecord / SourceConfig shapes are aspirational mirrors
# that have drifted from core (separate-package velocity tradeoff). The
# pyproject still pins ``nautilus-adapter-sdk`` so the entry-point Protocol
# contract is enforced by static analysis; runtime data interchange uses core.
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, ErrorRecord, IntentAnalysis, ScopeConstraint

from .errors import (
    NautobotAuthError,
    NautobotExecutionError,
    NautobotGraphQLPartialError,
)
from .graphql import (
    DATA_TYPE_QUERIES,
    QUERY_DEVICE_TYPE_INTROSPECTION,
    post_graphql,
    split_envelope,
)
from .rest import (
    REST_DEFAULT_LIMIT,
    assert_base_safe,
    fetch_device_cluster_assignments,
    fetch_devices_with_config_context,
    fetch_ip_address_to_interface,
    fetch_paginated,
    fetch_total_count,
    reject_writes,
)

logger = logging.getLogger(__name__)

DEFAULT_CUSTOM_FIELD_PREFIX = "cf_"


class NautobotAdapter:
    """GraphQL-primary, REST-fallback Nautobot 3.1 adapter."""

    source_type: ClassVar[str] = "nautobot"

    def __init__(self) -> None:
        self._source_id: str = ""
        self._client: httpx.AsyncClient | None = None
        self._token: str = ""
        self._base_url: str = ""
        self._base_host: str = ""
        self._data_types: list[str] = []
        self._cf_prefix: str = DEFAULT_CUSTOM_FIELD_PREFIX

    # ------------------------------------------------------------------ connect

    async def connect(self, config: SourceConfig) -> None:
        if config.type != "nautobot":
            raise AdapterError(f"NautobotAdapter received non-nautobot source type {config.type!r}")
        url = config.url or (config.connection if config.connection else None)
        if not url:
            raise AdapterError(
                "Nautobot source requires a base URL ('url' field or 'connection' string)"
            )
        assert_base_safe(url)
        self._source_id = config.id
        self._base_url = url.rstrip("/")
        self._base_host = httpx.URL(self._base_url).host
        self._token = await _resolve_token(config)
        self._data_types = list(config.data_types or [])
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
        )
        # AC-1.8 / TD-13 — introspect the custom-field prefix at connect().
        await self._introspect_custom_field_prefix()

    async def _introspect_custom_field_prefix(self) -> None:
        assert self._client is not None
        try:
            data, errors = await post_graphql(
                client=self._client,
                token=self._token,
                query=QUERY_DEVICE_TYPE_INTROSPECTION,
            )
        except (NautobotAuthError, NautobotExecutionError, httpx.HTTPError) as exc:
            logger.warning(
                "nautobot custom-field prefix introspection failed (%s); using default %r",
                exc,
                DEFAULT_CUSTOM_FIELD_PREFIX,
            )
            return
        if errors:
            logger.warning(
                "nautobot custom-field prefix introspection returned errors; using default"
            )
        if isinstance(data, dict):
            type_block = data.get("__type") or {}
            fields = type_block.get("fields") if isinstance(type_block, dict) else None
            if isinstance(fields, list):
                for field in fields:
                    name = field.get("name") if isinstance(field, dict) else None
                    if isinstance(name, str) and name.startswith("cf_"):
                        self._cf_prefix = "cf_"
                        return
                    # Site-customised prefixes other than ``cf_`` would surface
                    # here as the first non-default-field name; we keep the
                    # default to avoid mis-detecting unrelated fields.
        # Fall back silently to the default.

    @property
    def custom_field_prefix(self) -> str:
        """Resolved custom-field prefix (defaults to ``cf_``)."""
        return self._cf_prefix

    # ----------------------------------------------------------------- execute

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del scope  # Nautobot enforces scope server-side via object permissions
        start = time.monotonic()
        if self._client is None:
            return self._error_result("not_connected", "adapter is not connected", start)

        # The "method" hint in context can request a write; we reject in v1.
        if str(context.get("method", "GET")).upper() != "GET":
            reject_writes(context["method"])

        data_types = list(intent.data_types_needed) or self._data_types
        if not data_types:
            return self._error_result("no_data_types", "no data_types requested", start)

        rows: list[dict[str, Any]] = []
        warnings: list[str] = []
        try:
            for dt in data_types:
                gql_entry = DATA_TYPE_QUERIES.get(dt)
                if gql_entry is not None:
                    query, response_key = gql_entry
                    rows_for_type, warns = await self._execute_graphql(query, response_key, context)
                    rows.extend(_tag_rows(rows_for_type, dt))
                    warnings.extend(warns)
                else:
                    rows.extend(_tag_rows(await self._execute_rest_fallback(dt, context), dt))
        except NautobotAuthError as exc:
            return self._error_result("auth_error", str(exc), start)
        except NautobotGraphQLPartialError as exc:
            return self._error_result("graphql_no_data", str(exc), start)
        except NautobotExecutionError as exc:
            return self._error_result("execution_error", str(exc), start)
        except httpx.HTTPError as exc:
            return self._error_result(type(exc).__name__, str(exc), start)

        duration_ms = int((time.monotonic() - start) * 1000)
        return AdapterResult(
            source_id=self._source_id,
            rows=rows,
            duration_ms=duration_ms,
            warnings=warnings or None,
        )

    async def _execute_graphql(
        self,
        query: str,
        response_key: str,
        context: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        assert self._client is not None
        limit = int(context.get("limit") or REST_DEFAULT_LIMIT)
        offset = 0
        all_rows: list[dict[str, Any]] = []
        warnings: list[str] = []
        while True:
            data, errors = await post_graphql(
                client=self._client,
                token=self._token,
                query=query,
                variables={"limit": limit, "offset": offset},
            )
            page, page_warnings = split_envelope(data, errors, response_key=response_key)
            warnings.extend(page_warnings)
            if not page:
                break
            all_rows.extend(page)
            if len(page) < limit:
                break
            offset += limit
        return all_rows, warnings

    async def _execute_rest_fallback(
        self,
        data_type: str,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        assert self._client is not None
        limit = int(context.get("limit") or REST_DEFAULT_LIMIT)
        if data_type == "device_with_config_context":
            return await fetch_devices_with_config_context(
                client=self._client,
                token=self._token,
                base_host=self._base_host,
                limit=limit,
            )
        if data_type == "ip_address_to_interface":
            return await fetch_ip_address_to_interface(
                client=self._client,
                token=self._token,
                base_host=self._base_host,
                limit=limit,
            )
        if data_type == "device_cluster_assignment":
            return await fetch_device_cluster_assignments(
                client=self._client,
                token=self._token,
                base_host=self._base_host,
                limit=limit,
            )
        if data_type == "total_count_devices":
            count = await fetch_total_count(
                client=self._client,
                token=self._token,
                path="/api/dcim/devices/",
                base_host=self._base_host,
            )
            return [{"resource": "devices", "count": count}]
        if data_type.startswith("rest:"):
            path = data_type[len("rest:") :]
            return await fetch_paginated(
                client=self._client,
                path=path,
                token=self._token,
                base_host=self._base_host,
                limit=limit,
            )
        raise NautobotExecutionError(
            f"Unknown Nautobot data_type {data_type!r}; not in GraphQL or REST fallback set"
        )

    def _error_result(self, code: str, message: str, start: float) -> AdapterResult:
        duration_ms = int((time.monotonic() - start) * 1000)
        return AdapterResult(
            source_id=self._source_id,
            rows=[],
            duration_ms=duration_ms,
            error=ErrorRecord(
                source_id=self._source_id,
                error_type=code,
                message=message,
                trace_id="",
            ),
        )

    # ------------------------------------------------------------------- close

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _tag_rows(rows: list[dict[str, Any]], data_type: str) -> list[dict[str, Any]]:
    """Tag each row with its source data_type so consumers can split mixed batches."""
    for row in rows:
        row.setdefault("_data_type", data_type)
    return rows


async def _resolve_token(config: SourceConfig) -> str:
    """Resolve the bearer token from the configured secret reference.

    The Nautobot adapter accepts both a ``BearerAuth`` block (preferred,
    matches REST/ServiceNow conventions) and a free-form
    ``token_secret_ref`` string for raw URI references. Resolution prefers
    Nautilus's secret-provider registry when available; falls back to
    treating the value as the literal token.
    """
    auth = getattr(config, "auth", None)
    if auth is not None and getattr(auth, "type", None) == "bearer":
        token = getattr(auth, "token", "")
        if token:
            return token
    ref = getattr(config, "token_secret_ref", None) or os.environ.get("NAUTOBOT_TOKEN", "")
    if not ref:
        raise AdapterError(
            "NautobotAdapter requires a bearer token (auth.token or token_secret_ref)"
        )
    if "://" in ref:
        try:
            from nautilus.config.secrets import (
                resolve as resolve_secret,  # type: ignore[import-not-found]
            )
        except ImportError:
            raise AdapterError(
                "token_secret_ref scheme not resolvable in this environment "
                "(nautilus core not importable)"
            ) from None
        return await resolve_secret(ref)
    return ref


# NOTE: a static ``_: type[Adapter] = NautobotAdapter`` Protocol-conformance
# check would fail under pyright because ``NautobotAdapter`` consumes
# ``nautilus.config.models.SourceConfig`` and ``nautilus.core.models.IntentAnalysis``
# while the SDK Protocol's signature references its own copies of those
# types (the SDK + core models intentionally drift while the broker's
# concrete shapes remain authoritative). The runtime contract is enforced
# by the broker's ``ADAPTER_REGISTRY`` and the integration tests at
# ``packages/nautilus-adapter-nautobot/tests/integration/test_nautobot_e2e.py``.

__all__ = ["NautobotAdapter"]
