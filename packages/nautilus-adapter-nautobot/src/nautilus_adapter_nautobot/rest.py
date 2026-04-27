"""REST fallback paths for the Nautobot adapter (AC-1.6, AC-1.10, NFR-SSRF).

Five GraphQL gaps in v3.1 force a REST fallback:

1. Writes (rejected v1) — :class:`NautobotUnsupportedOperation`.
2. Total-count pagination metadata (``count`` field at the list endpoint).
3. ``?include=config_context`` — needed when callers want the resolved
   context attached to each device in a single round trip.
4. IP-to-interface M2M retrieval via ``/api/ipam/ip-address-to-interface/``
   (the GraphQL schema does not expose this junction table directly).
5. Device-cluster assignments via ``/api/dcim/device-cluster-assignments/``
   — ``Device.clusters`` is a v3 M2M (was a FK in v2).

Pagination uses offset/limit with ``limit=500`` default and iterates until
an empty page is returned (AC-1.10). Every REST call sends the v3.1
``Accept: application/json; version=3.1`` header (AC-1.4).
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

import httpx
from nautilus_adapter_sdk import enforce_no_cross_host_redirect, reject_private_ip_literal

from .errors import NautobotAuthError, NautobotExecutionError, NautobotUnsupportedOperation

logger = logging.getLogger(__name__)

REST_DEFAULT_LIMIT = 500
RETRY_MAX_ATTEMPTS = 3
RETRY_BASE_BACKOFF = 0.2

ACCEPT_HEADER = "application/json; version=3.1"


def reject_writes(method: str) -> None:
    """Reject any non-GET method at the REST boundary (AC-1.6 v1 scope)."""
    if method.upper() != "GET":
        raise NautobotUnsupportedOperation(
            f"Nautobot adapter v1 is read-only; refusing {method.upper()}"
        )


async def fetch_paginated(
    *,
    client: httpx.AsyncClient,
    path: str,
    token: str,
    base_host: str,
    limit: int = REST_DEFAULT_LIMIT,
    extra_params: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Iterate ``offset`` until an empty page is returned (AC-1.10)."""
    rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        params: dict[str, str] = {"limit": str(limit), "offset": str(offset)}
        if extra_params:
            params.update(extra_params)
        response = await _get_with_retry(
            client=client,
            path=path,
            token=token,
            params=params,
            base_host=base_host,
        )
        page = response.json()
        results = (
            page.get("results")
            if isinstance(page, dict)
            else page
            if isinstance(page, list)
            else None
        )
        if not isinstance(results, list) or not results:
            break
        rows.extend(results)
        if len(results) < limit:
            break
        offset += limit
    return rows


async def fetch_total_count(
    *,
    client: httpx.AsyncClient,
    path: str,
    token: str,
    base_host: str,
) -> int | None:
    """REST list endpoints expose a top-level ``count`` field (AC-1.6 case b)."""
    response = await _get_with_retry(
        client=client,
        path=path,
        token=token,
        params={"limit": "1", "offset": "0"},
        base_host=base_host,
    )
    body = response.json()
    if isinstance(body, dict):
        count = body.get("count")
        if isinstance(count, int):
            return count
    return None


async def fetch_ip_address_to_interface(
    *,
    client: httpx.AsyncClient,
    token: str,
    base_host: str,
    limit: int = REST_DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    """``/api/ipam/ip-address-to-interface/`` — v3 IP↔interface M2M (AC-1.6 case d)."""
    return await fetch_paginated(
        client=client,
        path="/api/ipam/ip-address-to-interface/",
        token=token,
        base_host=base_host,
        limit=limit,
    )


async def fetch_device_cluster_assignments(
    *,
    client: httpx.AsyncClient,
    token: str,
    base_host: str,
    limit: int = REST_DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    """``/api/dcim/device-cluster-assignments/`` — v3 ``Device.clusters`` M2M (AC-1.7)."""
    return await fetch_paginated(
        client=client,
        path="/api/dcim/device-cluster-assignments/",
        token=token,
        base_host=base_host,
        limit=limit,
    )


async def fetch_devices_with_config_context(
    *,
    client: httpx.AsyncClient,
    token: str,
    base_host: str,
    limit: int = REST_DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    """REST devices list with the resolved config context attached (AC-1.6 case c)."""
    return await fetch_paginated(
        client=client,
        path="/api/dcim/devices/",
        token=token,
        base_host=base_host,
        limit=limit,
        extra_params={"include": "config_context"},
    )


def assert_base_safe(base_url: str) -> None:
    """SSRF guard at connect() — refuse loopback / private / link-local IPs."""
    reject_private_ip_literal(base_url)


async def _get_with_retry(
    *,
    client: httpx.AsyncClient,
    path: str,
    token: str,
    params: dict[str, str],
    base_host: str,
) -> httpx.Response:
    """``GET path`` with exponential-backoff retry on 5xx (AC-1.11)."""
    headers = {
        "Authorization": f"Token {token}",
        "Accept": ACCEPT_HEADER,
    }
    last_exc: Exception | None = None
    for attempt in range(RETRY_MAX_ATTEMPTS):
        try:
            response = await client.get(path, params=params, headers=headers)
        except httpx.HTTPError as exc:
            last_exc = exc
            await _sleep_with_jitter(attempt)
            continue
        enforce_no_cross_host_redirect(response, base_host)
        if response.status_code in (401, 403):
            raise NautobotAuthError(
                f"Nautobot rejected REST request: HTTP {response.status_code}",
                kind="forbidden" if response.status_code == 403 else "missing_token",
            )
        if 500 <= response.status_code < 600:
            last_exc = httpx.HTTPStatusError(
                f"HTTP {response.status_code}", request=response.request, response=response
            )
            await _sleep_with_jitter(attempt)
            continue
        response.raise_for_status()
        return response
    raise NautobotExecutionError(
        f"Nautobot REST {path} failed after {RETRY_MAX_ATTEMPTS} attempts: {last_exc}"
    )


async def _sleep_with_jitter(attempt: int) -> None:
    backoff = RETRY_BASE_BACKOFF * (2**attempt)
    jitter = random.uniform(0.0, backoff * 0.25)
    await asyncio.sleep(backoff + jitter)


__all__ = [
    "ACCEPT_HEADER",
    "REST_DEFAULT_LIMIT",
    "RETRY_MAX_ATTEMPTS",
    "assert_base_safe",
    "fetch_device_cluster_assignments",
    "fetch_devices_with_config_context",
    "fetch_ip_address_to_interface",
    "fetch_paginated",
    "fetch_total_count",
    "reject_writes",
]
