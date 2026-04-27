# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
"""Nautobot GraphQL query builders + ``{data, errors}`` envelope handling.

Only the read paths needed for the Nautilus data-types Nautobot supports:
``device``, ``interface``, ``ipam`` (prefixes + ip_addresses), and
``config_context``. The Nautobot 3.x GraphQL schema renamed the polymorphic
filter from ``_type`` (v2) to ``type`` (v3); we never emit ``_type``.

Custom-field selections are added at runtime when the adapter detects a
prefix via :meth:`NautobotAdapter._introspect_custom_field_prefix` (TD-13).
"""

from __future__ import annotations

from typing import Any

import httpx

from .errors import (
    NautobotAuthError,
    NautobotExecutionError,
    NautobotGraphQLPartialError,
)

# Pure-string queries — no f-string interpolation of attacker input. All
# variable values flow through ``variables`` so injection is impossible.
QUERY_DEVICES = """
query Devices($limit: Int!, $offset: Int!) {
  devices(limit: $limit, offset: $offset) {
    id
    name
    serial
    status { name }
    role { name }
    device_type { model }
  }
}
""".strip()

QUERY_INTERFACES = """
query Interfaces($limit: Int!, $offset: Int!) {
  interfaces(limit: $limit, offset: $offset) {
    id
    name
    enabled
    type
    mac_address
    device { id name }
  }
}
""".strip()

QUERY_PREFIXES = """
query Prefixes($limit: Int!, $offset: Int!) {
  prefixes(limit: $limit, offset: $offset) {
    id
    prefix
    status { name }
    role { name }
    description
  }
}
""".strip()

QUERY_IP_ADDRESSES = """
query IPAddresses($limit: Int!, $offset: Int!) {
  ip_addresses(limit: $limit, offset: $offset) {
    id
    address
    status { name }
    dns_name
    description
  }
}
""".strip()

QUERY_CONFIG_CONTEXTS = """
query ConfigContexts($limit: Int!, $offset: Int!) {
  config_contexts(limit: $limit, offset: $offset) {
    id
    name
    weight
    description
    is_active
  }
}
""".strip()

QUERY_DEVICE_TYPE_INTROSPECTION = """
query DeviceTypeIntrospection {
  __type(name: "DeviceType") {
    fields { name }
  }
}
""".strip()


# Map ``data_types`` literal -> (graphql_query, response_key, label).
DATA_TYPE_QUERIES: dict[str, tuple[str, str]] = {
    "device": (QUERY_DEVICES, "devices"),
    "interface": (QUERY_INTERFACES, "interfaces"),
    "ipam_prefix": (QUERY_PREFIXES, "prefixes"),
    "ipam_ip": (QUERY_IP_ADDRESSES, "ip_addresses"),
    "config_context": (QUERY_CONFIG_CONTEXTS, "config_contexts"),
}


async def post_graphql(
    *,
    client: httpx.AsyncClient,
    token: str,
    query: str,
    variables: dict[str, Any] | None = None,
) -> tuple[Any, list[Any]]:
    """POST ``query`` with ``variables`` and unpack the ``{data, errors}`` envelope.

    Returns ``(data, errors)`` where ``data`` may be ``None`` (errors-only
    response). Callers branch on the combination per AC-1.11.

    Raises:
        NautobotAuthError: HTTP 403/401 outside the GraphQL envelope.
        NautobotExecutionError: HTTP 5xx after retries (handled by caller's
            retry layer, not here) or a malformed response shape.
    """
    response = await client.post(
        "/api/graphql/",
        headers={
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
        },
        json={"query": query, "variables": variables or {}},
    )
    if response.status_code in (401, 403):
        raise NautobotAuthError(
            f"Nautobot rejected GraphQL request: HTTP {response.status_code}",
            kind="forbidden" if response.status_code == 403 else "missing_token",
        )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise NautobotExecutionError("Nautobot GraphQL response was not a JSON object")
    data = payload.get("data")
    errors = payload.get("errors") or []
    if not isinstance(errors, list):
        errors = [errors]
    return data, errors


def split_envelope(
    data: Any, errors: list[Any], *, response_key: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Project ``data[response_key]`` to a row list and surface errors as warnings.

    Returns ``(rows, warnings)`` and raises :class:`NautobotGraphQLPartialError`
    when ``errors`` is non-empty AND ``data`` is ``None`` / missing
    (no usable rows).
    """
    if data is None:
        if errors:
            raise NautobotGraphQLPartialError(
                f"Nautobot GraphQL returned errors and no data: {_render_errors(errors)}"
            )
        return [], []
    rows = data.get(response_key) if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return [], _render_warning_list(errors)
    return rows, _render_warning_list(errors)


def _render_errors(errors: list[Any]) -> str:
    parts = []
    for err in errors[:5]:
        if isinstance(err, dict):
            parts.append(str(err.get("message") or err))
        else:
            parts.append(str(err))
    return "; ".join(parts)


def _render_warning_list(errors: list[Any]) -> list[str]:
    return [_render_errors([e]) for e in errors] if errors else []


__all__ = [
    "DATA_TYPE_QUERIES",
    "QUERY_CONFIG_CONTEXTS",
    "QUERY_DEVICES",
    "QUERY_DEVICE_TYPE_INTROSPECTION",
    "QUERY_INTERFACES",
    "QUERY_IP_ADDRESSES",
    "QUERY_PREFIXES",
    "post_graphql",
    "split_envelope",
]
