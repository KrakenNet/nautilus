# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false
"""``vault://`` secret provider — Vault KV v2 path resolution.

Reference shape: ``vault://<path>#<field>`` where ``<path>`` is the Vault KV v2
mount-relative path (e.g. ``secret/data/nautobot``) and ``<field>`` is the JSON
key under ``data.data`` to project.

Vault server URL is read from the ``VAULT_ADDR`` env var; the auth token from
``VAULT_TOKEN``. Both must be set when this provider is exercised. Missing env
gives a :class:`ValueError` with a path-redacted message (NFR-SEC-SECRETS).

Failure messages MUST NOT contain anything after ``#`` (the field selector
identifies the secret) or any portion of the upstream Vault response body.
"""

from __future__ import annotations

import os
from typing import ClassVar
from urllib.parse import urlsplit

import httpx

from . import register


def _redact_ref(ref: str) -> str:
    """Drop the ``#field`` portion so error messages never leak the field name."""
    base, _, _ = ref.partition("#")
    return base


@register("vault")
class VaultKVProvider:
    """Resolve ``vault://<path>#<field>`` against the Vault KV v2 engine.

    The provider hits ``GET {VAULT_ADDR}/v1/<path>`` with header
    ``X-Vault-Token: <VAULT_TOKEN>``, then projects ``data.data.<field>``.
    """

    scheme: ClassVar[str] = "vault"

    async def get(self, ref: str) -> str:
        if not ref.startswith("vault://"):
            raise ValueError("VaultKVProvider received non-vault ref")
        rest = ref.removeprefix("vault://")
        if "#" not in rest:
            raise ValueError("vault:// reference missing '#field' selector")
        path, _, field = rest.partition("#")
        if not path or not field:
            raise ValueError("vault:// reference must be 'vault://<path>#<field>'")

        vault_addr = os.environ.get("VAULT_ADDR")
        vault_token = os.environ.get("VAULT_TOKEN")
        if not vault_addr:
            raise ValueError("VAULT_ADDR not set; cannot resolve vault:// reference")
        if not vault_token:
            # Token contents must never appear in error messages.
            raise ValueError("VAULT_TOKEN not set; cannot resolve vault:// reference")

        # Defensive: never follow an attacker-controlled VAULT_ADDR scheme outside http(s).
        scheme = urlsplit(vault_addr).scheme
        if scheme not in {"http", "https"}:
            raise ValueError("VAULT_ADDR must be http(s); refusing to dispatch")

        url = f"{vault_addr.rstrip('/')}/v1/{path}"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url, headers={"X-Vault-Token": vault_token})
        except httpx.HTTPError as exc:
            # Hide URL so neither path nor host leaks beyond the scheme.
            raise ValueError(
                f"vault kv resolution failed: {scheme}://<vault>: {type(exc).__name__}"
            ) from exc

        if response.status_code == 404:
            raise ValueError(f"vault kv path not found: {_redact_ref(ref)!r}")
        if response.status_code != 200:
            # Status only — never the body (NFR-SEC-SECRETS).
            raise ValueError(
                f"vault kv resolution failed: HTTP {response.status_code} for {_redact_ref(ref)!r}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise ValueError("vault kv response was not JSON") from exc

        # KV v2 envelope: {"data": {"data": {field: ...}, "metadata": {...}}}.
        data = payload.get("data", {}).get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict) or field not in data:
            raise ValueError(f"vault kv field missing for {_redact_ref(ref)!r}")
        value = data[field]
        if not isinstance(value, str):
            raise ValueError(f"vault kv field is not a string for {_redact_ref(ref)!r}")
        return value
