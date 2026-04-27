"""Unit tests for the secret-provider Protocol, registry, EnvProvider (Task 4),
and the Vault KV / transit providers (Task 33)."""

from __future__ import annotations

import httpx
import pytest
import respx

from nautilus.config.secrets import REGISTRY, has_scheme, resolve
from nautilus.config.secrets.vault_transit import (
    TransitKeyRef,
    build_transit_signer_ref,
)

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_env_provider_resolves_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NAUTILUS_TEST_FOO", "hello-world")
    assert await resolve("env://NAUTILUS_TEST_FOO") == "hello-world"


@pytest.mark.asyncio
async def test_env_provider_missing_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NAUTILUS_TEST_MISSING", raising=False)
    with pytest.raises(ValueError) as excinfo:
        await resolve("env://NAUTILUS_TEST_MISSING")
    msg = str(excinfo.value)
    assert "NAUTILUS_TEST_MISSING" in msg
    # NFR-SEC-SECRETS: must not echo the full ref URI.
    assert "env://NAUTILUS_TEST_MISSING" not in msg


@pytest.mark.asyncio
async def test_env_provider_empty_var_name() -> None:
    with pytest.raises(ValueError, match="missing variable name"):
        await resolve("env://")


@pytest.mark.asyncio
async def test_unknown_scheme_raises_with_registered_list() -> None:
    with pytest.raises(ValueError) as excinfo:
        await resolve("unknown-scheme://anything")
    msg = str(excinfo.value)
    assert "unknown-scheme" in msg
    assert "env" in msg  # registered list should mention known providers


@pytest.mark.asyncio
async def test_resolve_rejects_ref_without_scheme() -> None:
    with pytest.raises(ValueError, match="no scheme"):
        await resolve("plain-string-no-scheme")


def test_has_scheme_matrix() -> None:
    assert has_scheme("env://FOO") is True
    assert has_scheme("plain string") is False
    assert has_scheme("unknown://x") is False
    assert has_scheme("") is False


def test_env_provider_registered() -> None:
    assert "env" in REGISTRY


# ---------------------------------------------------------------------------
# Task 33 — Vault KV provider.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vault_kv_provider_resolves_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-token")
    with respx.mock(base_url="https://vault.example.com") as router:
        router.get("/v1/secret/data/nautobot").mock(
            return_value=httpx.Response(
                200,
                json={"data": {"data": {"token": "abc-123"}, "metadata": {}}},
            )
        )
        result = await resolve("vault://secret/data/nautobot#token")
    assert result == "abc-123"


@pytest.mark.asyncio
async def test_vault_kv_provider_404_redacts_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-token")
    with respx.mock(base_url="https://vault.example.com") as router:
        router.get("/v1/secret/data/missing").mock(return_value=httpx.Response(404, json={}))
        with pytest.raises(ValueError) as excinfo:
            await resolve("vault://secret/data/missing#password")
    msg = str(excinfo.value)
    # NFR-SEC-SECRETS: the field selector must NOT appear in the error message.
    assert "password" not in msg
    assert "missing" in msg


@pytest.mark.asyncio
async def test_vault_kv_provider_500_does_not_leak_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("VAULT_TOKEN", "s.test-token")
    with respx.mock(base_url="https://vault.example.com") as router:
        router.get("/v1/secret/data/foo").mock(
            return_value=httpx.Response(500, text="Vault internal error: leaked stack trace")
        )
        with pytest.raises(ValueError) as excinfo:
            await resolve("vault://secret/data/foo#password")
    msg = str(excinfo.value)
    assert "leaked stack trace" not in msg
    assert "password" not in msg
    assert "500" in msg


@pytest.mark.asyncio
async def test_vault_kv_provider_missing_addr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.setenv("VAULT_TOKEN", "s.test-token")
    with pytest.raises(ValueError, match="VAULT_ADDR"):
        await resolve("vault://secret/data/foo#bar")


@pytest.mark.asyncio
async def test_vault_kv_provider_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises(ValueError) as excinfo:
        await resolve("vault://secret/data/foo#bar")
    # The token value must never appear; the var name is fine.
    assert "VAULT_TOKEN" in str(excinfo.value)


@pytest.mark.asyncio
async def test_vault_kv_provider_rejects_missing_field() -> None:
    with pytest.raises(ValueError, match="missing '#field'"):
        await resolve("vault://secret/data/foo")


# ---------------------------------------------------------------------------
# Task 33 — Vault transit provider (signing-key reference parser only).
# ---------------------------------------------------------------------------


def test_vault_transit_parses_key_name() -> None:
    parsed = build_transit_signer_ref("vault-transit://nautilus-session-prod")
    assert isinstance(parsed, TransitKeyRef)
    assert parsed.key_name == "nautilus-session-prod"


def test_vault_transit_rejects_path_separator() -> None:
    with pytest.raises(ValueError, match="single path segment"):
        build_transit_signer_ref("vault-transit://nautilus/with/slash")


def test_vault_transit_rejects_empty_key() -> None:
    with pytest.raises(ValueError, match="single path segment"):
        build_transit_signer_ref("vault-transit://")


@pytest.mark.asyncio
async def test_vault_transit_resolve_is_error() -> None:
    """resolve() on vault-transit must reject; the value is a key, not a secret."""
    with pytest.raises(ValueError, match="signing-key reference"):
        await resolve("vault-transit://nautilus-session-prod")


def test_vault_providers_registered() -> None:
    assert "vault" in REGISTRY
    assert "vault-transit" in REGISTRY
