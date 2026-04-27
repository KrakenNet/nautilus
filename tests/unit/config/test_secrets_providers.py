"""Unit tests for the secret-provider Protocol, registry, and EnvProvider (Task 4)."""

from __future__ import annotations

import pytest

from nautilus.config.secrets import REGISTRY, has_scheme, resolve

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


# Parameterized placeholders for Task 33 (vault providers). Un-skip when landing.
@pytest.mark.skip(reason="Task 33 lands vault providers")
@pytest.mark.parametrize("scheme", ["vault", "vault-transit"])
async def test_vault_provider_stub(scheme: str) -> None:
    ref = f"{scheme}://secret/data/foo#password"
    await resolve(ref)
