"""Secret-provider Protocol, registry, and async resolver (design TD-3).

Implements FR-14..FR-17 and NFR-SEC-SECRETS. Error messages MUST NOT leak full
reference paths (anything after ``://``) or upstream response bodies.
"""

from __future__ import annotations

from typing import ClassVar, Protocol, runtime_checkable


@runtime_checkable
class SecretProvider(Protocol):
    """Resolve a secret reference of the form ``<scheme>://<opaque>`` to plaintext."""

    scheme: ClassVar[str]

    async def get(self, ref: str) -> str: ...


REGISTRY: dict[str, SecretProvider] = {}


def register(scheme: str):
    """Class decorator that instantiates the provider and registers it under ``scheme``."""

    def deco(cls: type[SecretProvider]) -> type[SecretProvider]:
        REGISTRY[scheme] = cls()
        return cls

    return deco


async def resolve(ref: str) -> str:
    """Dispatch a secret-reference URI to the appropriate registered provider."""
    if "://" not in ref:
        # Truncate ref in error to avoid leaking secrets (NFR-SEC-SECRETS).
        raise ValueError(f"secret reference has no scheme: {ref[:20]!r}")
    scheme = ref.split("://", 1)[0]
    provider = REGISTRY.get(scheme)
    if provider is None:
        raise ValueError(f"unknown secret scheme: {scheme!r} (registered: {sorted(REGISTRY)})")
    return await provider.get(ref)


def has_scheme(ref: str) -> bool:
    """Return True iff ``ref`` starts with ``<scheme>://`` where ``scheme`` is registered."""
    if "://" not in ref:
        return False
    return ref.split("://", 1)[0] in REGISTRY


__all__ = ["REGISTRY", "SecretProvider", "has_scheme", "register", "resolve"]


def _load_builtin_providers() -> None:
    """Import built-in providers so their ``@register`` side effects fire."""
    from nautilus.config.secrets import env as _env  # noqa: I001, F401  # pyright: ignore[reportUnusedImport]
    from nautilus.config.secrets import vault_kv as _vault_kv  # noqa: I001, F401  # pyright: ignore[reportUnusedImport]
    from nautilus.config.secrets import vault_transit as _vault_transit  # noqa: I001, F401  # pyright: ignore[reportUnusedImport]


_load_builtin_providers()
