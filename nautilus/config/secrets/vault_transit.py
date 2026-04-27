"""``vault-transit://`` reference — Vault transit signing engine.

Distinct from a :class:`SecretProvider` because the private key never leaves
Vault; instead the caller asks Vault to sign a payload via
``POST /v1/transit/sign/<key>``. The resolver here simply parses the URI and
records the key name on a sentinel object that :mod:`nautilus.core.signer`
hands off to :class:`VaultTransitSignerAdapter`.

A ``vault-transit://<key-name>`` reference must NOT be passed to
:func:`nautilus.config.secrets.resolve` because it is not a value-bearing
secret; loaders that encounter the scheme should construct a signer through
:func:`build_transit_signer_ref` instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from . import register


@dataclass(frozen=True)
class TransitKeyRef:
    """Parsed ``vault-transit://<key-name>`` reference handed to the Signer."""

    scheme: ClassVar[str] = "vault-transit"
    key_name: str


def build_transit_signer_ref(ref: str) -> TransitKeyRef:
    """Parse ``vault-transit://<key>`` into a :class:`TransitKeyRef`.

    Raises:
        ValueError: when the URI is malformed or the key name is empty.
    """
    if not ref.startswith("vault-transit://"):
        raise ValueError("vault-transit:// reference required")
    key_name = ref.removeprefix("vault-transit://")
    if not key_name or "/" in key_name:
        raise ValueError("vault-transit:// key name must be a single path segment")
    return TransitKeyRef(key_name=key_name)


@register("vault-transit")
class VaultTransitSigner:
    """Stub provider — registered so URI dispatch recognises the scheme.

    Calling :meth:`get` on this provider is an error: transit references
    identify a remote signing key, not a secret value. Callers that need a
    signer should use :func:`build_transit_signer_ref` and instantiate
    :class:`nautilus.core.signer.VaultTransitSignerAdapter`.
    """

    scheme: ClassVar[str] = "vault-transit"

    async def get(self, ref: str) -> str:
        raise ValueError(
            "vault-transit:// is a signing-key reference, not a value secret;"
            " use nautilus.core.signer.VaultTransitSignerAdapter"
        )
