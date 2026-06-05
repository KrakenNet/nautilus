"""JWKS exporter (RFC 7517) — AC-18.c.

Mounted at ``GET /v1/keys/jwks.json`` by ``transport/fastapi_app.py``.
Excludes ``revoked`` keys that are outside the rotate-out window.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from nautilus.attestation.key_ring import KeyRing


def export_jwks(key_ring: KeyRing) -> dict[str, Any]:
    """RFC 7517 JWKS dict; one entry per active :class:`KeyEntry`.

    Emits ``kty=OKP`` + ``crv=Ed25519`` entries (Ed25519 = EdDSA family,
    per RFC 8037). Used by adapters to verify session tokens (AC-18.c).
    """
    entries: list[dict[str, Any]] = []
    for key_entry in key_ring.active():
        public_key = key_ring.load_public_key(key_entry)
        # Ed25519 public key in raw 32-byte form for OKP JWK.
        raw_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        x_b64 = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
        entries.append(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": key_entry.kid,
                "x": x_b64,
                "use": "sig",
            }
        )
    return {"keys": entries}


__all__ = ["export_jwks"]
