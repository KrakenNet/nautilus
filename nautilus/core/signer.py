# pyright: reportArgumentType=false
"""Async signing primitives for session-signed LLM responses (Tasks 34-36).

Two implementations of the :class:`Signer` Protocol:

1. :class:`InProcessEd25519Signer` — dev / test path. Loads a 32-byte hex seed
   from configuration into a PyCA :class:`Ed25519PrivateKey`. Failures here
   are programming bugs, never transients, so there is no circuit breaker.
2. :class:`VaultTransitSignerAdapter` — prod path. Sends the SHA-512 pre-hash
   of the payload to Vault transit; the private key never leaves Vault.
   Wrapped by :class:`~nautilus.core.circuit_breaker.CircuitBreaker` so a
   sustained outage opens the breaker and fails fast with HTTP 503.

The :func:`_build_dsse_envelope` helper canonicalises a payload via RFC 8785
(JCS) and produces the on-the-wire DSSE envelope (TD-6).

Failure semantics (NFR-SEC-SIGN, AC-5.12):
- In-process: bad seed → :class:`ValueError` at construction; never reaches
  ``connect()``.
- Vault transit 5xx → counted as a breaker failure; after ``failure_threshold``
  consecutive failures the breaker opens for ``reset_timeout`` seconds.
- Vault transit 404 (key not found) → fatal :class:`RuntimeError`, NOT counted
  toward the breaker — a config bug must not eventually trip the breaker.
- Breaker open → :class:`~nautilus.core.circuit_breaker.CircuitOpenError`,
  surfaced by :class:`~nautilus.adapters.llm.LLMAdapter` as an
  ``AdapterExecutionError`` and ultimately HTTP 503 by the broker. **Never
  return an unsigned response.**
"""

from __future__ import annotations

import base64
import hashlib
from typing import Protocol, runtime_checkable

import httpx
import rfc8785
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nautilus.core.circuit_breaker import CircuitBreaker

DSSE_PAYLOAD_TYPE = "application/vnd.nautilus.signed-session+json"


@runtime_checkable
class Signer(Protocol):
    """Async signer producing 64-byte Ed25519 signatures."""

    keyid: str

    async def sign(self, payload: bytes) -> bytes: ...


class InProcessEd25519Signer:
    """Dev / test signer backed by a 32-byte hex seed loaded from config.

    A bad seed (wrong length, non-hex) raises :class:`ValueError` at
    construction, ensuring the adapter never passes ``connect()`` readiness
    checks. There is intentionally no circuit breaker: in-process signing
    failures are programming bugs and must surface immediately.
    """

    def __init__(self, seed_hex: str, keyid: str) -> None:
        if not keyid:
            raise ValueError("keyid is required for an Ed25519 signer")
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError as exc:
            raise ValueError(f"signing seed is not valid hex: {exc}") from exc
        if len(seed) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes (64 hex chars); got {len(seed)} bytes")
        try:
            self._priv = Ed25519PrivateKey.from_private_bytes(seed)
        except (InvalidKey, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError(f"failed to load Ed25519 private key: {exc}") from exc
        self.keyid = keyid

    async def sign(self, payload: bytes) -> bytes:
        return self._priv.sign(payload)


class VaultTransitSignerAdapter:
    """Prod signer that delegates to Vault's transit signing engine.

    Wraps :class:`~nautilus.core.circuit_breaker.CircuitBreaker` so that a
    sustained Vault outage opens the breaker and short-circuits subsequent
    sign attempts with :class:`CircuitOpenError`. ``key_not_found`` (HTTP 404)
    is treated as a fatal config error and is **not** counted toward the
    breaker threshold (AC-5.12).
    """

    def __init__(
        self,
        *,
        key_name: str,
        vault_addr: str,
        vault_token: str,
        breaker: CircuitBreaker,
        keyid: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not key_name:
            raise ValueError("vault transit key_name is required")
        self._key_name = key_name
        self._vault_addr = vault_addr.rstrip("/")
        self._vault_token = vault_token
        self._breaker = breaker
        self._timeout = timeout_seconds
        self.keyid = keyid

    async def sign(self, payload: bytes) -> bytes:
        pre_hash = hashlib.sha512(payload).digest()
        url = f"{self._vault_addr}/v1/transit/sign/{self._key_name}"
        body = {
            "input": base64.b64encode(pre_hash).decode("ascii"),
            "hash_algorithm": "sha2-512",
            "prehashed": True,
        }
        async with self._breaker:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    url,
                    headers={"X-Vault-Token": self._vault_token},
                    json=body,
                )
            if response.status_code == 404:
                # Fatal config error — propagate without breaker accounting.
                raise RuntimeError(f"vault transit key not found: {self._key_name!r}") from None
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # Re-raise with body redacted; status code only.
                redacted = httpx.HTTPStatusError(
                    f"vault transit signing failed: HTTP {response.status_code}",
                    request=exc.request,
                    response=exc.response,
                )
                # Keep the original exception's response object, but our message
                # never exposes the response body.
                raise redacted from None
            sig_field = response.json().get("data", {}).get("signature", "")
        if not isinstance(sig_field, str) or not sig_field.startswith("vault:v1:"):
            raise RuntimeError("vault transit response missing 'vault:v1:' signature")
        sig_b64 = sig_field.removeprefix("vault:v1:")
        try:
            sig = base64.b64decode(sig_b64)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise RuntimeError("vault transit signature was not base64") from exc
        if len(sig) != 64:
            raise RuntimeError(
                f"vault transit returned {len(sig)}-byte signature; expected 64 (Ed25519)"
            )
        return sig


def _b64url_nopad(raw: bytes) -> str:
    """RFC 4648 base64url WITHOUT trailing ``=`` padding (DSSE convention)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


async def _build_dsse_envelope(payload: dict[str, object], signer: Signer) -> dict[str, object]:
    """Canonicalise ``payload`` via RFC 8785 (JCS), sign the raw bytes, return DSSE.

    The signature covers the raw canonical bytes — never the base64url text —
    so verifiers re-encode after canonicalising and compare bytes for bytes
    without re-running JCS (TD-6).
    """
    canonical = rfc8785.dumps(payload)
    sig = await signer.sign(canonical)
    return {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": _b64url_nopad(canonical),
        "signatures": [
            {"keyid": signer.keyid, "sig": _b64url_nopad(sig)},
        ],
    }


__all__ = [
    "DSSE_PAYLOAD_TYPE",
    "InProcessEd25519Signer",
    "Signer",
    "VaultTransitSignerAdapter",
    "_build_dsse_envelope",
]
