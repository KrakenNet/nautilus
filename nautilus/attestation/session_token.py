"""SessionTokenService — Ed25519 JWS issuance + verification (#18).

Implements AC-18.a through AC-18.g (excluding AC-18.c JWKS endpoint, which
lives in :mod:`nautilus.attestation.jwks`). The signer is **disjoint** from
Fathom's ``AttestationService`` because Fathom is single-key and cannot
satisfy AC-18.e's ≥2-active-key rotation window (see PRD Risk #5).

Reuse anchors:
- Crypto deps already present (``pyproject.toml:29-30``): ``pyjwt>=2.12.1``
  and ``cryptography>=46.0.7``.
- Header convention ``X-Nautilus-Session-Token`` mirrors ``X-API-Key``
  (``nautilus/transport/auth.py:34``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import jwt
import jwt.exceptions

from nautilus.attestation.key_ring import KeyRing


class SessionTokenError(Exception):
    """Raised by :meth:`SessionTokenService.verify` on rejection (AC-18.d).

    ``reason_code`` is one of:
    ``bad_signature | expired | unknown_kid | broker_instance_mismatch | missing``.
    """

    def __init__(self, reason_code: str, message: str = "") -> None:
        super().__init__(message or reason_code)
        self.reason_code: str = reason_code


@dataclass(frozen=True)
class SessionTokenClaims:
    """Decoded JWS body for AC-18.a fields.

    ``clearance`` is a free-form coarse string per DQ1 LOCKED (PRD AC-18.g).
    """

    session_id: str
    agent_id: str
    purpose: str
    clearance: str
    issued_at: int
    expires_at: int
    broker_instance_id: str
    kid: str


class SessionTokenService:
    """Mint + verify session-provenance JWTs (AC-18.a–g).

    Reads its key material from an injected :class:`KeyRing` so rotation
    (AC-18.e) is testable without process restart.
    """

    def __init__(
        self,
        key_ring: KeyRing,
        broker_instance_id: str,
        ttl_seconds: int = 3600,
    ) -> None:
        self._key_ring = key_ring
        self._broker_instance_id = broker_instance_id
        self._ttl_seconds = ttl_seconds

    def issue(
        self,
        *,
        session_id: str,
        agent_id: str,
        purpose: str,
        clearance: str,
    ) -> str:
        """Mint a compact JWS. Header carries ``kid``. AC-18.a + AC-18.f."""
        primary = self._key_ring.primary()
        private_key = self._key_ring.load_private_key(primary)
        now = int(time.time())
        payload = {
            "session_id": session_id,
            "agent_id": agent_id,
            "purpose": purpose,
            "clearance": clearance,
            "issued_at": now,
            "expires_at": now + self._ttl_seconds,
            "broker_instance_id": self._broker_instance_id,
            "kid": primary.kid,
        }
        token: str = jwt.encode(
            payload,
            private_key,  # type: ignore[arg-type]
            algorithm="EdDSA",
            headers={"kid": primary.kid},
        )
        return token

    def verify(self, token: str) -> SessionTokenClaims:
        """Return claims on success; raise :class:`SessionTokenError` on failure.

        Failure ``reason_code`` ∈ ``{bad_signature, expired, unknown_kid,
        broker_instance_mismatch, missing}`` per AC-18.d.
        """
        if not token:
            raise SessionTokenError("missing", "No token provided")

        # Peek at the header to get the kid before full verification.
        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise SessionTokenError("bad_signature", "Cannot decode token header") from exc

        kid = header.get("kid")
        if not kid:
            raise SessionTokenError("unknown_kid", "Token header missing kid")

        entry = self._key_ring.verifier_for(kid)
        if entry is None:
            raise SessionTokenError("unknown_kid", f"Unknown kid: {kid!r}")

        public_key = self._key_ring.load_public_key(entry)

        try:
            payload = jwt.decode(
                token,
                public_key,  # type: ignore[arg-type]
                algorithms=["EdDSA"],
                options={"verify_exp": False},  # We check expires_at manually below.
            )
        except jwt.exceptions.InvalidSignatureError as exc:
            raise SessionTokenError("bad_signature", "Invalid signature") from exc
        except Exception as exc:
            raise SessionTokenError("bad_signature", "Token decode failed") from exc

        # Manual expiry check using our custom expires_at claim.
        expires_at = payload.get("expires_at", 0)
        if int(time.time()) > expires_at:
            raise SessionTokenError("expired", "Token has expired")

        # Broker instance check.
        broker_instance_id = payload.get("broker_instance_id", "")
        if broker_instance_id != self._broker_instance_id:
            raise SessionTokenError(
                "broker_instance_mismatch",
                f"Token issued for {broker_instance_id!r}, not {self._broker_instance_id!r}",
            )

        return SessionTokenClaims(
            session_id=payload["session_id"],
            agent_id=payload["agent_id"],
            purpose=payload["purpose"],
            clearance=payload["clearance"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            broker_instance_id=payload["broker_instance_id"],
            kid=kid,
        )


__all__ = ["SessionTokenClaims", "SessionTokenError", "SessionTokenService"]
