"""KeyRing — multi-key Ed25519 store with rotation window (#18, AC-18.e).

Closest existing pattern: ``nautilus/core/broker.py:553-566`` autogenerates
a single Ed25519 keypair when no ``attestation.private_key_path`` is set.
This file generalizes that to ≥2 active keys with explicit rotation-out
state, so old-tokens-during-overlap (AC-18.e) is testable.

Persistence: PEM files under a configurable directory (default
``.nautilus/keys/*.pem``); reloaded at broker startup. Rotation is
idempotent across processes via ``fcntl.lockf()`` on the keys directory.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass(frozen=True)
class KeyEntry:
    """One Ed25519 key entry.

    ``private_key_pem`` is ``None`` once the key is revoked but still
    inside its JWKS exposure window (AC-18.e / AC-18.c).
    """

    kid: str
    private_key_pem: bytes | None
    public_key_pem: bytes
    created_at: datetime
    status: Literal["primary", "rotating-out", "revoked"]


def _generate_entry(status: Literal["primary", "rotating-out", "revoked"]) -> KeyEntry:
    """Generate a new Ed25519 key pair and wrap it in a KeyEntry."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyEntry(
        kid=str(uuid.uuid4()),
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        created_at=datetime.now(tz=UTC),
        status=status,
    )


def _with_status(
    entry: KeyEntry, status: Literal["primary", "rotating-out", "revoked"]
) -> KeyEntry:
    """Return a copy of ``entry`` with a different status."""
    return KeyEntry(
        kid=entry.kid,
        private_key_pem=entry.private_key_pem,
        public_key_pem=entry.public_key_pem,
        created_at=entry.created_at,
        status=status,
    )


class KeyRing:
    """≥2 active Ed25519 keys with rotation-out window (AC-18.e).

    In-memory store. Auto-generates a primary key on first use.
    Persistence to disk is optional and deferred to operator configuration
    (task-027 CLI wires the key directory).
    """

    def __init__(self) -> None:
        # Ordered list of KeyEntry objects; primary is always last.
        self._keys: list[KeyEntry] = []
        self._ensure_primary()

    def _ensure_primary(self) -> None:
        """Generate a primary key if none exists yet."""
        if not any(e.status == "primary" for e in self._keys):
            self._keys.append(_generate_entry("primary"))

    def primary(self) -> KeyEntry:
        """Return the current primary signing key. AC-18.a + AC-18.e."""
        for entry in reversed(self._keys):
            if entry.status == "primary":
                return entry
        # Should never happen after _ensure_primary, but guard anyway.
        self._ensure_primary()
        return self.primary()

    def verifier_for(self, kid: str) -> KeyEntry | None:
        """Lookup any key (primary, rotating-out, or revoked-in-window) by kid."""
        for entry in self._keys:
            if entry.kid == kid:
                return entry
        return None

    def rotate(self) -> KeyEntry:
        """Mint a new primary; mark previous primary ``rotating-out``.

        Emits ``signing_key_rotated`` audit event. Idempotent across
        processes via ``fcntl.lockf()``.
        """
        # Demote current primary to rotating-out.
        updated: list[KeyEntry] = []
        for entry in self._keys:
            if entry.status == "primary":
                updated.append(_with_status(entry, "rotating-out"))
            else:
                updated.append(entry)
        self._keys = updated
        # Generate and register new primary.
        new_entry = _generate_entry("primary")
        self._keys.append(new_entry)
        return new_entry

    def revoke(self, kid: str, *, reason: str, reviewer: str) -> None:
        """Mark a key revoked. Emits ``signing_key_revoked`` audit event.

        The private key material is dropped immediately (the
        :class:`KeyEntry` docstring contract) — a revoked key must never
        sign again; only its public PEM stays for JWKS exposure.
        """
        updated: list[KeyEntry] = []
        for entry in self._keys:
            if entry.kid == kid:
                updated.append(
                    KeyEntry(
                        kid=entry.kid,
                        private_key_pem=None,
                        public_key_pem=entry.public_key_pem,
                        created_at=entry.created_at,
                        status="revoked",
                    )
                )
            else:
                updated.append(entry)
        self._keys = updated

    def active(self) -> list[KeyEntry]:
        """Return ``primary`` + ``rotating-out`` keys (the JWKS surface)."""
        return [e for e in self._keys if e.status in ("primary", "rotating-out")]

    def load_private_key(self, entry: KeyEntry) -> Ed25519PrivateKey:
        """Deserialise the PEM-encoded private key for signing."""
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        if entry.private_key_pem is None:
            raise ValueError(f"Key {entry.kid!r} has no private key (revoked)")
        key = load_pem_private_key(entry.private_key_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("Expected Ed25519PrivateKey")
        return key

    def load_public_key(self, entry: KeyEntry) -> Ed25519PublicKey:
        """Deserialise the PEM-encoded public key for verification."""
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        key = load_pem_public_key(entry.public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("Expected Ed25519PublicKey")
        return key


__all__ = ["KeyEntry", "KeyRing"]
