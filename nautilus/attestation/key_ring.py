"""KeyRing — multi-key Ed25519 store with rotation window (#18, AC-18.e).

Closest existing pattern: ``nautilus/core/broker.py:553-566`` autogenerates
a single Ed25519 keypair when no ``attestation.private_key_path`` is set.
This file generalizes that to ≥2 active keys with explicit rotation-out
state, so old-tokens-during-overlap (AC-18.e) is testable.

By default the ring is in-process only: a restarted broker mints a fresh one
and every token signed by the old ring stops verifying. Pass ``store_path``
(``session_tokens.key_ring_path`` in ``nautilus.yaml``) to persist it, which is
what a multi-replica deployment needs — two processes that do not share key
material reject each other's session tokens with ``unknown_kid``, and behind a
load balancer that is every second request.
"""

from __future__ import annotations

import fcntl
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

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


def _entry_to_json(entry: KeyEntry) -> dict[str, object]:
    return {
        "kid": entry.kid,
        "private_key_pem": (
            entry.private_key_pem.decode("ascii") if entry.private_key_pem is not None else None
        ),
        "public_key_pem": entry.public_key_pem.decode("ascii"),
        "created_at": entry.created_at.isoformat(),
        "status": entry.status,
    }


def _entry_from_json(raw: dict[str, object]) -> KeyEntry:
    private = raw.get("private_key_pem")
    return KeyEntry(
        kid=str(raw["kid"]),
        private_key_pem=str(private).encode("ascii") if isinstance(private, str) else None,
        public_key_pem=str(raw["public_key_pem"]).encode("ascii"),
        created_at=datetime.fromisoformat(str(raw["created_at"])),
        status=cast("Literal['primary', 'rotating-out', 'revoked']", str(raw["status"])),
    )


class KeyRing:
    """≥2 active Ed25519 keys with rotation-out window (AC-18.e).

    In-memory unless ``store_path`` is given, in which case the ring is loaded
    from that file at construction and rewritten on every change, so replicas
    pointed at one shared path sign and verify with the same keys. The file
    holds private key material and is written ``0600``.
    """

    def __init__(self, store_path: Path | str | None = None) -> None:
        # Ordered list of KeyEntry objects; primary is always last.
        self._keys: list[KeyEntry] = []
        self._store_path = Path(store_path) if store_path is not None else None
        if self._store_path is not None:
            self._load()
        self._ensure_primary()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Read the persisted ring, if there is one. A missing file is not an error."""
        assert self._store_path is not None  # noqa: S101 — callers guard
        try:
            raw = json.loads(self._store_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        self._keys = [_entry_from_json(e) for e in cast("list[dict[str, object]]", raw)]

    def _persist(self) -> None:
        """Write the ring back, atomically, if this ring is persistent."""
        if self._store_path is None:
            return
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps([_entry_to_json(e) for e in self._keys])
        tmp = self._store_path.with_name(f"{self._store_path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._store_path)

    def _ensure_primary(self) -> None:
        """Generate a primary key if none exists yet.

        Persistent rings generate under an exclusive lock on a sidecar and
        re-read first: two replicas starting together must end up with one
        ring, not with the second one overwriting the first's key.
        """
        if any(e.status == "primary" for e in self._keys):
            return
        if self._store_path is None:
            self._keys.append(_generate_entry("primary"))
            return
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._store_path.with_name(self._store_path.name + ".lock")
        with lock_path.open("a+", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            self._load()
            if not any(e.status == "primary" for e in self._keys):
                self._keys.append(_generate_entry("primary"))
                self._persist()

    def primary(self) -> KeyEntry:
        """Return the current primary signing key. AC-18.a + AC-18.e."""
        for entry in reversed(self._keys):
            if entry.status == "primary":
                return entry
        # Should never happen after _ensure_primary, but guard anyway.
        self._ensure_primary()
        return self.primary()

    def verifier_for(self, kid: str) -> KeyEntry | None:
        """Lookup any key (primary, rotating-out, or revoked-in-window) by kid.

        An unknown kid on a persistent ring is re-read from the store before
        being reported missing: another replica may have rotated since this
        process loaded, and rejecting its tokens is the failure sharing the
        ring exists to prevent.
        """
        for entry in self._keys:
            if entry.kid == kid:
                return entry
        if self._store_path is not None:
            self._load()
            self._ensure_primary()
            for entry in self._keys:
                if entry.kid == kid:
                    return entry
        return None

    def rotate(self) -> KeyEntry:
        """Mint a new primary; mark previous primary ``rotating-out``.

        The caller emits the ``signing_key_rotated`` audit event — see
        :meth:`nautilus.core.broker.Broker.rotate_signing_key`, which is the
        only path that does.
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
        self._persist()
        return new_entry

    def revoke(self, kid: str, *, reason: str, reviewer: str) -> None:
        """Mark a key revoked. The caller emits ``signing_key_revoked``.

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
        self._persist()

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
