"""WAVE E2 — two replicas, and two boots, must tell the truth.

Three blockers, each reproduced first-hand against a running broker before a
line of fix was written:

1. Two brokers pointed at one ``audit.chained: true`` log both start and both
   append. Each keeps its own in-memory chain head, so the chain forks within
   seconds while every request still answers 200. The next restart of either
   replica finds a log it cannot verify and fails closed on every request.
   ``ChainedFileAttestationSink`` already solves exactly this for the
   *attestation* sink, with an exclusive ``flock`` on a sidecar. The audit sink
   never got the same treatment.

   The lock belongs at the first write, not at construction: W7 gate 5 pins
   that a read-only ``nautilus adapters list`` / ``schema-ack`` must still
   build a Broker while the server runs, and ``schema-ack`` is the documented
   recovery from a drift quarantine. So both brokers still start; the second
   one refuses to serve.

2. A session token minted by replica A is rejected by replica B with
   ``broker_instance_mismatch``, even when both share the documented
   ``session_tokens.key_ring_path``. The id compared is ``uuid.uuid4()``
   generated per ``Broker``, exposed by no configuration key, so the token check
   can never pass behind a load balancer:

       SessionTokenError: Token issued for 'ea9f340e-…', not '1c6ba9a1-…'

3. ``attestation.enabled: true`` with no ``private_key_path`` (documented as
   auto-generating a keypair per process) plus ``audit.chained: true`` works on
   the first boot and is permanently broken on every boot after, because the new
   process signs with a new key:

       AttestationError: chained log …/audit.jsonl is corrupt; refusing append:
       signing key fingerprint ff59494e…

   Both settings are documented; the combination is never rejected. Failing at
   the first request rather than at startup is the difference between a config
   error an operator reads and an outage they debug.

   The refusal is scoped to appending to a chain that already exists, which is
   the broken case. A fresh chain with an ephemeral key still starts — B3d pins
   that — because nothing on disk was signed by another key yet.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

import pytest
import yaml

from nautilus.attestation.session_token import SessionTokenError
from nautilus.core.broker import Broker

pytestmark = [pytest.mark.integration]

_SOURCES: list[dict[str, Any]] = [
    {
        "id": "orders",
        "type": "static",
        "classification": "unclassified",
        "data_types": ["orders"],
        "rows": [{"id": 1, "region": "us-east"}],
    }
]
_AGENTS: dict[str, Any] = {"a1": {"id": "a1", "clearance": "unclassified"}}


def _signing_key(tmp_path: Path) -> str:
    """A real Ed25519 PEM on disk — a stable key is the point of these pins."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = tmp_path / "att.pem"
    pem.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return str(pem)


def _write_config(path: Path, **overrides: Any) -> str:
    """A minimal working config plus whatever the pin is about."""
    document: dict[str, Any] = {"sources": _SOURCES, "agents": _AGENTS}
    document.update(overrides)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return str(path)


async def _request(broker: Broker, **context: Any) -> Any:
    return await broker.arequest("a1", "list recent orders", {"purpose": "analytics", **context})


@pytest.mark.asyncio
async def test_e2_a_second_writer_on_a_chained_audit_log_is_refused(tmp_path: Path) -> None:
    """One chained log, one writer. Two forks it, and the fork is silent.

    Both brokers still *build* — read-only CLI surfaces depend on that (W7
    gate 5). The second one must refuse to write rather than interleave.
    """
    overrides: dict[str, Any] = {
        "attestation": {"enabled": True, "private_key_path": _signing_key(tmp_path)},
        "audit": {"path": str(tmp_path / "audit.jsonl"), "chained": True},
    }
    config = _write_config(tmp_path / "nautilus.yaml", **overrides)

    first = await Broker.afrom_config(config)
    second = await Broker.afrom_config(config)
    try:
        await _request(first, session_id="s1")

        with pytest.raises(Exception, match="(?i)one writer|single"):
            await _request(second, session_id="s2")
    finally:
        await second.aclose()
        await first.aclose()


@pytest.mark.asyncio
async def test_e2_session_tokens_survive_a_shared_key_ring(tmp_path: Path) -> None:
    """A token minted by one replica must verify on the replica next door.

    Sharing ``key_ring_path`` is what the operator guide tells you to do to run
    more than one replica. It is not enough today: the instance id is a per
    process uuid4, so the token fails on any replica but its issuer.
    """
    overrides: dict[str, Any] = {
        "session_tokens": {"enabled": True, "key_ring_path": str(tmp_path / "ring.json")},
        "audit": {"path": str(tmp_path / "audit.jsonl")},
    }
    config = _write_config(tmp_path / "nautilus.yaml", **overrides)

    replica_a = await Broker.afrom_config(config)
    await replica_a.setup()
    replica_b = await Broker.afrom_config(config)
    await replica_b.setup()
    try:
        minted = await _request(replica_a, session_id="s1")
        assert minted.session_token, "replica A minted no session token to test with"

        served = await _request(replica_b, session_id="s1", session_token=minted.session_token)
        assert served.outcome in {"allowed", "denied", "skipped", "errored"}
    finally:
        await replica_a.aclose()
        await replica_b.aclose()


@pytest.mark.asyncio
async def test_e2_an_explicit_instance_id_still_scopes_tokens(tmp_path: Path) -> None:
    """Two deployments that set different ids must still reject each other.

    Widening the check must not delete it: the id exists so a token cannot be
    replayed against an unrelated broker that happens to share key material.
    """
    ring = str(tmp_path / "ring.json")
    audit = str(tmp_path / "audit.jsonl")
    config_a = _write_config(
        tmp_path / "a.yaml",
        session_tokens={"enabled": True, "key_ring_path": ring, "broker_instance_id": "east"},
        audit={"path": audit},
    )
    config_b = _write_config(
        tmp_path / "b.yaml",
        session_tokens={"enabled": True, "key_ring_path": ring, "broker_instance_id": "west"},
        audit={"path": audit},
    )

    east = await Broker.afrom_config(config_a)
    await east.setup()
    west = await Broker.afrom_config(config_b)
    await west.setup()
    try:
        minted = await _request(east, session_id="s1")
        assert minted.session_token

        with pytest.raises(SessionTokenError, match="broker_instance_mismatch|not 'west'"):
            await _request(west, session_id="s1", session_token=minted.session_token)
    finally:
        await east.aclose()
        await west.aclose()


@pytest.mark.asyncio
async def test_e2_chained_audit_refuses_a_per_process_signing_key(tmp_path: Path) -> None:
    """Reject the combination at boot two's startup, not at its first request.

    An auto-generated key is per process. A chained log signed by one process is
    unverifiable by the next, so this pairing is broken from the second boot
    onwards — and it is two documented settings, not an exotic configuration.
    """
    config = _write_config(
        tmp_path / "nautilus.yaml",
        attestation={"enabled": True},
        audit={"path": str(tmp_path / "audit.jsonl"), "chained": True},
    )

    boot_one = await Broker.afrom_config(config)
    try:
        await _request(boot_one, session_id="s1")
    finally:
        await boot_one.aclose()

    with pytest.raises(Exception, match="(?i)private_key_path"):
        boot_two = await Broker.afrom_config(config)
        with contextlib.suppress(Exception):
            await boot_two.aclose()
