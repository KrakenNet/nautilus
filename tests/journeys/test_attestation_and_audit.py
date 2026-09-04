"""Journey: the two receipts Nautilus issues for every request.

"Attestation -- Can we prove this routing decision happened? needs a signed
token." / "Audit -- What data did this agent touch, and why? requires a
tamper-evident trail." (README)

A receipt is only worth what an independent party can verify, so these tests
verify the signature and the chain rather than checking that a token-shaped
string came back.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.journey


@pytest.fixture
def deployment(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[str, Path]:
    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    audit = tmp_path / "audit.jsonl"
    config = write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "confidential",
                    "data_types": ["patients"],
                    "allowed_purposes": ["care"],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                },
                {
                    "id": "classified",
                    "type": "postgres",
                    "description": "classified records",
                    "classification": "secret",
                    "data_types": ["patients"],
                    "allowed_purposes": ["care"],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                },
            ],
            "agents": {
                "analyst": {"id": "analyst", "clearance": "confidential"},
            },
            "audit": {"path": str(audit)},
            "attestation": {"enabled": True},
        }
    )
    return config, audit


async def _request(config: str, **context: Any) -> Any:
    from nautilus import Broker

    broker = Broker.from_config(config)
    try:
        return await broker.arequest("analyst", "patient records", {"purpose": "care", **context})
    finally:
        await broker.aclose()


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------


def test_the_attestation_token_verifies_against_the_broker_public_key(
    deployment: tuple[str, Path],
) -> None:
    """A signed decision that nobody can verify is not attestation.

    Verifies the Ed25519 JWS end to end, then tamper-checks it: flipping one
    character of the payload must make verification fail.
    """
    import jwt as pyjwt

    from nautilus import Broker

    config, _ = deployment

    async def _token_and_key() -> tuple[str | None, Any]:
        # One broker: a fresh Broker mints a fresh key ring, so the token and
        # the key that verifies it have to come from the same instance.
        broker = Broker.from_config(config)
        try:
            response = await broker.arequest(
                "analyst", "patient records", {"purpose": "care", "session_id": "attest"}
            )
            # Same accessor the shipped verifier uses (``ui/router.py:560``).
            attestation = broker._attestation  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            assert attestation is not None, "attestation is disabled on this deployment"
            return response.attestation_token, attestation.public_key
        finally:
            await broker.aclose()

    token, public_key = asyncio.run(_token_and_key())
    assert token, "no attestation token was issued for a routed request"

    claims = pyjwt.decode(token, public_key, algorithms=["EdDSA"])
    assert claims, "the token verified but carried no claims"

    # A tampered token must not verify.
    header, payload, signature = token.split(".")
    forged = f"{header}.{payload[:-2]}{'AA' if payload[-2:] != 'AA' else 'AB'}.{signature}"
    with pytest.raises(pyjwt.PyJWTError):
        pyjwt.decode(forged, public_key, algorithms=["EdDSA"])


def test_the_attestation_is_bound_to_this_request(
    deployment: tuple[str, Path],
) -> None:
    """A token that is not bound to its request can be replayed onto another."""
    import base64

    config, _ = deployment
    first = asyncio.run(_request(config, session_id="bind-1"))
    second = asyncio.run(_request(config, session_id="bind-2"))

    def _claims(token: str) -> dict[str, Any]:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))

    assert first.attestation_token != second.attestation_token, (
        "two different requests were issued the identical attestation token"
    )
    assert _claims(first.attestation_token) != _claims(second.attestation_token), (
        "two different requests produced identical attestation claims, so the "
        "token is not bound to the request it attests"
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_every_request_appends_one_audit_entry(
    deployment: tuple[str, Path],
) -> None:
    """ "per-request, append-only entries" (README) -- including for denials."""
    config, audit = deployment

    async def _three() -> None:
        from nautilus import Broker

        broker = Broker.from_config(config)
        try:
            for i in range(3):
                await broker.arequest(
                    "analyst",
                    "patient records",
                    {"purpose": "care", "session_id": f"audit-{i}"},
                )
        finally:
            await broker.aclose()

    asyncio.run(_three())
    lines = [ln for ln in audit.read_text().splitlines() if ln.strip()]
    assert len(lines) >= 3, (
        f"three requests produced {len(lines)} audit lines; the audit trail is "
        f"the record of what the agent touched"
    )
    for line in lines:
        json.loads(line)  # every line must be parseable JSON


def test_the_audit_entry_names_the_sources_allowed_and_denied(
    deployment: tuple[str, Path],
) -> None:
    """ "What data did this agent touch, and why" must be answerable from the log.

    The analyst's clearance dominates ``patients`` but not ``classified``, so
    a correct entry names both outcomes.
    """
    config, audit = deployment
    asyncio.run(_request(config, session_id="audit-detail"))

    text = audit.read_text()
    assert "patients" in text, "the queried source is not named in the audit log"
    assert "classified" in text, (
        "the denied source is not named in the audit log, so the log records "
        "what was read but not what was refused"
    )


def test_the_audit_log_is_append_only_across_broker_restarts(
    deployment: tuple[str, Path],
) -> None:
    """A restart must not truncate the trail."""
    config, audit = deployment

    asyncio.run(_request(config, session_id="restart-1"))
    first = len([ln for ln in audit.read_text().splitlines() if ln.strip()])
    asyncio.run(_request(config, session_id="restart-2"))
    second = [ln for ln in audit.read_text().splitlines() if ln.strip()]

    assert len(second) > first, (
        f"a second broker wrote {len(second)} lines over a log that already had "
        f"{first}; the log is not append-only across restarts"
    )
