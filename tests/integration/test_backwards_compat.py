"""Phase-1 backwards-compat integration tests (Task 3.14, NFR-5/NFR-6, AC-7.5).

Exercises two round-trip invariants against the frozen Phase-1 fixtures
recorded under :mod:`tests.fixtures.audit`:

(a) NFR-5 — the captured Phase-1 :class:`AuditEntry` JSONL line still
    parses under the Phase-2 :class:`AuditEntry` pydantic model without
    any missing / mismatched fields, with every Phase-2-only block
    defaulting to ``None``.

(b) NFR-6 / AC-7.5 — the Phase-1 attestation token's JWS envelope still
    decodes under the Phase-2 verifier path (``fathom.attestation.verify_token``
    → ``jwt.decode`` with ``algorithms=["EdDSA"]``), and the token's
    ``input_hash`` claim is byte-identical to what the Phase-2
    :func:`nautilus.core.attestation_payload.build_payload` emits when
    fed the same Phase-1 inputs. Because the fixture was minted with an
    ephemeral Ed25519 keypair (no pinned public key is checked into the
    tree), we prove verifier compatibility two ways:

    1. Decode the token under the standard Phase-2 algorithm allowlist
       (``EdDSA``) with signature verification disabled — this catches
       any future drift in the JWS envelope (alg flip, claim schema
       change) that would break Phase-1 tokens.
    2. Sign a *fresh* Phase-2 token with the same Phase-1 claim set via
       :meth:`AttestationService.sign`, then verify it with
       :func:`verify_token` under that service's public key — this
       proves the verifier still accepts the Phase-1 claim shape
       (``iss=fathom``, ``decision``, ``rule_trace``, ``input_hash``,
       ``session_id``).

Both cases are marked ``@pytest.mark.integration`` per the suite's
marker convention; they read only small fixture files so they are fast
and do not require Docker.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jwt as pyjwt
import pytest
from fathom.attestation import AttestationService, verify_token

from nautilus.core.attestation_payload import build_payload
from nautilus.core.models import AuditEntry

# ---------------------------------------------------------------------------
# Fixture paths — pinned to the Phase-1 captures recorded by Task 2.25.
# ---------------------------------------------------------------------------

_FIXTURE_DIR: Path = Path(__file__).resolve().parents[1] / "fixtures" / "audit"
_PHASE1_AUDIT_PATH: Path = _FIXTURE_DIR / "phase1_audit_line.jsonl"
_PHASE1_TOKEN_PATH: Path = _FIXTURE_DIR / "phase1_attestation_token.jwt"


# ---------------------------------------------------------------------------
# (a) NFR-5 — AuditEntry JSONL line round-trips.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_phase1_audit_line_round_trips_under_phase2_model() -> None:
    """Phase-1 audit JSONL parses unchanged under the Phase-2 :class:`AuditEntry`.

    The Phase-2 model added a block of optional fields (``llm_provider``,
    ``scope_hash_version``, ``session_store_mode``, …); each must default
    to ``None`` on a Phase-1 line so operators upgrading from Phase-1
    logs see no parse errors.
    """
    assert _PHASE1_AUDIT_PATH.exists(), f"Phase-1 audit fixture missing at {_PHASE1_AUDIT_PATH}"
    raw = _PHASE1_AUDIT_PATH.read_text(encoding="utf-8").strip()
    assert raw, "Phase-1 audit fixture is empty"

    entry = AuditEntry.model_validate_json(raw)

    # Core Phase-1 fields survive the round-trip.
    assert entry.request_id == "52f2cfe5-b1bd-43a8-bb31-b22d6628dd0d"
    assert entry.agent_id == "agent-alpha"
    assert entry.session_id == "s1"
    assert entry.sources_queried == ["internal_vulns", "nvd_db"]
    assert entry.rule_trace == ["nautilus-routing::match-sources-by-data-type"]
    # scope_hash_version was stamped ``"v1"`` on Phase-1 captures (Task 1.12).
    assert entry.scope_hash_version == "v1"

    # NFR-5 pin: Phase-2-only fields default to None on Phase-1 lines.
    assert entry.llm_provider is None
    assert entry.llm_model is None
    assert entry.llm_version is None
    assert entry.raw_response_hash is None
    assert entry.prompt_version is None
    assert entry.fallback_used is None
    assert entry.session_id_source is None
    assert entry.session_store_mode is None
    # event_type defaults to None in Phase-1 captures (the field was added
    # in Phase-2 but Phase-1 lines wrote ``None`` rather than ``"request"``).
    assert entry.event_type in (None, "request")
    assert entry.handoff_id is None
    assert entry.handoff_decision is None


# ---------------------------------------------------------------------------
# (b) NFR-6 / AC-7.5 — Phase-1 token verifies under Phase-2 verifier.
# ---------------------------------------------------------------------------


def _canonical_input_hash(input_facts: list[dict[str, Any]]) -> str:
    """Mirror ``fathom.attestation.AttestationService.sign``'s input_hash derivation."""
    return hashlib.sha256(json.dumps(input_facts, sort_keys=True).encode()).hexdigest()


@pytest.mark.integration
def test_phase1_attestation_token_verifies_under_phase2_verifier() -> None:
    """Phase-1 JWS envelope + claim set still pass the Phase-2 verifier path.

    Two-step proof (see module docstring):

    1. The Phase-1 token decodes under ``alg=EdDSA`` on the Phase-2 PyJWT
       dependency — the JWS envelope has not drifted. Signature
       verification is skipped because the fixture was minted with an
       ephemeral keypair (no pinned public key), but every other layer
       the verifier exercises (base64url, JWS header, JSON claims) is
       traversed.
    2. The Phase-1 ``input_hash`` is bit-identical to what the Phase-2
       :func:`build_payload` + :class:`AttestationService` pipeline emits
       for the same inputs recovered from the Phase-1 audit line — the
       canonicalization frozen by Task 1.12 / NFR-6 still holds.
    """
    assert _PHASE1_TOKEN_PATH.exists(), f"Phase-1 token fixture missing at {_PHASE1_TOKEN_PATH}"
    token = _PHASE1_TOKEN_PATH.read_text(encoding="utf-8").strip()
    assert token, "Phase-1 token fixture is empty"

    # --- (1) JWS envelope still decodes under the Phase-2 algorithm allowlist.
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "EdDSA", f"alg drift: {header!r}"
    assert header["typ"] == "JWT"

    # Decode the claim set (sig skipped — see module docstring for why).
    claims: dict[str, Any] = pyjwt.decode(
        token,
        algorithms=["EdDSA"],
        options={"verify_signature": False},
    )
    assert claims["iss"] == "fathom"
    assert claims["session_id"] == "s1"
    assert claims["decision"].startswith("nautilus:")
    assert claims["rule_trace"] == ["nautilus-routing::match-sources-by-data-type"]
    # input_hash is a hex SHA-256 (64 lowercase hex chars).
    assert isinstance(claims["input_hash"], str)
    assert len(claims["input_hash"]) == 64
    int(claims["input_hash"], 16)  # purely structural — raises on non-hex.

    # --- (2) Phase-2 build_payload reproduces the Phase-1 input_hash.
    audit_raw = _PHASE1_AUDIT_PATH.read_text(encoding="utf-8").strip()
    entry = AuditEntry.model_validate_json(audit_raw)

    nautilus_payload, version = build_payload(
        request_id=entry.request_id,
        agent_id=entry.agent_id,
        # Broker sorts before signing (see ``Broker._sign``); the audit line
        # already carries the sorted list but we re-sort defensively.
        sources_queried=sorted(entry.sources_queried),
        scope_constraints=[],  # Phase-1 capture had ``scope_constraints == []``.
        rule_trace=list(entry.rule_trace),
    )
    assert version == "v1", "Phase-1 captures must re-derive as v1 (NFR-6)"

    # ``AttestationService.sign`` packs ``input_facts = [nautilus_payload]``
    # (mirrors :meth:`nautilus.core.broker.Broker._sign`); replicate that
    # wrapping so the hash matches bit-for-bit.
    recomputed_hash = _canonical_input_hash([nautilus_payload])
    assert recomputed_hash == claims["input_hash"], (
        "Phase-2 build_payload + AttestationService input_hash drift detected — "
        f"Phase-1 token carries {claims['input_hash']!r}, Phase-2 re-derives "
        f"{recomputed_hash!r}. NFR-6 canonicalization has regressed."
    )

    # --- Sanity: the verifier accepts a freshly-signed Phase-2 token with
    # the same Phase-1 claim shape. This covers the full verify_token path
    # (signature + alg + claim parse) that the fixture alone cannot because
    # its signing key was ephemeral.
    svc = AttestationService.generate_keypair()
    result = SimpleNamespace(
        decision=claims["decision"],
        rule_trace=list(claims["rule_trace"]),
    )
    fresh_token = svc.sign(
        result=result,  # type: ignore[arg-type]
        session_id=str(claims["session_id"]),
        input_facts=[nautilus_payload],
    )
    verified: dict[str, Any] = verify_token(fresh_token, svc.public_key)
    assert verified["input_hash"] == claims["input_hash"], (
        "Round-trip through AttestationService.sign + verify_token must preserve "
        "the Phase-1 input_hash bit-for-bit."
    )
    assert verified["session_id"] == claims["session_id"]
    assert verified["decision"] == claims["decision"]
    assert verified["rule_trace"] == claims["rule_trace"]
