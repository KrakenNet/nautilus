# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportMissingTypeArgument=false, reportArgumentType=false, reportIndexIssue=false, reportOperatorIssue=false, reportUnknownArgumentType=false
"""Tests for nautilus.core.signer (Tasks 34, 35, 36).

Task 34: RFC 8032 test vector 1 KAT for InProcessEd25519Signer.
Task 35: VaultTransitSignerAdapter circuit-breaker fail-closed semantics.
Task 36: DSSE envelope golden-bytes round-trip.
"""

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nautilus.core.circuit_breaker import CircuitBreaker, CircuitOpenError
from nautilus.core.signer import (
    InProcessEd25519Signer,
    VaultTransitSignerAdapter,
    _build_dsse_envelope,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Task 34 — RFC 8032 §7.1 test vector 1 (the canonical empty-message KAT).
# ---------------------------------------------------------------------------

RFC8032_VECTOR_1_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC8032_VECTOR_1_PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
RFC8032_VECTOR_1_SIG = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf"
    "9b46bd25bf5f0595bbe24655141438e7a100b"
)


@pytest.mark.asyncio
async def test_kat_ed25519() -> None:
    """RFC 8032 test vector 1: seed + empty message → expected 64-byte signature."""
    signer = InProcessEd25519Signer(seed_hex=RFC8032_VECTOR_1_SEED, keyid="kat-1")
    sig = await signer.sign(b"")
    assert sig.hex() == RFC8032_VECTOR_1_SIG
    assert len(sig) == 64

    # Double-check by verifying with the published public key.
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(RFC8032_VECTOR_1_PUBKEY))
    pub.verify(sig, b"")  # raises on mismatch


def test_invalid_seed_fails_at_init() -> None:
    """Bad seed bytes must fail at construction (fail readiness, never run)."""
    with pytest.raises(ValueError):
        InProcessEd25519Signer(seed_hex="not-hex", keyid="bad")
    with pytest.raises(ValueError):
        InProcessEd25519Signer(seed_hex="ab" * 16, keyid="too-short")  # 16 bytes


def test_keyid_required() -> None:
    with pytest.raises(ValueError, match="keyid"):
        InProcessEd25519Signer(seed_hex=RFC8032_VECTOR_1_SEED, keyid="")


# ---------------------------------------------------------------------------
# Task 35 — VaultTransitSignerAdapter against a respx-mocked Vault.
# ---------------------------------------------------------------------------


def _vault_sig_response(raw_sig_hex: str) -> dict:
    """Wrap a raw signature in Vault transit's vault:v1:<b64> envelope."""
    raw = bytes.fromhex(raw_sig_hex)
    return {"data": {"signature": "vault:v1:" + base64.b64encode(raw).decode()}}


@pytest.mark.asyncio
async def test_vault_transit_happy_path() -> None:
    breaker = CircuitBreaker(name="test", failure_threshold=3)
    adapter = VaultTransitSignerAdapter(
        key_name="nautilus-session-test",
        vault_addr="https://vault.example.com",
        vault_token="s.test-token",
        breaker=breaker,
        keyid="prod-1",
    )
    payload = b"hello"
    expected_pre_hash = base64.b64encode(hashlib.sha512(payload).digest()).decode()

    with respx.mock(base_url="https://vault.example.com") as router:
        route = router.post("/v1/transit/sign/nautilus-session-test").mock(
            return_value=httpx.Response(200, json=_vault_sig_response(RFC8032_VECTOR_1_SIG))
        )
        sig = await adapter.sign(payload)

    assert sig.hex() == RFC8032_VECTOR_1_SIG
    assert len(sig) == 64
    request_body = route.calls[0].request.read()
    assert expected_pre_hash.encode() in request_body
    assert breaker.state == "closed"


@pytest.mark.asyncio
async def test_vault_transit_503_increments_breaker_until_open() -> None:
    breaker = CircuitBreaker(name="test-503", failure_threshold=3, reset_timeout=60.0)
    adapter = VaultTransitSignerAdapter(
        key_name="nautilus-session-test",
        vault_addr="https://vault.example.com",
        vault_token="s.test-token",
        breaker=breaker,
        keyid="prod-1",
    )
    with respx.mock(base_url="https://vault.example.com") as router:
        router.post("/v1/transit/sign/nautilus-session-test").mock(
            return_value=httpx.Response(503, text="Vault is sealed")
        )
        for _ in range(3):
            with pytest.raises(httpx.HTTPStatusError):
                await adapter.sign(b"payload")
        # 4th attempt: breaker is open, never reaches Vault.
        with pytest.raises(CircuitOpenError):
            await adapter.sign(b"payload")
    assert breaker.state == "open"


@pytest.mark.asyncio
async def test_vault_transit_404_is_fatal_not_breaker_counted() -> None:
    """Per AC-5.12: 404 (key not found) is a fatal config error, NOT counted toward
    the breaker threshold so a misconfiguration cannot eventually open the breaker."""
    breaker = CircuitBreaker(name="test-404", failure_threshold=3)
    adapter = VaultTransitSignerAdapter(
        key_name="nautilus-session-test",
        vault_addr="https://vault.example.com",
        vault_token="s.test-token",
        breaker=breaker,
        keyid="prod-1",
    )
    with respx.mock(base_url="https://vault.example.com") as router:
        router.post("/v1/transit/sign/nautilus-session-test").mock(
            return_value=httpx.Response(404, json={"errors": ["key not found"]})
        )
        with pytest.raises(RuntimeError, match="vault transit key not found"):
            await adapter.sign(b"payload")
    assert breaker.state == "closed"


@pytest.mark.asyncio
async def test_vault_transit_response_body_not_leaked_in_error() -> None:
    breaker = CircuitBreaker(name="test-leak", failure_threshold=3)
    adapter = VaultTransitSignerAdapter(
        key_name="nautilus-session-test",
        vault_addr="https://vault.example.com",
        vault_token="s.secret-token-DONOTLOG",
        breaker=breaker,
        keyid="prod-1",
    )
    with respx.mock(base_url="https://vault.example.com") as router:
        router.post("/v1/transit/sign/nautilus-session-test").mock(
            return_value=httpx.Response(500, text="STACK TRACE WITH POLICY DETAILS")
        )
        with pytest.raises(httpx.HTTPStatusError) as excinfo:
            await adapter.sign(b"payload")
    rendered = repr(excinfo.value)
    assert "STACK TRACE WITH POLICY DETAILS" not in rendered
    assert "secret-token-DONOTLOG" not in rendered


# ---------------------------------------------------------------------------
# Task 36 — DSSE envelope KAT.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dsse_kat() -> None:
    """The DSSE envelope must (a) base64url the canonical bytes, (b) sign the raw
    canonical bytes (NOT the base64url text), and (c) match a captured golden."""
    # 5-field session-signing payload, deliberately unsorted to force JCS.
    payload = {
        "timestamp": "2026-04-27T10:00:00.000Z",
        "model_id": "gpt-4o-2024-11-20",
        "prompt_hash": "1" * 64,
        "output_hash": "2" * 64,
        "params_hash": "3" * 64,
    }
    signer = InProcessEd25519Signer(seed_hex=RFC8032_VECTOR_1_SEED, keyid="kat-1")
    envelope = await _build_dsse_envelope(payload, signer)

    # Shape per design line 410-419.
    assert envelope["payloadType"] == "application/vnd.nautilus.signed-session+json"
    assert "payload" in envelope
    assert envelope["signatures"][0]["keyid"] == "kat-1"

    # Decode the payload — must yield JCS canonical (sorted keys, no whitespace).
    payload_bytes = base64.urlsafe_b64decode(envelope["payload"] + "==")
    expected = (
        b'{"model_id":"gpt-4o-2024-11-20","output_hash":"'
        b'2222222222222222222222222222222222222222222222222222222222222222","params_hash":"'
        b'3333333333333333333333333333333333333333333333333333333333333333","prompt_hash":"'
        b'1111111111111111111111111111111111111111111111111111111111111111",'
        b'"timestamp":"2026-04-27T10:00:00.000Z"}'
    )
    assert payload_bytes == expected

    # Verify the signature is over the raw canonical bytes, NOT the base64url text.
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(RFC8032_VECTOR_1_PUBKEY))
    sig = base64.urlsafe_b64decode(envelope["signatures"][0]["sig"] + "==")
    pub.verify(sig, payload_bytes)
