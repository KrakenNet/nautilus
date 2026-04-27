"""Unit tests for LLMAdapter session-signing wiring (Task 39, AC-5.9-5.16).

These tests stub out the provider SDKs entirely so we can exercise the
signing hook without VCR cassettes. They verify:

  * a chat response carries a verifiable DSSE envelope on ``AdapterResult.signature``
  * embeddings re-pack to big-endian float32 bytes before SHA-256 (TD-15)
  * signer failures fail-closed (no unsigned response is returned)
  * ``params_hash`` reflects only parameters actually passed
"""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nautilus.adapters.base import AdapterError
from nautilus.adapters.llm import LLMAdapter
from nautilus.config.models import SessionSigningConfig, SourceConfig
from nautilus.core.models import IntentAnalysis

pytestmark = pytest.mark.unit


KAT_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
KAT_PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def _config(**overrides: object) -> SourceConfig:
    fields: dict[str, object] = {
        "id": "signing-test",
        "type": "llm",
        "description": "test",
        "classification": "internal",
        "data_types": ["llm-output"],
        "connection": "",
        "llm_provider": "openai",
        "llm_model": "gpt-4o-mini",
        "surface": "chat",
        "token_secret_ref": "sk-test",
        "session_signing": SessionSigningConfig(
            enabled=True, key_ref="env://NAUTILUS_TEST_SIGNING_SEED"
        ),
    }
    fields.update(overrides)
    return SourceConfig(**fields)  # type: ignore[arg-type]


class _FakeChatChoice:
    class _Msg:
        def __init__(self, content: str) -> None:
            self.content = content
            self.tool_calls = []

    def __init__(self, content: str) -> None:
        self.message = self._Msg(content)


class _FakeChatResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_FakeChatChoice(content)]

        class _Usage:
            prompt_tokens = 7
            completion_tokens = 5
            total_tokens = 12

        self.usage = _Usage()


class _FakeChatNamespace:
    def __init__(self, content: str) -> None:
        self._content = content

    async def create(self, **kwargs: Any) -> _FakeChatResponse:
        del kwargs
        return _FakeChatResponse(self._content)


class _FakeOpenAI:
    def __init__(self, content: str = "hello") -> None:
        class _Chat:
            completions = _FakeChatNamespace(content)

        class _Embeddings:
            async def create(self, **kwargs: Any) -> Any:
                del kwargs

                class _Item:
                    def __init__(self, vec: list[float], idx: int) -> None:
                        self.embedding = vec
                        self.index = idx

                class _Resp:
                    def __init__(self) -> None:
                        self.data = [_Item([0.1, 0.2, 0.3], 0)]

                        class _U:
                            prompt_tokens = 3
                            total_tokens = 3

                        self.usage = _U()

                return _Resp()

        self.chat = _Chat()
        self.embeddings = _Embeddings()

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_chat_response_carries_verifiable_dsse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NAUTILUS_TEST_SIGNING_SEED", KAT_SEED)
    adapter = LLMAdapter()
    await adapter.connect(_config())
    adapter._openai = _FakeOpenAI(content="the answer is 42")  # type: ignore[assignment]

    intent = IntentAnalysis(raw_intent="hello", data_types_needed=[], entities=[])
    result = await adapter.execute(intent, [], {"temperature": 0.5})

    assert result.signature is not None
    assert result.signature["payloadType"] == "application/vnd.nautilus.signed-session+json"

    # Decode + verify with the KAT pubkey.
    payload_b64 = result.signature["payload"]
    sig_b64 = result.signature["signatures"][0]["sig"]
    canonical = base64.urlsafe_b64decode(payload_b64 + "==")
    sig = base64.urlsafe_b64decode(sig_b64 + "==")

    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(KAT_PUBKEY))
    pub.verify(sig, canonical)


@pytest.mark.asyncio
async def test_embeddings_output_hash_uses_big_endian_float32(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NAUTILUS_TEST_SIGNING_SEED", KAT_SEED)
    adapter = LLMAdapter()
    await adapter.connect(_config(surface="embeddings"))
    adapter._openai = _FakeOpenAI()  # type: ignore[assignment]

    intent = IntentAnalysis(raw_intent="hello", data_types_needed=[], entities=[])
    result = await adapter.execute(intent, [], {})

    assert result.signature is not None
    canonical = base64.urlsafe_b64decode(result.signature["payload"] + "==")
    payload_dict = rfc8785.dumps(
        {
            "model_id": "gpt-4o-mini",
            "output_hash": hashlib.sha256(struct.pack(">fff", 0.1, 0.2, 0.3)).hexdigest(),
            "params_hash": hashlib.sha256(rfc8785.dumps({"model_id": "gpt-4o-mini"})).hexdigest(),
            "prompt_hash": hashlib.sha256(rfc8785.dumps(["hello"])).hexdigest(),
            # timestamp is dynamic — assert via field-by-field below.
        }
    )
    # Compare just the structural keys (timestamps differ per call).
    import json

    decoded = json.loads(canonical)
    expected = json.loads(payload_dict)
    for key in ("model_id", "output_hash", "params_hash", "prompt_hash"):
        assert decoded[key] == expected[key], f"{key} mismatch"
    assert "timestamp" in decoded


@pytest.mark.asyncio
async def test_signer_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NAUTILUS_TEST_SIGNING_SEED", KAT_SEED)
    adapter = LLMAdapter()
    await adapter.connect(_config())
    adapter._openai = _FakeOpenAI(content="hello")  # type: ignore[assignment]

    class _BoomSigner:
        keyid = "boom"

        async def sign(self, payload: bytes) -> bytes:
            raise RuntimeError("vault transit unreachable")

    adapter._signer = _BoomSigner()  # type: ignore[assignment]

    intent = IntentAnalysis(raw_intent="hello", data_types_needed=[], entities=[])
    with pytest.raises(AdapterError, match="session signing failed"):
        await adapter.execute(intent, [], {})


@pytest.mark.asyncio
async def test_unsigned_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NAUTILUS_TEST_SIGNING_SEED", KAT_SEED)
    adapter = LLMAdapter()
    await adapter.connect(
        _config(session_signing=SessionSigningConfig(enabled=False, key_ref="")),
    )
    adapter._openai = _FakeOpenAI()  # type: ignore[assignment]
    intent = IntentAnalysis(raw_intent="hello", data_types_needed=[], entities=[])
    result = await adapter.execute(intent, [], {})
    assert result.signature is None
