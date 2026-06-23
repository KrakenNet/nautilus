"""Integration: per-source response hashing + attestation linkage (issue #19).

These tests close the gap that PR #41 left open. PR #41 added a single,
broker-level ``response_hash`` over the *merged, post-synthesis* blob — which
is strictly weaker than design §5.7 Weakness 7, which requires a hash of
*each source's* response captured at the adapter boundary, with per-source
attribution recorded in the attestation token.

They use an in-process fake-adapter harness (no testcontainers) so the full
broker pipeline — route → fan-out → synthesize → sign — runs end to end.

Test B — the signed attestation payload carries a
``source_response_hashes: {source_id: "sha256:..."}`` claim with one
sha256-prefixed entry per successfully queried source.

Test C — the *real* chain-of-custody tamper test the existing
``test_response_hash_byte_mutation`` only faked: mutating a single row that an
adapter returned causes the per-source hash to no longer match the signed
claim (i.e. tamper is detectable end to end). On current ``main`` this test
cannot even be expressed because no per-source hash is captured at the adapter
boundary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import pytest

from nautilus import Broker
from nautilus.adapters.schema import AdapterSchema
from nautilus.config.models import SourceConfig
from nautilus.core.attestation_payload import compute_raw_response_hash
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

pytestmark = pytest.mark.integration

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide dummy DSNs so the fixture config interpolates.

    Adapters are constructed but never ``connect()``-ed (fakes are swapped in),
    so the DSN values just need to be non-empty strings.
    """
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


class _HashingFakeAdapter:
    """Minimal Adapter Protocol impl returning fixed rows.

    A deterministic adapter returns only ``rows``; the broker computes the
    per-source chain-of-custody digest centrally over those rows (issue #56
    review), so the adapter never sets a digest itself.
    """

    source_type: str = "fake"

    def __init__(self, source_id: str, rows: list[dict[str, Any]]) -> None:
        self._source_id = source_id
        self._rows = rows

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        return AdapterResult(
            source_id=self._source_id,
            rows=list(self._rows),
            duration_ms=0,
        )

    async def close(self) -> None:
        return None

    async def get_schema(self) -> AdapterSchema:
        return AdapterSchema.unknown(self._source_id, self.source_type)


class _NonDeterministicFakeAdapter:
    """Fake llm-style adapter: declares ``non_deterministic`` and never hashes.

    Mirrors the real LLM adapter contract (AC-19.g): it returns rows but leaves
    ``response_hash`` unset, and the ``non_deterministic`` capability tells the
    broker to exclude it from ``source_response_hashes`` and to sign
    ``hash_skipped=True``.
    """

    source_type: str = "fake-llm"
    capabilities: ClassVar[frozenset[str]] = frozenset({"non_deterministic"})

    def __init__(self, source_id: str, rows: list[dict[str, Any]]) -> None:
        self._source_id = source_id
        self._rows = rows

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        return AdapterResult(source_id=self._source_id, rows=list(self._rows), duration_ms=0)

    async def close(self) -> None:
        return None

    async def get_schema(self) -> AdapterSchema:
        return AdapterSchema.unknown(self._source_id, self.source_type)


def _install_fakes(broker: Broker, fakes: dict[str, Any]) -> None:
    """Swap the broker's real adapters for fakes and mark them connected.

    Reaching into the private adapter maps mirrors ``tests/unit/test_broker.py``:
    the broker has no public DI surface for adapters in Phase 1.
    """
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes.keys())  # type: ignore[attr-defined]  # noqa: SLF001


def _ctx() -> dict[str, Any]:
    """Baseline request context that routes to both nautilus.yaml sources."""
    return {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "s1",
        "embedding": [0.1, 0.2, 0.3],
    }


def _capture_signed_payloads(broker: Broker, sink: dict[str, Any]) -> None:
    """Wrap ``broker._sign`` so the signed Nautilus payload is captured.

    The signed payload is what the JWT ``input_hash`` covers; capturing it lets
    the test inspect the ``source_response_hashes`` claim without needing the
    attestation sink wired up.
    """
    original = broker._sign  # type: ignore[attr-defined]  # noqa: SLF001

    def _wrapped(**kwargs: Any) -> Any:
        token, version, payload = original(**kwargs)
        sink["payload"] = payload
        return token, version, payload

    broker._sign = _wrapped  # type: ignore[attr-defined]  # noqa: SLF001


@pytest.mark.integration
async def test_source_response_hashes_claim_present_per_source() -> None:
    """Test B: the signed payload carries one sha256 hash per queried source."""
    broker = Broker.from_config(FIXTURE_PATH)
    captured: dict[str, Any] = {}
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _HashingFakeAdapter("nvd_db", [{"id": 1, "cve": "CVE-0"}]),
                "internal_vulns": _HashingFakeAdapter("internal_vulns", [{"id": 2}]),
            },
        )
        _capture_signed_payloads(broker, captured)
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
        assert set(resp.sources_queried) == {"nvd_db", "internal_vulns"}
    finally:
        await broker.aclose()

    payload = captured["payload"]
    assert "source_response_hashes" in payload, (
        "signed attestation payload must carry the per-source hash claim"
    )
    hashes = payload["source_response_hashes"]
    assert set(hashes) == {"nvd_db", "internal_vulns"}
    for source_id, h in hashes.items():
        assert h.startswith("sha256:"), f"{source_id} hash not sha256-prefixed: {h!r}"


@pytest.mark.integration
async def test_per_source_hash_matches_adapter_rows() -> None:
    """The signed per-source hash equals the helper applied to that source's rows."""
    nvd_rows = [{"id": 1, "cve": "CVE-0"}]
    iv_rows = [{"id": 2}]
    broker = Broker.from_config(FIXTURE_PATH)
    captured: dict[str, Any] = {}
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _HashingFakeAdapter("nvd_db", nvd_rows),
                "internal_vulns": _HashingFakeAdapter("internal_vulns", iv_rows),
            },
        )
        _capture_signed_payloads(broker, captured)
        await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
    finally:
        await broker.aclose()

    hashes = captured["payload"]["source_response_hashes"]
    assert hashes["nvd_db"] == compute_raw_response_hash(nvd_rows)
    assert hashes["internal_vulns"] == compute_raw_response_hash(iv_rows)


@pytest.mark.integration
async def test_row_mutation_after_adapter_return_is_detectable() -> None:
    """Test C: mutating a returned row breaks the signed per-source hash.

    This is the genuine chain-of-custody check. The adapter hashes its raw
    response at the boundary (inside ``execute()``); the broker threads that
    hash into the signed attestation claim. If a single row is altered after
    the fact, recomputing the hash over the tampered rows no longer matches the
    signed claim — tamper detected.
    """
    rows = [{"id": 1, "cve": "CVE-0", "severity": "high"}]
    broker = Broker.from_config(FIXTURE_PATH)
    captured: dict[str, Any] = {}
    try:
        _install_fakes(
            broker,
            {"nvd_db": _HashingFakeAdapter("nvd_db", rows)},
        )
        _capture_signed_payloads(broker, captured)
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
        assert resp.sources_queried == ["nvd_db"]
    finally:
        await broker.aclose()

    signed_hash = captured["payload"]["source_response_hashes"]["nvd_db"]
    # The honest data verifies.
    assert compute_raw_response_hash(rows) == signed_hash

    # Tamper: flip one byte in one returned row.
    tampered = [dict(r) for r in rows]
    tampered[0]["severity"] = "low"
    assert compute_raw_response_hash(tampered) != signed_hash, (
        "row mutation must be detectable against the signed per-source hash"
    )


@pytest.mark.integration
async def test_mixed_deterministic_and_llm_coexistence() -> None:
    """Findings #3/#4 (issue #19): a request mixing a deterministic source and a
    non-deterministic (llm) source signs ``hash_skipped=True`` (the whole-response
    hash is unverifiable) AND a ``source_response_hashes`` map that covers ONLY the
    deterministic source. This locks the documented coexistence decision: the two
    claims are not mutually exclusive — per-source custody survives for the sources
    that ARE deterministic, while the llm source is signalled as unhashed by its
    absence from the map.
    """
    nvd_rows = [{"id": 1, "cve": "CVE-0"}]
    broker = Broker.from_config(FIXTURE_PATH)
    captured: dict[str, Any] = {}
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _HashingFakeAdapter("nvd_db", nvd_rows),
                "internal_vulns": _NonDeterministicFakeAdapter(
                    "internal_vulns", [{"id": 2, "summary": "llm text"}]
                ),
            },
        )
        _capture_signed_payloads(broker, captured)
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
        assert set(resp.sources_queried) == {"nvd_db", "internal_vulns"}
    finally:
        await broker.aclose()

    payload = captured["payload"]
    # Whole-response hash is skipped (the llm row makes the merged blob unverifiable).
    assert payload["hash_skipped"] is True
    assert "response_hash" not in payload
    # Per-source custody still holds for the deterministic source only.
    hashes = payload["source_response_hashes"]
    assert set(hashes) == {"nvd_db"}, (
        "the non-deterministic source must be absent from the per-source map"
    )
    assert hashes["nvd_db"] == compute_raw_response_hash(nvd_rows)


def _capture_audit_entries(broker: Broker, sink: list[Any]) -> None:
    """Wrap the broker's audit logger so emitted ``AuditEntry`` objects are captured."""
    original = broker._audit_logger.emit  # type: ignore[attr-defined]  # noqa: SLF001

    def _wrapped(entry: Any) -> Any:
        sink.append(entry)
        return original(entry)

    broker._audit_logger.emit = _wrapped  # type: ignore[attr-defined]  # noqa: SLF001


@pytest.mark.integration
async def test_adapter_supplied_hash_is_not_trusted() -> None:
    """Security (issue #56 review): a digest smuggled onto the AdapterResult must
    NOT reach the signed attestation. The broker recomputes every per-source hash
    from the adapter's actual rows, so a malicious or buggy adapter cannot forge
    the ``source_response_hashes`` claim (attestation forgery).
    """
    rows = [{"id": 1, "cve": "CVE-0"}]
    forged = "sha256:" + "0" * 64

    class _ForgingFakeAdapter(_HashingFakeAdapter):
        async def execute(
            self,
            intent: IntentAnalysis,
            scope: list[ScopeConstraint],
            context: dict[str, Any],
        ) -> AdapterResult:
            res = await super().execute(intent, scope, context)
            # Smuggle a lie onto the result object, bypassing the model schema.
            object.__setattr__(res, "response_hash", forged)
            return res

    broker = Broker.from_config(FIXTURE_PATH)
    captured: dict[str, Any] = {}
    try:
        _install_fakes(broker, {"nvd_db": _ForgingFakeAdapter("nvd_db", rows)})
        _capture_signed_payloads(broker, captured)
        await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
    finally:
        await broker.aclose()

    signed = captured["payload"]["source_response_hashes"]["nvd_db"]
    assert signed == compute_raw_response_hash(rows), "broker must hash the real rows"
    assert signed != forged, "adapter-supplied digest must never reach the attestation"


@pytest.mark.integration
async def test_source_response_hashes_recorded_in_audit_log() -> None:
    """Issue #56 review (audit gap): the per-source digests are signed into the
    JWT AND persisted on the ``attestation_emitted`` AuditEntry, so they can be
    verified offline from the audit log alone.
    """
    nvd_rows = [{"id": 1, "cve": "CVE-0"}]
    broker = Broker.from_config(FIXTURE_PATH)
    entries: list[Any] = []
    try:
        _install_fakes(broker, {"nvd_db": _HashingFakeAdapter("nvd_db", nvd_rows)})
        _capture_audit_entries(broker, entries)
        await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
    finally:
        await broker.aclose()

    emitted = [e for e in entries if getattr(e, "event_type", None) == "attestation_emitted"]
    assert len(emitted) == 1, "exactly one attestation_emitted event per request"
    assert emitted[0].source_response_hashes == {"nvd_db": compute_raw_response_hash(nvd_rows)}


@pytest.mark.integration
async def test_source_response_hashes_on_primary_request_entry() -> None:
    """Issue #56 review (#1): the per-source digests appear on the canonical
    ``event_type == "request"`` AuditEntry, so a single audit record is verifiable
    without correlating the secondary ``attestation_emitted`` event.
    """
    nvd_rows = [{"id": 1, "cve": "CVE-0"}]
    broker = Broker.from_config(FIXTURE_PATH)
    entries: list[Any] = []
    try:
        _install_fakes(broker, {"nvd_db": _HashingFakeAdapter("nvd_db", nvd_rows)})
        _capture_audit_entries(broker, entries)
        await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
    finally:
        await broker.aclose()

    request_entries = [e for e in entries if getattr(e, "event_type", None) == "request"]
    assert len(request_entries) == 1, "exactly one request entry per request"
    assert request_entries[0].source_response_hashes == {
        "nvd_db": compute_raw_response_hash(nvd_rows)
    }


@pytest.mark.integration
async def test_source_response_hashes_recorded_when_attestation_disabled() -> None:
    """Issue #56 review (#2): with JWT attestation disabled, the per-source digests
    are still persisted on the request AuditEntry rather than silently discarded.
    """
    nvd_rows = [{"id": 1, "cve": "CVE-0"}]
    broker = Broker.from_config(FIXTURE_PATH)
    entries: list[Any] = []
    try:
        _install_fakes(broker, {"nvd_db": _HashingFakeAdapter("nvd_db", nvd_rows)})
        broker._attestation = None  # type: ignore[attr-defined]  # noqa: SLF001 — disable signing
        _capture_audit_entries(broker, entries)
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
        assert resp.attestation_token is None, "attestation must be disabled for this test"
    finally:
        await broker.aclose()

    request_entries = [e for e in entries if getattr(e, "event_type", None) == "request"]
    assert len(request_entries) == 1
    assert request_entries[0].source_response_hashes == {
        "nvd_db": compute_raw_response_hash(nvd_rows)
    }
