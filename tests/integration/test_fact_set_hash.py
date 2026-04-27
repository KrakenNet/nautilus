"""US-6 / FR-62 ``fact_set_hash`` opaque-pass-through integration tests.

AC coverage: AC-6.1, AC-6.2, AC-6.3, AC-6.4, AC-6.6, AC-6.7, AC-6.8,
NFR-BC, NFR-ERR-OPAQUE.

Exercises the Task 23 wiring end-to-end through an in-process
:class:`Broker`: caller supplies ``fact_set_hash`` on the request, and
the three surfaces that must carry it (``BrokerResponse``,
``AuditEntry`` JSONL, signed attestation JWS claim) all see the exact
same bytes. No validation, no recomputation — opaque round-trip.

Scenarios:

1. **``fact_set_hash="abc123"``** — round-trips on response,
   audit entry, and the JWT's inner Nautilus payload (AC-6.7).
2. **``fact_set_hash=None`` (omitted)** — byte-identical to pre-spec:
   response + audit carry ``None``, and the signed payload does NOT
   contain the ``fact_set_hash`` key (AC-6.8 / NFR-ATT-V2-FROZEN
   sanity).
3. **``fact_set_hash=""``** — empty string round-trips on response +
   audit as ``""``. Per
   :func:`nautilus.core.attestation_payload._has_fact_set_hash`,
   ``bool("") is False`` so the signed payload DOES NOT embed the
   key — an empty-string sentinel is documented as "present but
   unset" and NOT bit-echoed into the attestation claim (design
   Cross-Cutting Concerns block).
4. **10KB unicode edge case** — mixed CJK + emoji + RTL text +
   zero-width joiners at ~10KB round-trips byte-identically on every
   surface (NFR-ERR-OPAQUE).

All scenarios use the in-process broker (Phase-1 in-memory session
store + fixture ``nautilus.yaml``) with :class:`_FakeAdapter` doubles
installed via the same pattern used by ``tests/integration/test_cost_caps.py``
— no Docker, no testcontainers. Audit file rooted under ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nautilus import Broker
from nautilus.adapters.base import Adapter
from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.config.models import SourceConfig
from nautilus.core.attestation_sink import FileAttestationSink
from nautilus.core.models import AdapterResult, AuditEntry, IntentAnalysis, ScopeConstraint

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"


# ---------------------------------------------------------------------------
# Test doubles — mirror tests/integration/test_cost_caps.py::_FakeAdapter
# ---------------------------------------------------------------------------


class _FakeAdapter:
    """Minimal :class:`Adapter` Protocol impl (no external I/O)."""

    source_type: str = "fake"

    def __init__(self, source_id: str, *, rows: list[dict[str, Any]] | None = None) -> None:
        self._source_id = source_id
        self._rows = rows if rows is not None else [{"id": 1}]

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


def _install_fakes(broker: Broker, fakes: dict[str, _FakeAdapter]) -> None:
    """Swap adapters for fakes + pre-mark them as connected (no Postgres)."""
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes.keys())  # type: ignore[attr-defined]  # noqa: SLF001
    for adapter in fakes.values():
        assert isinstance(adapter, Adapter)


def _ctx() -> dict[str, Any]:
    return {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "sess-fact-set-hash",
        "embedding": [0.1, 0.2, 0.3],
    }


def _read_audit_entries(audit_file: Path) -> list[AuditEntry]:
    entries: list[AuditEntry] = []
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
        entries.append(AuditEntry.model_validate_json(entry_json))
    return entries


def _install_file_sink(broker: Broker, path: Path) -> None:
    """Swap the broker's attestation sink for a :class:`FileAttestationSink`.

    The Phase-1 fixture ``nautilus.yaml`` wires :class:`NullAttestationSink`
    (no sink path configured), so the signed Nautilus payload is never
    persisted anywhere the test can observe. Substituting a
    :class:`FileAttestationSink` gives us JSONL on disk whose
    ``nautilus_payload`` column carries the exact dict handed to
    :meth:`AttestationService.sign` — the source of truth for "what was
    in the signed payload".
    """
    broker._attestation_sink = FileAttestationSink(path)  # type: ignore[attr-defined]  # noqa: SLF001


def _read_nautilus_payloads(sink_path: Path) -> list[dict[str, Any]]:
    """Pull back the list of inner Nautilus payloads from the sink JSONL."""
    out: list[dict[str, Any]] = []
    for line in sink_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        payload: Any = record.get("nautilus_payload")
        assert isinstance(payload, dict), (
            f"attestation sink row missing nautilus_payload dict; got {record!r}"
        )
        typed_payload: dict[str, Any] = payload  # pyright: ignore[reportUnknownVariableType]
        out.append(typed_payload)
    return out


@pytest.fixture(autouse=True)
def _set_test_env(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Provide dummy DSNs + root audit writes under ``tmp_path``."""
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")
    monkeypatch.chdir(tmp_path)


# ---------------------------------------------------------------------------
# Scenario 1: AC-6.7 — "abc123" round-trips on all three surfaces.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_fact_set_hash_round_trips_on_response_audit_and_attestation(
    tmp_path: Path,
) -> None:
    """AC-6.7 — ``fact_set_hash="abc123"`` surfaces verbatim on:
    response, audit JSONL, and the signed attestation payload.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    sink_path = tmp_path / "attestation.jsonl"
    _install_file_sink(broker, sink_path)
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db", rows=[{"id": 1, "cve": "CVE-FSH-1"}]),
                "internal_vulns": _FakeAdapter("internal_vulns", rows=[{"id": 2}]),
            },
        )
        resp = await broker.arequest(
            "agent-alpha",
            "vulnerability scan",
            _ctx(),
            fact_set_hash="abc123",
        )

        # (1) Response round-trip — AC-6.1 / AC-6.4.
        assert resp.fact_set_hash == "abc123", (
            f"response.fact_set_hash must echo the caller's value verbatim; "
            f"got {resp.fact_set_hash!r}"
        )
        assert resp.attestation_token is not None, "attestation must produce a signed token"

        # (2) Audit JSONL round-trip — AC-6.6 / FR-62.
        audit_file = tmp_path / "audit.jsonl"
        assert audit_file.exists(), f"audit file missing at {audit_file}"
        entries = _read_audit_entries(audit_file)
        request_entries = [e for e in entries if e.event_type in (None, "request")]
        assert len(request_entries) == 1, (
            f"expected exactly one request audit entry; got {len(request_entries)}"
        )
        assert request_entries[0].fact_set_hash == "abc123", (
            f"AuditEntry.fact_set_hash must echo the caller's value verbatim; "
            f"got {request_entries[0].fact_set_hash!r}"
        )

        # (3) Signed attestation payload round-trip — AC-6.3 / FR-62.
        payloads = _read_nautilus_payloads(sink_path)
        assert len(payloads) == 1, (
            f"expected exactly one emitted attestation payload; got {len(payloads)}"
        )
        assert payloads[0].get("fact_set_hash") == "abc123", (
            f"signed Nautilus payload must include fact_set_hash='abc123'; got {payloads[0]!r}"
        )
    finally:
        await broker.aclose()


# ---------------------------------------------------------------------------
# Scenario 2: AC-6.8 — omitted fact_set_hash → byte-identical pre-spec behavior.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_fact_set_hash_omitted_keeps_bit_identical_prespec_behavior(
    tmp_path: Path,
) -> None:
    """AC-6.8 / NFR-BC — omitting ``fact_set_hash`` produces pre-spec output.

    The signed Nautilus payload must NOT carry a ``fact_set_hash`` key
    when the caller does not supply one — this is the NFR-ATT-V2-FROZEN
    guarantee enforced at the unit-level, asserted here end-to-end.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    sink_path = tmp_path / "attestation.jsonl"
    _install_file_sink(broker, sink_path)
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db"),
                "internal_vulns": _FakeAdapter("internal_vulns"),
            },
        )
        # fact_set_hash omitted → defaults to None.
        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())

        assert resp.fact_set_hash is None, (
            f"response.fact_set_hash must be None when omitted; got {resp.fact_set_hash!r}"
        )
        assert resp.attestation_token is not None

        entries = _read_audit_entries(tmp_path / "audit.jsonl")
        request_entries = [e for e in entries if e.event_type in (None, "request")]
        assert len(request_entries) == 1
        assert request_entries[0].fact_set_hash is None, (
            f"AuditEntry.fact_set_hash must be None when omitted; "
            f"got {request_entries[0].fact_set_hash!r}"
        )

        payloads = _read_nautilus_payloads(sink_path)
        assert len(payloads) == 1
        assert "fact_set_hash" not in payloads[0], (
            f"signed Nautilus payload MUST NOT contain fact_set_hash when omitted "
            f"(NFR-ATT-V2-FROZEN); got {payloads[0]!r}"
        )
    finally:
        await broker.aclose()


# ---------------------------------------------------------------------------
# Scenario 3: empty-string sentinel — round-trips on response/audit, NOT on JWT.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_fact_set_hash_empty_string_round_trips_but_not_in_payload(
    tmp_path: Path,
) -> None:
    """NFR-ERR-OPAQUE — empty string round-trips verbatim on response + audit.

    Per :func:`nautilus.core.attestation_payload._has_fact_set_hash`,
    ``bool("") is False`` → the ``fact_set_hash`` key is NOT emitted into
    the signed payload. Empty string is documented as a "present but
    unset" sentinel at the attestation layer: the outer surfaces still
    carry the caller's ``""`` verbatim (AC-6.4 opaque round-trip), only
    the inner JWT claim omits the key.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    sink_path = tmp_path / "attestation.jsonl"
    _install_file_sink(broker, sink_path)
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db"),
                "internal_vulns": _FakeAdapter("internal_vulns"),
            },
        )
        resp = await broker.arequest(
            "agent-alpha",
            "vulnerability scan",
            _ctx(),
            fact_set_hash="",
        )

        # Response + audit echo the empty string verbatim.
        assert resp.fact_set_hash == "", (
            f"response.fact_set_hash must round-trip '' verbatim; got {resp.fact_set_hash!r}"
        )
        entries = _read_audit_entries(tmp_path / "audit.jsonl")
        request_entries = [e for e in entries if e.event_type in (None, "request")]
        assert len(request_entries) == 1
        assert request_entries[0].fact_set_hash == "", (
            f"AuditEntry.fact_set_hash must round-trip '' verbatim; "
            f"got {request_entries[0].fact_set_hash!r}"
        )

        # Attestation payload: by design, empty string does NOT embed.
        assert resp.attestation_token is not None
        payloads = _read_nautilus_payloads(sink_path)
        assert len(payloads) == 1
        assert "fact_set_hash" not in payloads[0], (
            f"empty-string fact_set_hash must NOT embed into the signed payload "
            f"(bool('') is False; _has_fact_set_hash returns False by design); "
            f"got {payloads[0]!r}"
        )
    finally:
        await broker.aclose()


# ---------------------------------------------------------------------------
# Scenario 4: 10KB unicode — mixed CJK + emoji + RTL + ZWJ round-trips verbatim.
# ---------------------------------------------------------------------------


def _build_10kb_unicode_hash() -> str:
    """Construct a ~10KB string mixing CJK + emoji + RTL + zero-width joiners.

    Per NFR-ERR-OPAQUE the broker must never inspect, validate, or
    normalize the caller's ``fact_set_hash``; any byte sequence that
    fits the ``str`` type must round-trip verbatim. We deliberately
    include:

    - CJK Han characters (3-byte UTF-8)
    - Emoji above BMP (4-byte UTF-8 surrogate pair region)
    - RTL (Arabic) text (embedded direction switches)
    - Zero-width joiner sequences (family emoji, variant selectors)

    The resulting string is well over 10,000 bytes once UTF-8 encoded.
    """
    cjk = "漢字テストひらがなカタカナ"  # mixed CJK + kana
    emoji = "🚀🌊🐙⚡🔥💎🦀"  # above-BMP emoji
    rtl = "مرحبا بالعالم"  # Arabic RTL
    zwj_family = "👨‍👩‍👧‍👦"  # ZWJ sequence
    chunk = f"{cjk}|{emoji}|{rtl}|{zwj_family}|"
    out: list[str] = []
    total_bytes = 0
    while total_bytes < 10_000:
        out.append(chunk)
        total_bytes += len(chunk.encode("utf-8"))
    return "".join(out)


@pytest.mark.integration
async def test_fact_set_hash_10kb_unicode_round_trips_verbatim(tmp_path: Path) -> None:
    """NFR-ERR-OPAQUE — ~10KB mixed-script unicode round-trips byte-identically.

    Covers response, audit JSONL, and the signed Nautilus payload: all
    three must carry the caller's exact string — no validation, no
    normalization, no recomputation (AC-6.4 opaque pass-through).
    """
    big_hash = _build_10kb_unicode_hash()
    # Sanity: we actually hit the >10KB size target the task calls for.
    assert len(big_hash.encode("utf-8")) >= 10_000, (
        f"test input too small; got {len(big_hash.encode('utf-8'))} bytes"
    )

    broker = Broker.from_config(FIXTURE_PATH)
    sink_path = tmp_path / "attestation.jsonl"
    _install_file_sink(broker, sink_path)
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db"),
                "internal_vulns": _FakeAdapter("internal_vulns"),
            },
        )
        resp = await broker.arequest(
            "agent-alpha",
            "vulnerability scan",
            _ctx(),
            fact_set_hash=big_hash,
        )

        assert resp.fact_set_hash == big_hash, (
            "response.fact_set_hash must be byte-identical to the caller's input"
        )

        entries = _read_audit_entries(tmp_path / "audit.jsonl")
        request_entries = [e for e in entries if e.event_type in (None, "request")]
        assert len(request_entries) == 1
        assert request_entries[0].fact_set_hash == big_hash, (
            "AuditEntry.fact_set_hash must be byte-identical to the caller's input"
        )

        assert resp.attestation_token is not None
        payloads = _read_nautilus_payloads(sink_path)
        assert len(payloads) == 1
        assert payloads[0].get("fact_set_hash") == big_hash, (
            "signed Nautilus payload must carry the caller's fact_set_hash byte-identically"
        )
    finally:
        await broker.aclose()
