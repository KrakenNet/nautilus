"""Unit tests for post-run engine consistency checks (#27).

Thick-unit style mirroring ``tests/unit/test_fathom_router.py``: a real
:class:`fathom.Engine` runs against the built-in rules tree, then
``monkeypatch`` intercepts ``engine.query`` readbacks to inject the
inconsistent fact sets each check guards against (the design §4-ops
"retraction cascade" failure mode is not reproducible with the shipped
rule packs — which is the point of the checks).

Covers:

- Default-on: a clean 3-source route passes all checks.
- Each violation class raises :class:`ConsistencyError` with its check name:
  ``routing_unknown_source``, ``scope_without_routing``,
  ``denial_unknown_source``, ``denial_missing_linkage``,
  ``agent_fact_integrity`` (count + slot mutation),
  ``session_exposure_count``.
- ``check_consistency=False`` disables the checks (config escape hatch).
- ``rules.consistency_checks`` config plumb: default ``True``,
  ``Broker.from_config`` propagates it to the router.
- Broker fail-closed path: a violation surfaces as ``PolicyEngineError``
  AND the emitted audit entry carries the check name in ``error_records``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.config.models import NautilusConfig, SourceConfig
from nautilus.core import Broker, ConsistencyError, PolicyEngineError
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import IntentAnalysis
from nautilus.rules import BUILT_IN_RULES_DIR

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dummy DSNs so the config interpolator does not fail (adapters never connect)."""
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


def _make_router(*, check_consistency: bool = True) -> FathomRouter:
    return FathomRouter(
        built_in_rules_dir=BUILT_IN_RULES_DIR,
        user_rules_dirs=[],
        attestation=None,
        check_consistency=check_consistency,
    )


def _three_sources() -> list[SourceConfig]:
    return [
        SourceConfig(
            id="vuln-db",
            type="postgres",
            description="vulnerability database",
            classification="secret",
            data_types=["vulnerability", "cve"],
            allowed_purposes=["audit", "research"],
            connection="postgres://localhost/vuln",
        ),
        SourceConfig(
            id="asset-db",
            type="postgres",
            description="asset inventory",
            classification="secret",
            data_types=["asset", "host"],
            allowed_purposes=["audit", "research"],
            connection="postgres://localhost/asset",
        ),
        SourceConfig(
            id="log-db",
            type="postgres",
            description="event logs",
            classification="secret",
            data_types=["log", "event"],
            allowed_purposes=["audit", "research"],
            connection="postgres://localhost/logs",
        ),
    ]


def _intent_all_three() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="show vulns, assets, and logs",
        data_types_needed=["vulnerability", "asset", "log"],
        entities=[],
    )


def _route(router: FathomRouter, *, session: dict[str, Any] | None = None) -> Any:
    return router.route(
        agent_id="agent-1",
        context={"clearance": "secret", "purpose": "audit"},
        intent=_intent_all_three(),
        sources=_three_sources(),
        session=session or {"id": "sess-1", "pii_sources_accessed": 0},
    )


def _patch_query(
    monkeypatch: pytest.MonkeyPatch,
    router: FathomRouter,
    overrides: dict[str, Callable[[list[dict[str, Any]]], list[dict[str, Any]]]],
) -> None:
    """Intercept ``engine.query`` per-template; pass real rows through the override."""
    real_query = router.engine.query

    def fake(template: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = [dict(r) for r in real_query(template)]
        override = overrides.get(template)
        return override(rows) if override is not None else rows

    monkeypatch.setattr(router.engine, "query", fake)


# ---------------------------------------------------------------------------
# Router-level: default-on happy path + each violation class
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_clean_route_passes_checks() -> None:
    """Checks are on by default and a consistent engine run sails through."""
    router = _make_router()
    try:
        result = _route(router)
        assert {rd.source_id for rd in result.routing_decisions} == {
            "vuln-db",
            "asset-db",
            "log-db",
        }
    finally:
        router.close()


@pytest.mark.unit
def test_routing_unknown_source_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    router = _make_router()
    try:
        _patch_query(
            monkeypatch,
            router,
            {
                "routing_decision": lambda rows: [
                    *rows,
                    {"source_id": "ghost-db", "reason": "haunted"},
                ]
            },
        )
        with pytest.raises(ConsistencyError) as exc_info:
            _route(router)
        assert exc_info.value.check_name == "routing_unknown_source"
        assert "ghost-db" in str(exc_info.value)
    finally:
        router.close()


@pytest.mark.unit
def test_scope_without_routing_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    """A scope_constraint for a declared-but-never-routed source is inconsistent."""
    router = _make_router()
    try:
        _patch_query(
            monkeypatch,
            router,
            {
                # Drop asset-db's routing decision but leave a scope for it.
                "routing_decision": lambda rows: [r for r in rows if r["source_id"] != "asset-db"],
                "scope_constraint": lambda rows: [
                    *rows,
                    {
                        "source_id": "asset-db",
                        "field": "hostname",
                        "operator": "=",
                        "value": "web-01",
                    },
                ],
            },
        )
        with pytest.raises(ConsistencyError) as exc_info:
            _route(router)
        assert exc_info.value.check_name == "scope_without_routing"
        assert "asset-db" in str(exc_info.value)
    finally:
        router.close()


@pytest.mark.unit
def test_denial_unknown_source_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    router = _make_router()
    try:
        _patch_query(
            monkeypatch,
            router,
            {
                "denial_record": lambda rows: [
                    *rows,
                    {
                        "source_id": "ghost-db",
                        "reason": "clearance",
                        "rule_name": "deny-ghost",
                    },
                ]
            },
        )
        with pytest.raises(ConsistencyError) as exc_info:
            _route(router)
        assert exc_info.value.check_name == "denial_unknown_source"
    finally:
        router.close()


@pytest.mark.unit
def test_denial_missing_linkage_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    router = _make_router()
    try:
        _patch_query(
            monkeypatch,
            router,
            {
                "denial_record": lambda rows: [
                    *rows,
                    {"source_id": "vuln-db", "reason": "  ", "rule_name": "deny-x"},
                ]
            },
        )
        with pytest.raises(ConsistencyError) as exc_info:
            _route(router)
        assert exc_info.value.check_name == "denial_missing_linkage"
        assert "vuln-db" in str(exc_info.value)
    finally:
        router.close()


@pytest.mark.unit
def test_agent_fact_retraction_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    """The §4-ops cascade scenario: the agent fact vanished mid-evaluation."""
    router = _make_router()
    try:
        _patch_query(monkeypatch, router, {"agent": lambda rows: []})
        with pytest.raises(ConsistencyError) as exc_info:
            _route(router)
        assert exc_info.value.check_name == "agent_fact_integrity"
        assert "found 0" in str(exc_info.value)
    finally:
        router.close()


@pytest.mark.unit
def test_agent_fact_mutation_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    """An agent fact whose purpose slot changed under evaluation is inconsistent."""
    router = _make_router()
    try:
        _patch_query(
            monkeypatch,
            router,
            {"agent": lambda rows: [{**row, "purpose": "exfiltration"} for row in rows]},
        )
        with pytest.raises(ConsistencyError) as exc_info:
            _route(router)
        assert exc_info.value.check_name == "agent_fact_integrity"
        assert "purpose" in str(exc_info.value)
    finally:
        router.close()


@pytest.mark.unit
def test_session_exposure_retraction_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    """Session exposure facts retracted mid-evaluation (the issue's headline case)."""
    router = _make_router()
    try:
        _patch_query(monkeypatch, router, {"session_exposure": lambda rows: []})
        with pytest.raises(ConsistencyError) as exc_info:
            _route(
                router,
                session={
                    "id": "sess-1",
                    "pii_sources_accessed": 0,
                    "sources_visited": ["vuln-db", "asset-db"],
                },
            )
        assert exc_info.value.check_name == "session_exposure_count"
        assert "expected 2" in str(exc_info.value)
    finally:
        router.close()


@pytest.mark.unit
def test_checks_disabled_lets_inconsistency_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``check_consistency=False`` is the config escape hatch — no raise."""
    router = _make_router(check_consistency=False)
    try:
        _patch_query(
            monkeypatch,
            router,
            {
                "routing_decision": lambda rows: [
                    *rows,
                    {"source_id": "ghost-db", "reason": "haunted"},
                ]
            },
        )
        result = _route(router)
        assert "ghost-db" in {rd.source_id for rd in result.routing_decisions}
    finally:
        router.close()


# ---------------------------------------------------------------------------
# Config plumb + broker fail-closed audit
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_rules_config_defaults_consistency_checks_on() -> None:
    assert NautilusConfig().rules.consistency_checks is True
    cfg = NautilusConfig.model_validate({"rules": {"consistency_checks": False}})
    assert cfg.rules.consistency_checks is False


def _write_fixture_with_tmp_audit(tmp_path: Path) -> tuple[Path, Path]:
    """Clone the fixture yaml with the audit log pointed under ``tmp_path``."""
    audit_path = tmp_path / "audit.jsonl"
    src = FIXTURE_PATH.read_text(encoding="utf-8")
    dst_text = src.replace("path: ./audit.jsonl", f"path: {audit_path}")
    assert str(audit_path) in dst_text, "audit path replacement must land"
    dst = tmp_path / "nautilus.yaml"
    dst.write_text(dst_text, encoding="utf-8")
    return dst, audit_path


def _read_audit_entries(path: Path) -> list[dict[str, Any]]:
    """Unwrap nautilus AuditEntry payloads from the fathom AuditRecord JSONL."""
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        metadata: dict[str, Any] = record.get("metadata") or {}
        raw = metadata.get(NAUTILUS_METADATA_KEY)
        if isinstance(raw, str):
            entries.append(json.loads(raw))
    return entries


@pytest.mark.unit
def test_from_config_plumbs_consistency_flag(tmp_path: Path) -> None:
    config_path, _ = _write_fixture_with_tmp_audit(tmp_path)
    disabled_path = tmp_path / "nautilus-disabled.yaml"
    disabled_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "user_rules_dirs: []",
            "user_rules_dirs: []\n  consistency_checks: false",
        ),
        encoding="utf-8",
    )

    broker = Broker.from_config(config_path)
    try:
        router: Any = broker._router  # noqa: SLF001 # pyright: ignore[reportPrivateUsage]
        assert router._check_consistency_enabled is True
    finally:
        broker.close()

    broker = Broker.from_config(disabled_path)
    try:
        router = broker._router  # noqa: SLF001 # pyright: ignore[reportPrivateUsage]
        assert router._check_consistency_enabled is False
    finally:
        broker.close()


@pytest.mark.unit
async def test_broker_fails_closed_and_audits_check_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A consistency violation fails the request closed AND lands in the audit log."""
    config_path, audit_path = _write_fixture_with_tmp_audit(tmp_path)
    broker = Broker.from_config(config_path)
    try:
        engine = broker._router.engine  # noqa: SLF001 # pyright: ignore[reportPrivateUsage]
        real_query = engine.query

        def fake(template: str) -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = [dict(r) for r in real_query(template)]
            if template == "routing_decision":
                rows.append({"source_id": "ghost-db", "reason": "haunted"})
            return rows

        monkeypatch.setattr(engine, "query", fake)

        with pytest.raises(PolicyEngineError, match="routing_unknown_source"):
            await broker.arequest(
                "agent-alpha",
                "vulnerability scan",
                {
                    "clearance": "unclassified",
                    "purpose": "threat-analysis",
                    "session_id": "s1",
                },
            )

        entries = _read_audit_entries(audit_path)
        assert entries, "fail-closed path must still emit an audit entry"
        errors = [err for entry in entries for err in entry.get("error_records", [])]
        assert any(
            err.get("error_type") == "ConsistencyError"
            and "routing_unknown_source" in str(err.get("message", ""))
            for err in errors
        ), f"audit must capture the check name; got {errors!r}"
    finally:
        await broker.aclose()
