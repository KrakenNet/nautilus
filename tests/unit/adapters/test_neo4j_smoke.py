"""Smoke coverage for :mod:`nautilus.adapters.neo4j` (Task 2.10 bridge).

Exercises the Cypher-build / scope-enforcement surface of
:class:`Neo4jAdapter` so the [VERIFY] 2.10 gate clears the 80% branch
floor. No real Neo4j driver is built — :class:`unittest.mock.AsyncMock`
stands in for ``AsyncDriver.execute_query`` and ``AsyncDriver.close``.

Locked behavior:

- ``connect()`` rejects empty / malformed labels with
  :class:`ScopeEnforcementError` (AC-10.1) before the driver is built.
- ``connect()`` accepts a regex-valid label + injected fake driver.
- Every allowlisted operator (``=``, ``!=``, ``IN``, ``NOT IN``, ``<``,
  ``>``, ``<=``, ``>=``, ``BETWEEN``, ``LIKE`` (both ``starts_with`` and
  ``regex`` styles), ``IS NULL``) emits the expected Cypher fragment with
  identifiers backticked and values bound via ``parameters_`` (AC-10.2).
- Unknown operator → :class:`ScopeEnforcementError`.
- Bad property identifier → :class:`ScopeEnforcementError`.
- ``close()`` is idempotent (FR-17).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.adapters.base import ScopeEnforcementError
from nautilus.adapters.neo4j import Neo4jAdapter
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint


def _make_neo4j_source(label: str | None = "Vuln", like_style: str = "starts_with") -> SourceConfig:
    return SourceConfig(
        id="vulns_graph",
        type="neo4j",
        description="vuln graph",
        classification="secret",
        data_types=["vulnerability"],
        allowed_purposes=["research"],
        connection="bolt://localhost:7687",
        label=label,
        auth=NoneAuth(),
        like_style=like_style,  # type: ignore[arg-type]
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="lookup",
        data_types_needed=["vulnerability"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


async def _connected_adapter(
    *, like_style: str = "starts_with", driver: Any = None
) -> Neo4jAdapter:
    fake_driver = driver if driver is not None else AsyncMock()
    adapter = Neo4jAdapter(driver=fake_driver)
    await adapter.connect(_make_neo4j_source(like_style=like_style))
    return adapter


# ---------------------------------------------------------------------------
# connect()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_connect_rejects_empty_label() -> None:
    adapter = Neo4jAdapter(driver=AsyncMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(_make_neo4j_source(label=None))


@pytest.mark.unit
async def test_connect_rejects_malformed_label() -> None:
    adapter = Neo4jAdapter(driver=AsyncMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(_make_neo4j_source(label="bad-label!"))


@pytest.mark.unit
async def test_connect_accepts_pascal_case_label() -> None:
    fake_driver = AsyncMock()
    adapter = Neo4jAdapter(driver=fake_driver)
    await adapter.connect(_make_neo4j_source(label="VulnerabilityRecord"))
    assert adapter._label == "VulnerabilityRecord"  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_connect_warns_on_regex_like_style(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``like_style='regex'`` triggers an AC-10.3 WARN log line."""
    fake_driver = AsyncMock()
    adapter = Neo4jAdapter(driver=fake_driver)
    with caplog.at_level("WARNING"):
        await adapter.connect(_make_neo4j_source(like_style="regex"))
    assert any("regex" in record.message.lower() for record in caplog.records)


# ---------------------------------------------------------------------------
# _build_cypher operator coverage
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_build_cypher_eq_operator() -> None:
    adapter = await _connected_adapter()
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [ScopeConstraint(source_id="vulns_graph", field="severity", operator="=", value="high")],
        100,
    )
    assert "MATCH (n:`Vuln`)" in cypher
    assert "n.`severity` = $p0" in cypher
    assert params["p0"] == "high"
    assert params["L"] == 100


@pytest.mark.unit
async def test_build_cypher_ne_operator() -> None:
    adapter = await _connected_adapter()
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [ScopeConstraint(source_id="vulns_graph", field="severity", operator="!=", value="low")],
        100,
    )
    assert "n.`severity` <> $p0" in cypher
    assert params["p0"] == "low"


@pytest.mark.unit
async def test_build_cypher_in_operator() -> None:
    adapter = await _connected_adapter()
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [
            ScopeConstraint(
                source_id="vulns_graph",
                field="status",
                operator="IN",
                value=["open", "triaged"],
            )
        ],
        100,
    )
    assert "n.`status` IN $p0" in cypher
    assert params["p0"] == ["open", "triaged"]


@pytest.mark.unit
async def test_build_cypher_not_in_operator() -> None:
    adapter = await _connected_adapter()
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [
            ScopeConstraint(
                source_id="vulns_graph",
                field="status",
                operator="NOT IN",
                value=["closed"],
            )
        ],
        100,
    )
    assert "NOT n.`status` IN $p0" in cypher
    assert params["p0"] == ["closed"]


@pytest.mark.unit
@pytest.mark.parametrize("op", ["<", ">", "<=", ">="])
async def test_build_cypher_relational_operators(op: str) -> None:
    adapter = await _connected_adapter()
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [ScopeConstraint(source_id="vulns_graph", field="cvss", operator=op, value=7.0)],  # type: ignore[arg-type]
        100,
    )
    assert f"n.`cvss` {op} $p0" in cypher
    assert params["p0"] == 7.0


@pytest.mark.unit
async def test_build_cypher_between_operator() -> None:
    adapter = await _connected_adapter()
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [
            ScopeConstraint(
                source_id="vulns_graph",
                field="cvss",
                operator="BETWEEN",
                value=[5.0, 9.0],
            )
        ],
        100,
    )
    assert "$p0_lo <= n.`cvss` <= $p0_hi" in cypher
    assert params["p0_lo"] == 5.0
    assert params["p0_hi"] == 9.0


@pytest.mark.unit
async def test_build_cypher_like_starts_with_default() -> None:
    adapter = await _connected_adapter(like_style="starts_with")
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [ScopeConstraint(source_id="vulns_graph", field="title", operator="LIKE", value="CVE-")],
        100,
    )
    assert "n.`title` STARTS WITH $p0" in cypher
    assert params["p0"] == "CVE-"


@pytest.mark.unit
async def test_build_cypher_like_regex_when_configured() -> None:
    adapter = await _connected_adapter(like_style="regex")
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [
            ScopeConstraint(
                source_id="vulns_graph",
                field="title",
                operator="LIKE",
                value="^CVE-2024.*",
            )
        ],
        100,
    )
    assert "n.`title` =~ $p0" in cypher
    assert params["p0"] == "^CVE-2024.*"


@pytest.mark.unit
async def test_build_cypher_is_null_operator() -> None:
    adapter = await _connected_adapter()
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [
            ScopeConstraint(
                source_id="vulns_graph", field="closed_at", operator="IS NULL", value=None
            )
        ],
        100,
    )
    assert "n.`closed_at` IS NULL" in cypher
    # IS NULL binds no $pN; only the limit is in params.
    assert "p0" not in params
    assert params["L"] == 100


@pytest.mark.unit
async def test_build_cypher_combines_multiple_constraints_with_and() -> None:
    adapter = await _connected_adapter()
    cypher, _params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [
            ScopeConstraint(source_id="vulns_graph", field="severity", operator="=", value="high"),
            ScopeConstraint(
                source_id="vulns_graph", field="status", operator="IN", value=["open", "triaged"]
            ),
        ],
        100,
    )
    assert " AND " in cypher


# ---------------------------------------------------------------------------
# Negative paths
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_build_cypher_unknown_operator_raises() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "DROP TABLE"
    bad.field = "severity"
    bad.value = "x"
    with pytest.raises(ScopeEnforcementError):
        adapter._build_cypher("Vuln", [bad], 100)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_build_cypher_bad_property_identifier_raises() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "="
    bad.field = "bad name with spaces"
    bad.value = "x"
    with pytest.raises(ScopeEnforcementError):
        adapter._build_cypher("Vuln", [bad], 100)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_build_cypher_in_requires_list() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "IN"
    bad.field = "severity"
    bad.value = "scalar-not-list"
    with pytest.raises(ScopeEnforcementError):
        adapter._build_cypher("Vuln", [bad], 100)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_build_cypher_like_requires_string() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "LIKE"
    bad.field = "title"
    bad.value = 42
    with pytest.raises(ScopeEnforcementError):
        adapter._build_cypher("Vuln", [bad], 100)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_build_cypher_between_requires_2_tuple() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "BETWEEN"
    bad.field = "cvss"
    bad.value = [1.0]  # length 1
    with pytest.raises(ScopeEnforcementError):
        adapter._build_cypher("Vuln", [bad], 100)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_build_cypher_between_rejects_scalar() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "BETWEEN"
    bad.field = "cvss"
    bad.value = 5.0
    with pytest.raises(ScopeEnforcementError):
        adapter._build_cypher("Vuln", [bad], 100)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# execute() / close()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_execute_returns_adapter_result_with_rows() -> None:
    """End-to-end: ``execute`` runs the parameterized query and wraps records."""
    fake_driver = AsyncMock()
    record = MagicMock()
    # Ensure ``record["n"]`` returns our sentinel node dict — avoid a lambda so
    # pyright can infer the parameter types cleanly.

    def _getitem(_self: Any, key: str) -> Any:
        return {"severity": "high", "id": "v1"} if key == "n" else None

    record.__getitem__ = _getitem
    fake_result = MagicMock()
    fake_result.records = [record]
    fake_driver.execute_query = AsyncMock(return_value=fake_result)

    adapter = await _connected_adapter(driver=fake_driver)
    result = await adapter.execute(
        intent=_intent(),
        scope=[
            ScopeConstraint(source_id="vulns_graph", field="severity", operator="=", value="high"),
        ],
        context={},
    )
    assert isinstance(result, AdapterResult)
    assert result.source_id == "vulns_graph"
    assert result.rows == [{"severity": "high", "id": "v1"}]
    fake_driver.execute_query.assert_awaited_once()


@pytest.mark.unit
async def test_execute_before_connect_raises() -> None:
    adapter = Neo4jAdapter(driver=None)
    from nautilus.adapters.base import AdapterError

    with pytest.raises(AdapterError):
        await adapter.execute(intent=_intent(), scope=[], context={})


@pytest.mark.unit
async def test_close_is_idempotent() -> None:
    """FR-17: second ``close()`` is a no-op."""
    fake_driver = AsyncMock()
    adapter = Neo4jAdapter(driver=fake_driver)
    await adapter.connect(_make_neo4j_source())

    await adapter.close()
    await adapter.close()
    await adapter.close()

    assert fake_driver.close.await_count == 1
