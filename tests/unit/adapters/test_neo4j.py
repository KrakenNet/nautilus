"""Task 3.10 unit coverage for :mod:`nautilus.adapters.neo4j`.

Complements :mod:`tests.unit.adapters.test_neo4j_smoke` (Task 2.10) with the
five Task 3.10 cases called out by the spec:

(a) **Operator → Cypher round-trip drift** — every operator in the Neo4j
    adapter's local ``_OPERATOR_ALLOWLIST`` produces a recognisable Cypher
    fragment with identifiers backticked and values bound via ``$pN``
    parameters (NFR-4). Fails loud if a new operator is added to the
    allowlist without a corresponding dispatch arm in ``_build_cypher``.
(b) **Bad label rejected at connect** — a label failing the AC-10.1 regex
    (``^[A-Z][A-Za-z0-9_]*$``) triggers :class:`ScopeEnforcementError` at
    ``connect()`` *before* any driver is built.
(c) **LIKE style switch + CONFIG WARN** — ``like_style='starts_with'`` emits
    ``STARTS WITH $p0``; ``like_style='regex'`` emits ``=~ $p0`` AND logs a
    CONFIG WARN line at ``WARNING`` level (AC-10.3).
(d) **Property identifier regex + backticking** — a valid property name is
    backticked in the generated Cypher; a bad identifier containing a dot
    (``"bad.name"``) is rejected by :func:`_validate_property`.
(e) **``close()`` idempotent** — calling ``close()`` multiple times awaits
    the underlying driver's ``close`` exactly once (FR-17).
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from nautilus.adapters.base import ScopeEnforcementError
from nautilus.adapters.neo4j import (
    _OPERATOR_ALLOWLIST,  # pyright: ignore[reportPrivateUsage]
    Neo4jAdapter,
)
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import ScopeConstraint

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


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


# Per-operator drift fixture: maps each allowlisted operator to a
# ``(value, expected_substring)`` probe tuned to exercise the dispatch arm.
# Centralising the mapping here means any new operator added to
# ``_OPERATOR_ALLOWLIST`` without a matching entry here (or a matching
# dispatch branch in ``_build_cypher``) fails the drift test loudly.
_DRIFT_PROBES: dict[str, tuple[object, str]] = {
    "=": ("high", "n.`severity` = $p0"),
    "!=": ("low", "n.`severity` <> $p0"),
    "<": (1.0, "n.`severity` < $p0"),
    ">": (1.0, "n.`severity` > $p0"),
    "<=": (1.0, "n.`severity` <= $p0"),
    ">=": (1.0, "n.`severity` >= $p0"),
    "IN": (["open", "triaged"], "n.`severity` IN $p0"),
    "NOT IN": (["closed"], "NOT n.`severity` IN $p0"),
    "LIKE": ("CVE-", "n.`severity` STARTS WITH $p0"),
    "BETWEEN": ([1.0, 9.0], "$p0_lo <= n.`severity` <= $p0_hi"),
    "IS NULL": (None, "n.`severity` IS NULL"),
}


# ---------------------------------------------------------------------------
# (a) Operator → Cypher drift (NFR-4)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("operator", sorted(_OPERATOR_ALLOWLIST))
async def test_operator_cypher_drift_every_op_renders(operator: str) -> None:
    """Every operator on the Neo4j allowlist dispatches to a Cypher fragment.

    Catches drift where an operator is added to ``_OPERATOR_ALLOWLIST`` but
    never wired into the ``_build_cypher`` dispatch — which would silently
    fall through to the ``IS NULL`` branch or the unreachable-else.
    """
    assert operator in _DRIFT_PROBES, (
        f"operator '{operator}' in _OPERATOR_ALLOWLIST but missing a "
        f"_DRIFT_PROBES entry — add one when extending the allowlist (NFR-4)"
    )
    value, expected = _DRIFT_PROBES[operator]
    adapter = Neo4jAdapter(driver=AsyncMock())
    await adapter.connect(_make_neo4j_source())
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [
            ScopeConstraint(
                source_id="vulns_graph",
                field="severity",
                operator=operator,  # type: ignore[arg-type]
                value=value,
            )
        ],
        100,
    )
    assert expected in cypher, (
        f"operator '{operator}' did not produce expected Cypher fragment "
        f"'{expected}' (got: {cypher!r})"
    )
    # Limit parameter is always present regardless of operator arm.
    assert params["L"] == 100


# ---------------------------------------------------------------------------
# (b) Bad label rejected at connect (AC-10.1)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_bad_label_rejected_at_connect() -> None:
    """An AC-10.1 violating label raises before the driver is built."""
    # A label with a space + semicolon cannot match ``^[A-Z][A-Za-z0-9_]*$``.
    adapter = Neo4jAdapter(driver=AsyncMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(_make_neo4j_source(label="Bad Label; DROP"))


# ---------------------------------------------------------------------------
# (c) LIKE style switch + CONFIG WARN (AC-10.3)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_like_starts_with_style_emits_starts_with_clause(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``like_style='starts_with'`` (the default) uses ``STARTS WITH`` and
    emits NO CONFIG WARN line."""
    adapter = Neo4jAdapter(driver=AsyncMock())
    with caplog.at_level("WARNING"):
        await adapter.connect(_make_neo4j_source(like_style="starts_with"))
    cypher, params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [ScopeConstraint(source_id="vulns_graph", field="title", operator="LIKE", value="CVE-")],
        100,
    )
    assert "STARTS WITH $p0" in cypher
    assert params["p0"] == "CVE-"
    # No CONFIG WARN when the safer starts_with style is active.
    assert not any("like_style='regex'" in record.message for record in caplog.records)


@pytest.mark.unit
async def test_like_regex_style_emits_regex_match_and_config_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``like_style='regex'`` uses ``=~`` and emits a CONFIG WARN (AC-10.3)."""
    adapter = Neo4jAdapter(driver=AsyncMock())
    with caplog.at_level("WARNING"):
        await adapter.connect(_make_neo4j_source(like_style="regex"))
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
    assert "=~ $p0" in cypher
    assert params["p0"] == "^CVE-2024.*"
    # CONFIG WARN line present at WARNING level.
    assert any(
        "CONFIG WARN" in record.message and "regex" in record.message.lower()
        for record in caplog.records
        if record.levelname == "WARNING"
    )


# ---------------------------------------------------------------------------
# (d) Property identifier regex + backticking
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_property_identifier_backticked_in_cypher() -> None:
    """Valid property names are backticked inside the generated Cypher."""
    adapter = Neo4jAdapter(driver=AsyncMock())
    await adapter.connect(_make_neo4j_source())
    cypher, _params = adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        "Vuln",
        [ScopeConstraint(source_id="vulns_graph", field="valid_prop", operator="=", value="x")],
        100,
    )
    # Identifier appears wrapped in backticks, never bare.
    assert "n.`valid_prop`" in cypher
    assert "n.valid_prop " not in cypher  # no un-backticked occurrence


@pytest.mark.unit
async def test_property_identifier_rejects_dotted_name() -> None:
    """A property name with a dot fails the ``_PROP_PATTERN`` regex."""
    adapter = Neo4jAdapter(driver=AsyncMock())
    await adapter.connect(_make_neo4j_source())
    with pytest.raises(ScopeEnforcementError):
        adapter._build_cypher(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            "Vuln",
            [
                ScopeConstraint(
                    source_id="vulns_graph",
                    field="bad.name",
                    operator="=",
                    value="x",
                )
            ],
            100,
        )


# ---------------------------------------------------------------------------
# (e) close() idempotent (FR-17)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_close_idempotent_awaits_driver_close_once() -> None:
    """Multiple ``close()`` calls must fan down to a single driver close."""
    fake_driver = AsyncMock()
    adapter = Neo4jAdapter(driver=fake_driver)
    await adapter.connect(_make_neo4j_source())

    await adapter.close()
    await adapter.close()
    await adapter.close()

    assert fake_driver.close.await_count == 1
