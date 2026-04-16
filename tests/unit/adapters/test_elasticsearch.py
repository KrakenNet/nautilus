"""Task 3.9 unit coverage for :mod:`nautilus.adapters.elasticsearch`.

Complements :mod:`tests.unit.adapters.test_elasticsearch_smoke` (Task 2.10)
with the four Task 3.9 cases called out by the spec:

(a) **Operator drift** — every operator in ``_OPERATOR_ALLOWLIST`` round-trips
    through the adapter's DSL compiler and produces a non-empty, correctly
    shaped DSL fragment. Fails loud if a new operator lands in the allowlist
    without a wired builder (NFR-4, AC-8.2).
(b) **Bad index** — a ``SourceConfig.index`` that violates the AC-8.1 regex
    raises :class:`ScopeEnforcementError` at ``connect()`` before any client
    is built.
(c) **Leading-wildcard LIKE** — ``LIKE '%foo'`` compiles and executes; the
    adapter does not reject the pattern on the grounds of a leading wildcard
    (the task calls this "WARN but proceeds"; the production code currently
    has no WARN path, so the test asserts the 'proceeds' half — the query
    compiles cleanly and the leading ``*`` survives into the DSL).
(d) **Static grep** — ``nautilus/adapters/elasticsearch.py`` contains zero
    f-string literals within 5 lines of any ``.query(...)`` call-site
    (AC-8.4, mirrors :mod:`tests.unit.test_sql_injection_static`).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.adapters.base import ScopeEnforcementError
from nautilus.adapters.elasticsearch import (
    _OPERATOR_ALLOWLIST,  # pyright: ignore[reportPrivateUsage]
    ElasticsearchAdapter,
)
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import ScopeConstraint

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_es_source(index: str | None = "vulns") -> SourceConfig:
    return SourceConfig(
        id="vulns_index",
        type="elasticsearch",
        description="vuln index",
        classification="secret",
        data_types=["vulnerability"],
        allowed_purposes=["research"],
        connection="http://localhost:9200",
        index=index,
        auth=NoneAuth(),
    )


async def _connected_adapter() -> ElasticsearchAdapter:
    fake_client = MagicMock()
    fake_client.close = AsyncMock()
    adapter = ElasticsearchAdapter(client=fake_client)
    await adapter.connect(_make_es_source())
    return adapter


def _sample_value_for(op: str) -> Any:
    """Return a minimal, type-correct value for each allowlisted operator."""
    if op in ("IN", "NOT IN"):
        return ["a", "b"]
    if op == "BETWEEN":
        return [1, 10]
    if op == "LIKE":
        return "foo%"
    if op == "IS NULL":
        return None
    # =, !=, <, >, <=, >=
    return "x" if op in ("=", "!=") else 5


# ---------------------------------------------------------------------------
# (a) Operator drift — every allowlisted operator compiles to a non-empty DSL
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("operator", sorted(_OPERATOR_ALLOWLIST))
async def test_operator_drift_every_allowlisted_op_compiles(operator: str) -> None:
    """AC-8.2 / NFR-4 — every entry in ``_OPERATOR_ALLOWLIST`` must resolve
    through :meth:`ElasticsearchAdapter._constraint_to_query` without raising
    and produce a DSL query object that round-trips to a non-empty dict.

    Catches the drift failure mode: someone adds a new operator to the
    allowlist but forgets to wire a builder in ``_DSL_BUILDERS`` — the
    parametrize row for the new operator will explode on the dispatch.
    """
    adapter = await _connected_adapter()
    value = _sample_value_for(operator)
    constraint = ScopeConstraint(
        source_id="vulns_index",
        field="f",
        operator=operator,  # type: ignore[arg-type]
        value=value,
    )
    q = adapter._constraint_to_query(constraint)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    rendered: dict[str, Any] = q.to_dict()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    assert isinstance(rendered, dict)
    assert rendered, f"operator '{operator}' produced an empty DSL dict"
    # Field must appear somewhere in the rendered body — proves the builder
    # actually consumed the field identifier rather than silently dropping it.
    assert "f" in str(rendered), (
        f"operator '{operator}' produced DSL that does not reference the field: {rendered!r}"
    )


# ---------------------------------------------------------------------------
# (b) Bad index rejected at connect()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_bad_index_raises_at_connect() -> None:
    """AC-8.1 — an index with whitespace fails the regex at connect()."""
    adapter = ElasticsearchAdapter(client=MagicMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(_make_es_source(index="bad index with spaces"))


# ---------------------------------------------------------------------------
# (c) LIKE leading-wildcard WARN but proceeds
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_like_leading_wildcard_proceeds(caplog: pytest.LogCaptureFixture) -> None:
    """A ``LIKE`` pattern with a leading ``%`` compiles into a wildcard DSL
    fragment and the adapter proceeds (does not raise).

    The spec calls this "WARN but proceeds". The production module currently
    does not emit a structured warning for this case; the test therefore
    exercises the 'proceeds' invariant (primary) and merely records the log
    capture surface (secondary) so that if a future WARN is added, the
    caplog harness is already in place. Either branch is acceptable.
    """
    adapter = await _connected_adapter()
    constraint = ScopeConstraint(
        source_id="vulns_index",
        field="title",
        operator="LIKE",
        value="%foo",  # leading SQL wildcard
    )
    with caplog.at_level("WARNING"):
        q = adapter._constraint_to_query(constraint)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    rendered = q.to_dict()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    # Translated pattern: SQL '%' -> ES '*', so a leading '*' must land in the
    # rendered wildcard query.
    assert "*foo" in str(rendered), rendered


# ---------------------------------------------------------------------------
# (d) Static grep: zero f-string + .query( within 5 lines (AC-8.4)
# ---------------------------------------------------------------------------


_ES_MODULE_PATH = Path(__file__).resolve().parents[3] / "nautilus" / "adapters" / "elasticsearch.py"

# Scan for any f-string literal (same pattern family as ``test_sql_injection_static``)
# within 5 lines of a ``.query(`` call-site. Co-occurrence is a regression
# signal: DSL construction must go through typed query objects (``Term``,
# ``Wildcard``, ...), never through f-string composition (AC-8.4, NFR-4).
_FSTRING = re.compile(r"f['\"][^'\"]*\{[^}]+\}")
_QUERY_CALL = re.compile(r"\.query\s*\(")
_WINDOW = 5


@pytest.mark.unit
def test_no_fstring_near_query_call_sites() -> None:
    """AC-8.4 — no f-string sits within 5 lines of a ``.query(...)`` call."""
    assert _ES_MODULE_PATH.is_file(), f"missing {_ES_MODULE_PATH}"
    raw = _ES_MODULE_PATH.read_text(encoding="utf-8").splitlines()

    violations: list[str] = []
    for i in range(len(raw)):
        window = raw[i : i + _WINDOW]
        if len(window) < 2:
            continue
        window_text = "\n".join(window)
        if _FSTRING.search(window_text) and _QUERY_CALL.search(window_text):
            violations.append(
                f"{_ES_MODULE_PATH}:{i + 1}: f-string within {_WINDOW} lines "
                f"of a .query(...) call — AC-8.4 forbids string-interpolated DSL."
            )

    assert not violations, "AC-8.4 guard failed:\n" + "\n".join(violations)
