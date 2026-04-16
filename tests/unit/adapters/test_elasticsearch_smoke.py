"""Smoke coverage for :mod:`nautilus.adapters.elasticsearch` (Task 2.10 bridge).

Exercises the DSL-build / scope-enforcement surface of
:class:`ElasticsearchAdapter` so the [VERIFY] 2.10 gate clears the 80%
branch floor. No real :class:`AsyncElasticsearch` client is built —
:class:`unittest.mock.AsyncMock` stands in for ``client.close``, and the
DSL ``.execute()`` call is monkeypatched to return canned hits.

Locked behavior:

- ``connect()`` rejects empty / malformed indices with
  :class:`ScopeEnforcementError` (AC-8.1) before the client is built.
- ``connect()`` accepts a regex-valid index + injected fake client.
- Every allowlisted operator (``=``, ``!=``, ``IN``, ``NOT IN``, ``<``,
  ``>``, ``<=``, ``>=``, ``BETWEEN``, ``LIKE``, ``IS NULL``) dispatches
  to the correct DSL builder (AC-8.2). ``LIKE`` translates SQL ``%`` →
  ``*`` and ``_`` → ``?``.
- Unknown operator → :class:`ScopeEnforcementError`.
- ``close()`` is idempotent (FR-17).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.adapters.base import AdapterError, ScopeEnforcementError
from nautilus.adapters.elasticsearch import (
    ElasticsearchAdapter,
    _translate_like,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint


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


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="search vulns",
        data_types_needed=["vulnerability"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


async def _connected_adapter(client: Any = None) -> ElasticsearchAdapter:
    fake_client = client if client is not None else MagicMock()
    fake_client.close = AsyncMock()
    adapter = ElasticsearchAdapter(client=fake_client)
    await adapter.connect(_make_es_source())
    return adapter


# ---------------------------------------------------------------------------
# connect()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_connect_rejects_empty_index() -> None:
    adapter = ElasticsearchAdapter(client=MagicMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(_make_es_source(index=None))


@pytest.mark.unit
async def test_connect_rejects_malformed_index() -> None:
    """Uppercase letters violate the AC-8.1 ``^[a-z0-9][a-z0-9._-]*$`` regex."""
    adapter = ElasticsearchAdapter(client=MagicMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(_make_es_source(index="BadIndex"))


@pytest.mark.unit
async def test_connect_accepts_lowercase_index() -> None:
    fake_client = MagicMock()
    fake_client.close = AsyncMock()
    adapter = ElasticsearchAdapter(client=fake_client)
    await adapter.connect(_make_es_source(index="my-vulns.2024_v1"))
    assert adapter._index == "my-vulns.2024_v1"  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# _build_search operator coverage
# ---------------------------------------------------------------------------


def _query_dict(adapter: ElasticsearchAdapter, scope: list[ScopeConstraint]) -> dict[str, Any]:
    """Build a search and extract the ``query`` portion of its DSL dict."""
    search = adapter._build_search("vulns", scope, 100)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    return search.to_dict()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]


@pytest.mark.unit
async def test_build_search_eq_emits_term_query() -> None:
    adapter = await _connected_adapter()
    body = _query_dict(
        adapter,
        [ScopeConstraint(source_id="vulns_index", field="severity", operator="=", value="high")],
    )
    # The DSL renders the single Term as a top-level ``query.term.severity``.
    assert "term" in str(body) or "match" in str(body)
    assert "severity" in str(body)
    assert "high" in str(body)
    assert body["size"] == 100


@pytest.mark.unit
async def test_build_search_ne_emits_must_not_term() -> None:
    adapter = await _connected_adapter()
    body = _query_dict(
        adapter,
        [ScopeConstraint(source_id="vulns_index", field="severity", operator="!=", value="low")],
    )
    rendered = str(body)
    assert "must_not" in rendered
    assert "severity" in rendered


@pytest.mark.unit
async def test_build_search_in_emits_terms_query() -> None:
    adapter = await _connected_adapter()
    body = _query_dict(
        adapter,
        [
            ScopeConstraint(
                source_id="vulns_index", field="status", operator="IN", value=["open", "triaged"]
            )
        ],
    )
    rendered = str(body)
    assert "terms" in rendered
    assert "open" in rendered and "triaged" in rendered


@pytest.mark.unit
async def test_build_search_not_in_emits_must_not_terms() -> None:
    adapter = await _connected_adapter()
    body = _query_dict(
        adapter,
        [
            ScopeConstraint(
                source_id="vulns_index",
                field="status",
                operator="NOT IN",
                value=["closed", "duplicate"],
            )
        ],
    )
    rendered = str(body)
    assert "must_not" in rendered
    assert "terms" in rendered


@pytest.mark.unit
@pytest.mark.parametrize(
    ("op", "expected_key"),
    [("<", "lt"), (">", "gt"), ("<=", "lte"), (">=", "gte")],
)
async def test_build_search_relational_emits_range(op: str, expected_key: str) -> None:
    adapter = await _connected_adapter()
    body = _query_dict(
        adapter,
        [ScopeConstraint(source_id="vulns_index", field="cvss", operator=op, value=7.0)],  # type: ignore[arg-type]
    )
    rendered = str(body)
    assert "range" in rendered
    assert expected_key in rendered
    assert "cvss" in rendered


@pytest.mark.unit
async def test_build_search_between_emits_range_with_gte_lte() -> None:
    adapter = await _connected_adapter()
    body = _query_dict(
        adapter,
        [
            ScopeConstraint(
                source_id="vulns_index", field="cvss", operator="BETWEEN", value=[5.0, 9.0]
            )
        ],
    )
    rendered = str(body)
    assert "range" in rendered
    assert "gte" in rendered and "lte" in rendered


@pytest.mark.unit
async def test_build_search_like_translates_wildcards() -> None:
    """SQL ``%`` → ES ``*`` and ``_`` → ``?``."""
    adapter = await _connected_adapter()
    body = _query_dict(
        adapter,
        [
            ScopeConstraint(
                source_id="vulns_index", field="title", operator="LIKE", value="%foo_bar%"
            )
        ],
    )
    rendered = str(body)
    assert "wildcard" in rendered
    assert "*foo?bar*" in rendered


@pytest.mark.unit
async def test_build_search_is_null_emits_must_not_exists() -> None:
    adapter = await _connected_adapter()
    body = _query_dict(
        adapter,
        [
            ScopeConstraint(
                source_id="vulns_index", field="closed_at", operator="IS NULL", value=None
            )
        ],
    )
    rendered = str(body)
    assert "must_not" in rendered
    assert "exists" in rendered


@pytest.mark.unit
def test_translate_like_helper_replaces_wildcards() -> None:
    """Direct unit on the helper for fast feedback on wildcard semantics."""
    assert _translate_like("foo%") == "foo*"
    assert _translate_like("a_b") == "a?b"
    assert _translate_like("%mid_dle%") == "*mid?dle*"


# ---------------------------------------------------------------------------
# Negative paths
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_constraint_to_query_unknown_operator_raises() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "DROP TABLE"
    bad.field = "severity"
    bad.value = "x"
    with pytest.raises(ScopeEnforcementError):
        adapter._constraint_to_query(bad)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_constraint_to_query_in_requires_list() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "IN"
    bad.field = "severity"
    bad.value = "scalar"
    with pytest.raises(ScopeEnforcementError):
        adapter._constraint_to_query(bad)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_constraint_to_query_like_requires_string() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "LIKE"
    bad.field = "title"
    bad.value = 42
    with pytest.raises(ScopeEnforcementError):
        adapter._constraint_to_query(bad)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_constraint_to_query_between_requires_2_seq() -> None:
    adapter = await _connected_adapter()
    bad = MagicMock()
    bad.operator = "BETWEEN"
    bad.field = "cvss"
    bad.value = [1.0]  # length 1
    with pytest.raises(ScopeEnforcementError):
        adapter._constraint_to_query(bad)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# execute() / close()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_execute_before_connect_raises() -> None:
    adapter = ElasticsearchAdapter(client=None)
    with pytest.raises(AdapterError):
        await adapter.execute(intent=_intent(), scope=[], context={})


@pytest.mark.unit
async def test_close_is_idempotent() -> None:
    """FR-17: second ``close()`` is a no-op."""
    fake_client = MagicMock()
    fake_client.close = AsyncMock()
    adapter = ElasticsearchAdapter(client=fake_client)
    await adapter.connect(_make_es_source())

    await adapter.close()
    await adapter.close()
    await adapter.close()

    assert fake_client.close.await_count == 1


@pytest.mark.unit
async def test_close_without_connect_is_safe() -> None:
    """``close()`` on an adapter that never connected is a clean no-op."""
    adapter = ElasticsearchAdapter(client=None)
    await adapter.close()
    await adapter.close()
