"""Smoke coverage for :mod:`nautilus.adapters.servicenow` (Task 2.14 bridge).

Exercises the encoded-query sanitiser, table allowlist, and GlideRecord
``sysparm_query`` composer so the [VERIFY] 2.14 gate clears the 80%
branch floor. No real ServiceNow instance is contacted —
:class:`httpx.MockTransport` stands in for the Table-API upstream.

Locked behavior:

- ``_sanitize_sn_value`` rejects the GlideRecord separator bytes
  (``^`` / ``\\n`` / ``\\r``) and passes plain strings through (AC-11.1).
- ``connect()`` rejects missing / malformed table names before building
  the client (AC-11.1).
- ``connect()`` accepts a regex-valid lowercase table + injected client.
- :meth:`ServiceNowAdapter._build_sysparm_query` composes the expected
  ``^``-separated segment per operator (AC-11.2); unknown operators and
  bad field names both raise :class:`ScopeEnforcementError`.
- ``IS NULL`` renders as ``<field>ISEMPTY``.
- Every scalar / element in ``IN`` / ``BETWEEN`` routes through
  :meth:`_sanitize_sn_value` so an injected ``^`` in any scope value is
  refused at compose time.
- ``close()`` is idempotent (FR-17).
- Auth plumbing: ``BearerAuth`` / ``BasicAuth`` / ``NoneAuth`` produce the
  expected ``httpx.Auth`` (or ``None``).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from nautilus.adapters.base import AdapterError, ScopeEnforcementError
from nautilus.adapters.servicenow import (
    ServiceNowAdapter,
    _auth_for_config,  # pyright: ignore[reportPrivateUsage]
    _BearerAuth,  # pyright: ignore[reportPrivateUsage]
    _coerce_rows,  # pyright: ignore[reportPrivateUsage]
    _validate_sn_field,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.config.models import (
    BasicAuth,
    BearerAuth,
    NoneAuth,
    SourceConfig,
)
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint


def _make_sn_source(
    table: str | None = "incident",
    auth: Any = None,
    connection: str = "https://dev.service-now.com",
) -> SourceConfig:
    return SourceConfig(
        id="sn_src",
        type="servicenow",
        description="SN incidents",
        classification="secret",
        data_types=["incident"],
        allowed_purposes=["research"],
        connection=connection,
        table=table,
        auth=auth if auth is not None else NoneAuth(),
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="look up incidents",
        data_types_needed=["incident"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


async def _connected_adapter(
    *,
    transport: httpx.MockTransport | None = None,
    table: str = "incident",
) -> ServiceNowAdapter:
    if transport is None:

        def _ok(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"result": []})

        transport = httpx.MockTransport(_ok)
    client = httpx.AsyncClient(base_url="https://dev.service-now.com", transport=transport)
    adapter = ServiceNowAdapter(client=client)
    await adapter.connect(_make_sn_source(table=table))
    return adapter


# ---------------------------------------------------------------------------
# _sanitize_sn_value
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_sanitize_rejects_caret() -> None:
    """``^`` is the GlideRecord separator and must never leak through."""
    with pytest.raises(ScopeEnforcementError):
        ServiceNowAdapter._sanitize_sn_value("abc^def")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_sanitize_rejects_newline() -> None:
    with pytest.raises(ScopeEnforcementError):
        ServiceNowAdapter._sanitize_sn_value("abc\ndef")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_sanitize_rejects_carriage_return() -> None:
    with pytest.raises(ScopeEnforcementError):
        ServiceNowAdapter._sanitize_sn_value("abc\rdef")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_sanitize_accepts_plain_string() -> None:
    """Plain strings pass unchanged."""
    got = ServiceNowAdapter._sanitize_sn_value("high")  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert got == "high"


# ---------------------------------------------------------------------------
# _validate_sn_field
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_validate_sn_field_accepts_dotted_walk() -> None:
    """AC-11.1 — dotted walks like ``assigned_to.name`` are allowed."""
    # Should not raise.
    _validate_sn_field("assigned_to.name")
    _validate_sn_field("short_description")


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_field",
    ["BAD", "1bad", "has space", "has^char", "has,comma", "has@at", ""],
)
def test_validate_sn_field_rejects_bad_names(bad_field: str) -> None:
    with pytest.raises(ScopeEnforcementError):
        _validate_sn_field(bad_field)


# ---------------------------------------------------------------------------
# connect() — table allowlist
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("bad", [None, "", "1bad", "BAD", "has space", "has^char"])
async def test_connect_rejects_bad_table(bad: str | None) -> None:
    adapter = ServiceNowAdapter(client=MagicMock())
    with pytest.raises(ScopeEnforcementError):
        await adapter.connect(_make_sn_source(table=bad))


@pytest.mark.unit
async def test_connect_accepts_valid_table_with_injected_client() -> None:
    adapter = await _connected_adapter(table="incident")
    assert adapter._table == "incident"  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    await adapter.close()


# ---------------------------------------------------------------------------
# _build_sysparm_query — operator dispatch
# ---------------------------------------------------------------------------


def _render(scope: list[ScopeConstraint]) -> str:
    return ServiceNowAdapter._build_sysparm_query(scope)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_build_sysparm_eq() -> None:
    q = _render(
        [ScopeConstraint(source_id="sn_src", field="state", operator="=", value="2")],
    )
    assert q == "state=2"


@pytest.mark.unit
def test_build_sysparm_ne() -> None:
    q = _render(
        [ScopeConstraint(source_id="sn_src", field="state", operator="!=", value="7")],
    )
    assert q == "state!=7"


@pytest.mark.unit
def test_build_sysparm_in() -> None:
    q = _render(
        [
            ScopeConstraint(
                source_id="sn_src",
                field="priority",
                operator="IN",
                value=["1", "2"],
            )
        ],
    )
    assert q == "priorityIN1,2"


@pytest.mark.unit
def test_build_sysparm_not_in() -> None:
    q = _render(
        [
            ScopeConstraint(
                source_id="sn_src",
                field="state",
                operator="NOT IN",
                value=["6", "7"],
            )
        ],
    )
    assert q == "stateNOT IN6,7"


@pytest.mark.unit
@pytest.mark.parametrize("op", ["<", ">", "<=", ">="])
def test_build_sysparm_relational(op: str) -> None:
    q = _render(
        [ScopeConstraint(source_id="sn_src", field="priority", operator=op, value=3)],  # type: ignore[arg-type]
    )
    assert q == f"priority{op}3"


@pytest.mark.unit
def test_build_sysparm_between_uses_at_separator() -> None:
    q = _render(
        [
            ScopeConstraint(
                source_id="sn_src",
                field="priority",
                operator="BETWEEN",
                value=[1, 5],
            )
        ],
    )
    assert q == "priorityBETWEEN1@5"


@pytest.mark.unit
def test_build_sysparm_like() -> None:
    q = _render(
        [
            ScopeConstraint(
                source_id="sn_src", field="short_description", operator="LIKE", value="network"
            )
        ],
    )
    assert q == "short_descriptionLIKEnetwork"


@pytest.mark.unit
def test_build_sysparm_is_null_renders_isempty() -> None:
    """AC-11.2 — ``IS NULL`` maps to ServiceNow's ``ISEMPTY`` segment."""
    q = _render(
        [
            ScopeConstraint(
                source_id="sn_src",
                field="resolved_at",
                operator="IS NULL",
                value=None,
            )
        ],
    )
    assert q == "resolved_atISEMPTY"


@pytest.mark.unit
def test_build_sysparm_joins_segments_with_caret() -> None:
    q = _render(
        [
            ScopeConstraint(source_id="sn_src", field="state", operator="=", value="2"),
            ScopeConstraint(source_id="sn_src", field="priority", operator="<", value=3),  # type: ignore[arg-type]
        ],
    )
    assert q == "state=2^priority<3"


# ---------------------------------------------------------------------------
# _build_sysparm_query — negative paths
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_render_segment_rejects_caret_in_scalar_value() -> None:
    """A ``^`` in the scope value is rejected by the sanitiser."""
    with pytest.raises(ScopeEnforcementError):
        _render(
            [
                ScopeConstraint(
                    source_id="sn_src",
                    field="short_description",
                    operator="=",
                    value="boom^state=1",
                )
            ],
        )


@pytest.mark.unit
def test_render_segment_rejects_caret_in_in_list() -> None:
    """Every element of an ``IN`` list passes through the sanitiser."""
    with pytest.raises(ScopeEnforcementError):
        _render(
            [
                ScopeConstraint(
                    source_id="sn_src",
                    field="priority",
                    operator="IN",
                    value=["1", "2^evil"],
                )
            ],
        )


@pytest.mark.unit
def test_render_segment_rejects_caret_in_between_endpoint() -> None:
    with pytest.raises(ScopeEnforcementError):
        _render(
            [
                ScopeConstraint(
                    source_id="sn_src",
                    field="priority",
                    operator="BETWEEN",
                    value=["1", "5^hack"],
                )
            ],
        )


@pytest.mark.unit
def test_render_segment_in_requires_list() -> None:
    bad = MagicMock()
    bad.operator = "IN"
    bad.field = "priority"
    bad.value = "1"  # scalar
    with pytest.raises(ScopeEnforcementError):
        ServiceNowAdapter._render_segment(bad)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_render_segment_between_requires_list_or_tuple() -> None:
    bad = MagicMock()
    bad.operator = "BETWEEN"
    bad.field = "priority"
    bad.value = "1@5"  # not a list/tuple
    with pytest.raises(ScopeEnforcementError):
        ServiceNowAdapter._render_segment(bad)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_render_segment_between_requires_two_endpoints() -> None:
    bad = MagicMock()
    bad.operator = "BETWEEN"
    bad.field = "priority"
    bad.value = [1]  # single element
    with pytest.raises(ScopeEnforcementError):
        ServiceNowAdapter._render_segment(bad)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_render_segment_unknown_operator_raises() -> None:
    bad = MagicMock()
    bad.operator = "DROP TABLE"
    bad.field = "state"
    bad.value = "x"
    with pytest.raises(ScopeEnforcementError):
        ServiceNowAdapter._render_segment(bad)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
def test_render_segment_bad_field_name_raises() -> None:
    with pytest.raises(ScopeEnforcementError):
        _render(
            [
                ScopeConstraint(
                    source_id="sn_src",
                    field="Bad Field",
                    operator="=",
                    value="x",
                )
            ],
        )


# ---------------------------------------------------------------------------
# execute() — happy path + pre-connect error
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_execute_happy_path_returns_rows() -> None:
    """A 200 ``{"result": [...]}`` body yields an :class:`AdapterResult`."""
    captured: dict[str, Any] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        return httpx.Response(
            200,
            json={"result": [{"number": "INC0001"}, {"number": "INC0002"}]},
        )

    transport = httpx.MockTransport(_handler)
    adapter = await _connected_adapter(transport=transport)
    try:
        result = await adapter.execute(
            intent=_intent(),
            scope=[ScopeConstraint(source_id="sn_src", field="state", operator="=", value="2")],
            context={},
        )
        assert isinstance(result, AdapterResult)
        assert result.source_id == "sn_src"
        assert [r["number"] for r in result.rows] == ["INC0001", "INC0002"]
        # URL uses the configured table and carries the sysparm_query param.
        assert "/api/now/table/incident" in captured["url"]
        assert "sysparm_query=state%3D2" in captured["url"]
        assert captured["method"] == "GET"
    finally:
        await adapter.close()


@pytest.mark.unit
async def test_execute_before_connect_raises() -> None:
    adapter = ServiceNowAdapter(client=None)
    with pytest.raises(AdapterError):
        await adapter.execute(intent=_intent(), scope=[], context={})


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_close_is_idempotent() -> None:
    """FR-17: second ``close()`` is a no-op."""
    fake_client = MagicMock()
    fake_client.aclose = AsyncMock()
    adapter = ServiceNowAdapter(client=fake_client)
    await adapter.connect(_make_sn_source())

    await adapter.close()
    await adapter.close()
    await adapter.close()

    assert fake_client.aclose.await_count == 1


@pytest.mark.unit
async def test_close_without_connect_is_safe() -> None:
    adapter = ServiceNowAdapter(client=None)
    await adapter.close()
    await adapter.close()


# ---------------------------------------------------------------------------
# Auth plumbing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_auth_for_config_bearer_returns_bearer_wrapper() -> None:
    config = _make_sn_source(auth=BearerAuth(token="t-sn"))
    auth = _auth_for_config(config)
    assert isinstance(auth, _BearerAuth)


@pytest.mark.unit
def test_auth_for_config_basic_returns_httpx_basic() -> None:
    config = _make_sn_source(auth=BasicAuth(username="u", password="p"))
    auth = _auth_for_config(config)
    assert isinstance(auth, httpx.BasicAuth)


@pytest.mark.unit
def test_auth_for_config_none_returns_none() -> None:
    config = _make_sn_source(auth=NoneAuth())
    assert _auth_for_config(config) is None


# ---------------------------------------------------------------------------
# _coerce_rows body-shape variants
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_coerce_rows_accepts_table_api_envelope() -> None:
    body = {"result": [{"number": "INC1"}, {"number": "INC2"}]}
    assert _coerce_rows(body, limit=10) == [{"number": "INC1"}, {"number": "INC2"}]


@pytest.mark.unit
def test_coerce_rows_wraps_bare_dict() -> None:
    body = {"single": True}
    assert _coerce_rows(body, limit=10) == [body]


@pytest.mark.unit
def test_coerce_rows_accepts_bare_list() -> None:
    assert _coerce_rows([{"a": 1}], limit=10) == [{"a": 1}]


@pytest.mark.unit
def test_coerce_rows_rejects_non_dict_items_in_list() -> None:
    assert _coerce_rows([{"ok": 1}, "bad", 42], limit=10) == [{"ok": 1}]


@pytest.mark.unit
def test_coerce_rows_on_scalar_returns_empty() -> None:
    assert _coerce_rows("not a shape", limit=10) == []


@pytest.mark.unit
def test_coerce_rows_honours_limit() -> None:
    body = {"result": [{"i": i} for i in range(5)]}
    assert _coerce_rows(body, limit=2) == [{"i": 0}, {"i": 1}]
